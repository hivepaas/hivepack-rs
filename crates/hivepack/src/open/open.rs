//! Opening a file through its layers: each is found by its first bytes and
//! taken off, until what is under them is a container or plain data.

use std::io::{self, Cursor, Read};

use crate::age::{BoxedIdentity, FileKey, FileKeyIdentity, Identity};

use crate::open::decode::{DecodeLimits, decoder};
use crate::open::detect::{
    Container, Detected, HEAD_LEN, Layer, UDF_HEAD_LEN, detect, is_lzma_alone,
};
use crate::open::error::Error;
use crate::threads::Threads;

/// How far an [`Opener`] goes.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Limits {
    /// The layers taken off at most: `backup.tar.zst.age` has two. 8 by
    /// default.
    pub max_layers: usize,
    /// The largest zstd window, as a power of two: 27 (128 MiB) by
    /// default, libzstd's own limit, beyond which `zstd -d` needs
    /// `--long` or `--memory`.
    pub zstd_window_log_max: u32,
    /// What xz, lzip and .lzma's decoders may use: 1 GiB by default. `xz
    /// -9` needs 65 MiB. With [`Opener::threads`], xz's threads are lowered
    /// to fit it, as liblzma lowers them, one always allowed, and pbzx's
    /// chunks in flight hold no more than it.
    pub xz_memlimit: u64,
    /// What bzip2's decoder may use in threads ([`Opener::threads`]): they
    /// are lowered until they fit, about 20.5 MiB each, and one, the
    /// caller's, about 4 MiB, is always allowed. No limit (`u64::MAX`) by
    /// default. See `docs/memory.md`.
    pub bzip2_memlimit: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_layers: 8,
            zstd_window_log_max: 27,
            xz_memlimit: 1 << 30,
            bzip2_memlimit: u64::MAX,
        }
    }
}

/// What a file is under its layers, and its data.
pub struct Opened<'a> {
    layers: Vec<Layer>,
    container: Container,
    reader: Box<dyn Read + Send + 'a>,
}

impl Opened<'_> {
    /// The layers taken off, the outermost first: `[Age, Zstd]` for
    /// `backup.tar.zst.age`.
    pub fn layers(&self) -> &[Layer] {
        &self.layers
    }

    /// What is under them.
    pub fn container(&self) -> Container {
        self.container
    }
}

impl std::fmt::Debug for Opened<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened")
            .field("layers", &self.layers)
            .field("container", &self.container)
            .finish_non_exhaustive()
    }
}

/// The data under the layers. An error of a layer's data comes when it is
/// reached, of kind `InvalidData`: a [`DecodeError`](crate::open::DecodeError)
/// inside, or an age payload's [`crate::age::Error`].
impl Read for Opened<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

/// Opens a file through its layers, as often as it is asked to: once to
/// tell what it is, and again for each pass of what reads it
/// (`hivepack::extract::extract_tar` reads twice).
///
/// The first time an age layer is decrypted, its file key is kept: each
/// later open decrypts it with that key, so a passphrase is asked for, and
/// scrypt run, only once. A file that changed between opens fails with
/// [`Error::Changed`].
pub struct Opener<F> {
    open: F,
    name: Option<String>,
    identities: Vec<BoxedIdentity>,
    limits: Limits,
    threads: Threads,
    /// What the threads may hold in all, besides each decoder's limit.
    threads_memory: u64,
    /// The file key of each age layer decrypted, the outermost first.
    file_keys: Vec<FileKey>,
    /// What the first open found, which the next must find again.
    found: Option<(Vec<Layer>, Container)>,
}

impl<F> std::fmt::Debug for Opener<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opener")
            .field("name", &self.name)
            .field("identities", &self.identities.len())
            .field("limits", &self.limits)
            .field("threads", &self.threads)
            .field("found", &self.found)
            .finish_non_exhaustive()
    }
}

impl<F, R> Opener<F>
where
    F: FnMut() -> io::Result<R>,
    R: Read + Send,
{
    /// An opener of what `open` reads, from its start each time it is
    /// called: a file, opened again.
    pub fn new(open: F) -> Opener<F> {
        Opener {
            open,
            name: None,
            identities: Vec::new(),
            limits: Limits::default(),
            threads: Threads::One,
            threads_memory: u64::MAX,
            file_keys: Vec::new(),
            found: None,
        }
    }

    /// The file's name, which tells `.lzma`, the one layer without magic
    /// bytes: `notes.txt.lzma`, `backup.tlz` (`.tar.lzma`), or
    /// `backup.tar.lzma.age` under its age layer.
    pub fn name(mut self, name: &str) -> Opener<F> {
        self.name = Some(name.to_owned());
        self
    }

    /// What decrypts age layers, tried in age's order: X25519 and scrypt
    /// identities first. [`LazyScryptIdentity`](crate::age::LazyScryptIdentity)
    /// asks for a passphrase only when a layer needs one.
    pub fn identities(mut self, identities: Vec<BoxedIdentity>) -> Opener<F> {
        self.identities = identities;
        self
    }

    /// Other limits than the default ones.
    pub fn limits(mut self, limits: Limits) -> Opener<F> {
        self.limits = limits;
        self
    }

    /// How many threads its decoders may use: one, the caller's, by
    /// default. An xz Stream whose Blocks have their sizes in their headers,
    /// as `xz -T`, 7-Zip and [`Stream::stream_encoder_mt`] write them, is
    /// decoded a Block in each, as far as [`Limits::xz_memlimit`] allows;
    /// bzip2 streams one after the other, as pbzip2 and [`CompressMt`] write
    /// them, a stream in each, and a stream of more than 2 MiB, as `bzip2`
    /// writes a file, a block in each, as far as [`Limits::bzip2_memlimit`]
    /// allows; pbzx's chunks, each an xz stream, a chunk in each, as far as
    /// [`Limits::xz_memlimit`] allows; the other layers, and the Blocks
    /// without their sizes, on the caller's thread. What is read is the same
    /// either way, errors too.
    ///
    /// [`Stream::stream_encoder_mt`]: crate::xz::Stream::stream_encoder_mt
    /// [`CompressMt`]: crate::bzip2::CompressMt
    pub fn threads(mut self, threads: Threads) -> Opener<F> {
        self.threads = threads;
        self
    }

    /// What the decoders' threads may hold in all, under the limits of
    /// each: xz's and bzip2's threads are lowered to fit it, and pbzx's
    /// chunks in flight held to it, one thread always allowed.
    #[cfg_attr(not(feature = "extract"), allow(dead_code))]
    pub(crate) fn threads_memory(mut self, bytes: u64) -> Opener<F> {
        self.threads_memory = bytes;
        self
    }

    /// The file opened again, through its layers.
    pub fn open<'a>(&mut self) -> Result<Opened<'a>, Error>
    where
        R: 'a,
    {
        let decode_limits = DecodeLimits {
            zstd_window_log_max: self.limits.zstd_window_log_max,
            xz_memlimit: self.limits.xz_memlimit,
            bzip2_memlimit: self.limits.bzip2_memlimit,
            threads: self.threads.count(),
            threads_memory: self.threads_memory,
        };
        let mut reader: Box<dyn Read + Send + 'a> = Box::new((self.open)()?);
        let full_name = self.name.clone();
        let mut name = full_name.as_deref();
        let mut layers = Vec::new();
        let mut ages = 0;
        let container = loop {
            let mut head = Vec::with_capacity(HEAD_LEN);
            (&mut reader).take(HEAD_LEN as u64).read_to_end(&mut head)?;
            let mut detected = detect(&head, name);
            // An RPM package's payload has no name to tell `.lzma` by.
            if detected == Detected::Container(Container::Data)
                && layers.last() == Some(&Layer::Rpm)
                && is_lzma_alone(&head)
            {
                detected = Detected::Layer(Layer::Lzma);
            }
            let mut deferred = None;
            if detected == Detected::Container(Container::Data) && head.len() == HEAD_LEN {
                // An ISO 9660 image or a UDF volume tells further in. An
                // error there comes when the data is read up to it, as it
                // would have.
                deferred = read_more(&mut reader, &mut head, UDF_HEAD_LEN);
                detected = detect(&head, name);
            }
            reader = match deferred {
                None => Box::new(Cursor::new(head).chain(reader)),
                Some(error) => Box::new(Cursor::new(head).chain(Deferred {
                    error: Some(error),
                    inner: reader,
                })),
            };
            let layer = match detected {
                Detected::Container(container) => break container,
                Detected::Layer(layer) => layer,
            };
            if layers.len() == self.limits.max_layers {
                return Err(Error::TooManyLayers(self.limits.max_layers));
            }
            layers.push(layer);
            // `backup.tar.lzma.age` is `backup.tar.lzma` under its age layer.
            name = name.and_then(|n| n.rsplit_once('.')).map(|(stem, _)| stem);
            reader = match layer {
                Layer::Age => {
                    let r = self.decrypt(reader, ages)?;
                    ages += 1;
                    r
                }
                layer => decoder(layer, reader, decode_limits)?,
            };
        };
        match &self.found {
            Some(found) if *found != (layers.clone(), container) => return Err(Error::Changed),
            Some(_) => {}
            None => self.found = Some((layers.clone(), container)),
        }
        Ok(Opened {
            layers,
            container,
            reader,
        })
    }

    /// The `index`th age layer, decrypted: with its file key if it was
    /// decrypted before, else with the identities, its file key kept.
    fn decrypt<'a>(
        &mut self,
        reader: Box<dyn Read + Send + 'a>,
        index: usize,
    ) -> Result<Box<dyn Read + Send + 'a>, Error> {
        if let Some(key) = self.file_keys.get(index) {
            let known = FileKeyIdentity(key.clone());
            return match crate::age::decrypt_file(reader, &[&known]) {
                Ok(decryptor) => Ok(Box::new(decryptor)),
                Err(crate::age::Error::HeaderMac) => Err(Error::Changed),
                Err(error) => Err(error.into()),
            };
        }
        let identities: Vec<&dyn Identity> = self
            .identities
            .iter()
            .map(|identity| &**identity as &dyn Identity)
            .collect();
        let decryptor = crate::age::decrypt_file(reader, &identities)?;
        self.file_keys.truncate(index);
        self.file_keys.push(decryptor.file_key().clone());
        Ok(Box::new(decryptor))
    }
}

/// Reads `reader` into `head` until it holds `len` bytes or the stream
/// ends; an error stops it, and is given back.
fn read_more(reader: &mut impl Read, head: &mut Vec<u8>, len: usize) -> Option<io::Error> {
    let mut buf = vec![0u8; len - head.len().min(len)];
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                head.extend_from_slice(&buf[..filled]);
                return Some(e);
            }
        }
    }
    head.extend_from_slice(&buf[..filled]);
    None
}

/// A stream whose first read gives an error met while looking ahead, and
/// the stream's reads after it.
struct Deferred<R> {
    error: Option<io::Error>,
    inner: R,
}

impl<R: Read> Read for Deferred<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.error.take() {
            Some(error) => Err(error),
            None => self.inner.read(buf),
        }
    }
}
