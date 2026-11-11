//! Reading an archive from several threads through one: each thread asks
//! for the pieces it reads, and the thread that holds the reader reads them,
//! one at a time, so that the reader needs no more than [`Read`] and [`Seek`].
//! 7z's folders decoded at once and SquashFS's files written at once read so.

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::mpsc::{self, Receiver, SyncSender};

/// A piece of the archive a thread asks for: `buf.len()` bytes at `pos`, and
/// where to send them.
pub(crate) struct Request {
    pos: u64,
    buf: Vec<u8>,
    reply: SyncSender<Reply>,
}

/// The buffer of a [`Request`], filled with as many bytes as there were, or
/// the error reading them.
type Reply = (Vec<u8>, io::Result<usize>);

/// Reads what the threads ask of `reader`, one piece at a time, until none of
/// them is left to ask.
pub(crate) fn serve<R: Read + Seek>(reader: &mut R, asked: &Receiver<Request>) {
    for Request {
        pos,
        mut buf,
        reply,
    } in asked
    {
        let read = read_at(reader, pos, &mut buf);
        // A thread that is gone needs no answer.
        let _ = reply.send((buf, read));
    }
}

/// Fills `buf` from `pos` in `reader`, as far as it goes.
fn read_at<R: Read + Seek>(reader: &mut R, pos: u64, buf: &mut [u8]) -> io::Result<usize> {
    reader.seek(SeekFrom::Start(pos))?;
    let mut got = 0;
    while got < buf.len() {
        match reader.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}

/// The archive, read by a thread through the one that [`serve`]s it.
pub(crate) struct Remote {
    pos: u64,
    requests: SyncSender<Request>,
    reply: SyncSender<Reply>,
    replies: Receiver<Reply>,
    /// The buffer sent with each request, kept between them.
    buf: Vec<u8>,
}

impl Remote {
    pub(crate) fn new(requests: SyncSender<Request>) -> Remote {
        let (reply, replies) = mpsc::sync_channel(1);
        Remote {
            pos: 0,
            requests,
            reply,
            replies,
            buf: Vec::new(),
        }
    }
}

impl Read for Remote {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut buf = std::mem::take(&mut self.buf);
        buf.resize(out.len(), 0);
        let gone = || io::Error::other("the archive's reader is gone");
        let request = Request {
            pos: self.pos,
            buf,
            reply: self.reply.clone(),
        };
        self.requests.send(request).map_err(|_| gone())?;
        let (buf, read) = self.replies.recv().map_err(|_| gone())?;
        self.buf = buf;
        let n = read?.min(out.len());
        out[..n].copy_from_slice(&self.buf[..n]);
        self.pos = self.pos.saturating_add(n as u64);
        Ok(n)
    }
}

impl Seek for Remote {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.pos = match to {
            SeekFrom::Start(pos) => Some(pos),
            SeekFrom::Current(by) => self.pos.checked_add_signed(by),
            SeekFrom::End(_) => None,
        }
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(self.pos)
    }
}
