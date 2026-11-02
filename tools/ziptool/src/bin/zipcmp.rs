//! zipcmp, which compares two archives and prints how they differ: port of
//! libzip's `src/zipcmp.c` and `src/diff_output.c`, for archives. It is
//! what libzip's tests compare the archives they write with (`zipcmp -pv`).
//!
//! Differs from libzip: directories are not read, as in a libzip built
//! without `fts.h`.

use std::io::Read;
use std::process::ExitCode;

use hivepack::deflate::crc32;
use hivepack::zip::{Archive, Error, Flags, OpenFlags};
use ziptool::{Getopt, Src, zip_open};

const PROGRAM: &str = "zipcmp";
const OPTIONS: &str = "ChipqsTtVv";

const HELP_HEAD: &str = "zipcmp (libzip) by Dieter Baron and Thomas Klausner\n\n";
const HELP: &str = "
  -C       check archive consistencies
  -h       display this help message
  -i       compare names ignoring case distinctions
  -p       compare as many details as possible
  -q       be quiet
  -s       print a summary
  -T       compare time stamps
  -t       test zip files (compare file contents to checksum)
  -V       display version number
  -v       be verbose (print differences, default)

Report bugs to <info@libzip.org>.
";
const VERSION_STRING: &str = "zipcmp (libzip 1.12.1)
Copyright (C) 2003-2025 Dieter Baron and Thomas Klausner
libzip comes with ABSOLUTELY NO WARRANTY, to the extent permitted by law.
";

/// `comp_methods`.
const COMP_METHODS: &[(u32, &str)] = &[
    (0, "Stored (no compression)"),
    (1, "Shrunk"),
    (2, "Reduced with compression factor 1"),
    (3, "Reduced with compression factor 2"),
    (4, "Reduced with compression factor 3"),
    (5, "Reduced with compression factor 4"),
    (6, "Imploded"),
    (7, "Reserved for Tokenizing compression algorithm"),
    (8, "Deflated"),
    (9, "Enhanced Deflating using Deflate64(tm)"),
    (
        10,
        "PKWARE Data Compression Library Imploding (old IBM TERSE)",
    ),
    (11, "11 (Reserved by PKWARE)"),
    (12, "BZIP2"),
    (13, "13 (Reserved by PKWARE)"),
    (14, "LZMA (EFS)"),
    (15, "15 (Reserved by PKWARE)"),
    (16, "16 (Reserved by PKWARE)"),
    (17, "17 (Reserved by PKWARE)"),
    (18, "IBM TERSE (new)"),
    (19, "IBM LZ77 z Architecture (PFS)"),
    (20, "Zstandard compressed data (obsolete)"),
    (93, "Zstandard compressed data"),
    (95, "XZ compressed data"),
    (97, "WavPack compressed data"),
    (98, "PPMd version I, Rev 1"),
    (99, "WinZIP AES Encryption"),
];

/// `extra_fields`.
const EXTRA_FIELDS: &[(u32, &str)] = &[
    // PKWARE defined
    (0x0001, "Zip64 extended information"),
    (0x0007, "AV Info"),
    (0x0008, "Reserved for extended language encoding data (PFS)"),
    (0x0009, "OS/2"),
    (0x000a, "NTFS"),
    (0x000c, "OpenVMS"),
    (0x000d, "UNIX"),
    (0x000e, "Reserved for file stream and fork descriptors"),
    (0x000f, "Patch Descriptor"),
    (0x0014, "PKCS#7 Store for X.509 Certificates"),
    (
        0x0015,
        "X.509 Certificate ID and Signature for individual file",
    ),
    (0x0016, "X.509 Certificate ID for Central Directory"),
    (0x0017, "Strong Encryption Header"),
    (0x0018, "Record Management Controls"),
    (0x0019, "PKCS#7 Encryption Recipient Certificate List"),
    (
        0x0065,
        "IBM S/390 (Z390), AS/400 (I400) attributes - uncompressed",
    ),
    (
        0x0066,
        "Reserved for IBM S/390 (Z390), AS/400 (I400) attributes - compressed",
    ),
    (0x4690, "POSZIP 4690 (reserved)"),
    // Third-Party defined; see InfoZIP unzip sources proginfo/extrafld.txt
    (0x07c8, "Info-ZIP Macintosh (old)"),
    (0x2605, "ZipIt Macintosh (first version)"),
    (0x2705, "ZipIt Macintosh 1.3.5+ (w/o full filename)"),
    (0x2805, "ZipIt Macintosh 1.3.5+"),
    (0x334d, "Info-ZIP Macintosh (new)"),
    (0x4154, "Tandem NSK"),
    (0x4341, "Acorn/SparkFS"),
    (0x4453, "Windows NT security descriptor"),
    (0x4704, "VM/CMS"),
    (0x470f, "MVS"),
    (0x4854, "Theos, old unofficial port"),
    (0x4b46, "FWKCS MD5"),
    (0x4c41, "OS/2 access control list (text ACL)"),
    (0x4d49, "Info-ZIP OpenVMS (obsolete)"),
    (0x4d63, "Macintosh SmartZIP"),
    (0x4f4c, "Xceed original location extra field"),
    (0x5356, "AOS/VS (ACL)"),
    (0x5455, "extended timestamp"),
    (0x554e, "Xceed unicode extra field"),
    (0x5855, "Info-ZIP UNIX (original)"),
    (0x6375, "Info-ZIP UTF-8 comment field"),
    (0x6542, "BeOS (BeBox, PowerMac, etc.)"),
    (0x6854, "Theos"),
    (0x7075, "Info-ZIP UTF-8 name field"),
    (0x7441, "AtheOS (AtheOS/Syllable attributes)"),
    (0x756e, "ASi UNIX"),
    (0x7855, "Info-ZIP UNIX"),
    (0x7875, "Info-ZIP UNIX 3rd generation"),
    (0x9901, "WinZIP AES encryption"),
    (0xa220, "Microsoft Open Packaging Growth Hint"),
    (0xcafe, "executable Java JAR file"),
    (0xfb4a, "SMS/QDOS"), // per InfoZIP extrafld.txt
    (0xfd4a, "SMS/QDOS"), // per appnote.txt
];

/// `ZIP_FL_LOCAL` and `ZIP_FL_CENTRAL`, as `struct ef` keeps them.
const LOCAL: u16 = 256;
const CENTRAL: u16 = 512;

/// `struct ef`: an extra field of one header.
struct Ef {
    flags: u16,
    id: u16,
    data: Vec<u8>,
}

/// `struct entry`.
#[derive(Default)]
struct Entry {
    name: Vec<u8>,
    size: u64,
    crc: u32,
    comp_method: u32,
    last_modification_time: i64,
    extra_fields: Vec<Ef>,
    comment: Vec<u8>,
}

/// `struct archive`.
#[derive(Default)]
struct ArchiveList {
    entry: Vec<Entry>,
    comment: Vec<u8>,
}

/// The options and counters, the C program's globals.
struct Zipcmp {
    progname: String,
    ignore_case: bool,
    test_files: bool,
    paranoid: bool,
    check_consistency: bool,
    compare_time_stamps: bool,
    summary: bool,
    plus_count: u32,
    minus_count: u32,
    output: DiffOutput,
}

/// `diff_output_t`.
struct DiffOutput {
    archive_names: Option<[String; 2]>,
    verbose: bool,
    /// the file whose details are printed before its first difference
    file: Option<(Vec<u8>, u64, u32, u64)>,
}

impl DiffOutput {
    /// `ensure_header`.
    fn ensure_header(&mut self) {
        if let Some([a, b]) = self.archive_names.take() {
            println!("--- {a}");
            println!("+++ {b}");
        }
    }

    /// `diff_output_start_file`.
    fn start_file(&mut self, name: &[u8], size: u64, crc: u32, mtime: u64) {
        self.file = Some((name.to_vec(), size, crc, mtime));
    }

    /// `diff_output_end_file`.
    fn end_file(&mut self) {
        self.file = None;
    }

    /// `diff_output`.
    fn line(&mut self, side: char, text: &str) {
        if !self.verbose {
            return;
        }
        self.ensure_header();
        if let Some((name, size, crc, mtime)) = self.file.take() {
            self.file_line(' ', &name, size, crc, mtime);
        }
        println!("{side} {text}");
    }

    /// `diff_output_file`.
    fn file_line(&mut self, side: char, name: &[u8], size: u64, crc: u32, mtime: u64) {
        if !self.verbose {
            return;
        }
        self.ensure_header();
        let name_text = String::from_utf8_lossy(name);
        if size == 0 && crc == 0 && name.last() == Some(&b'/') {
            println!("{side} directory '{name_text}'");
        } else {
            println!("{side} file '{name_text}', size {size}, crc {crc:08x}, mtime {mtime}");
        }
    }

    /// `diff_output_data`.
    fn data(&mut self, side: char, data: &[u8], prefix: &str) {
        if !self.verbose {
            return;
        }
        // MAX_BYTES
        let mut hexdata = String::new();
        for (i, b) in data.iter().enumerate() {
            hexdata.push(if i == 0 { '<' } else { ' ' });
            if i >= 64 {
                hexdata.push_str("...");
                break;
            }
            hexdata.push_str(&format!("{b:02x}"));
        }
        hexdata.push('>');
        self.line(
            side,
            &format!("{prefix}, length {}, data {hexdata}", data.len()),
        );
    }
}

/// `map_enum`.
fn map_enum(map: &[(u32, &str)], value: u32) -> String {
    match map.iter().find(|(v, _)| *v == value) {
        Some((_, name)) => (*name).to_string(),
        None => format!("unknown ({value})"),
    }
}

/// A name as C sees it: up to its first NUL byte.
fn c_string(name: &[u8]) -> &[u8] {
    &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())]
}

/// `strcmp`, or `strcasecmp`.
fn compare_names(a: &[u8], b: &[u8], ignore_case: bool) -> std::cmp::Ordering {
    if ignore_case {
        a.iter()
            .map(u8::to_ascii_lowercase)
            .cmp(b.iter().map(u8::to_ascii_lowercase))
    } else {
        a.cmp(b)
    }
}

/// `ef_order`: by header, then id, length and data.
fn ef_order(a: &Ef, b: &Ef) -> std::cmp::Ordering {
    a.flags
        .cmp(&b.flags)
        .then(a.id.cmp(&b.id))
        .then(a.data.len().cmp(&b.data.len()))
        .then(a.data.cmp(&b.data))
}

impl Zipcmp {
    /// `entry_cmp`: by name, size and CRC, and time with `-T`.
    fn entry_cmp(&self, e1: &Entry, e2: &Entry) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        let c = compare_names(&e1.name, &e2.name, self.ignore_case);
        if c != Ordering::Equal {
            return c;
        }
        if e1.size != e2.size {
            return e1.size.cmp(&e2.size);
        }
        if e1.crc != e2.crc {
            // (int)e1->crc - (int)e2->crc
            return (e1.crc as i32).wrapping_sub(e2.crc as i32).cmp(&0);
        }
        if self.compare_time_stamps && e1.last_modification_time != e2.last_modification_time {
            return (e1
                .last_modification_time
                .wrapping_sub(e2.last_modification_time) as i32)
                .cmp(&0);
        }
        Ordering::Equal
    }

    /// `list_zip`: the entries of the archive `name`, and its comment.
    fn list_zip(&mut self, name: &str) -> Result<ArchiveList, ()> {
        let flags = if self.check_consistency {
            OpenFlags::CHECKCONS
        } else {
            OpenFlags(0)
        };
        let za = match zip_open(name, flags, 0, 0) {
            Ok(za) => za,
            Err(e) => {
                // zip_error_init_with_code
                let e = Error::new(e.code(), e.system());
                eprintln!("{}: cannot open zip archive '{name}': {e}", self.progname);
                return Err(());
            }
        };

        let mut a = ArchiveList::default();
        let nentry = za.get_num_entries(Flags::NONE);
        if nentry == 0 {
            return Ok(a);
        }
        for i in 0..nentry {
            let st = match za.stat_index(i, Flags::NONE) {
                Ok(st) => st,
                Err(e) => {
                    eprintln!(
                        "{}: warning: cannot stat file {i} in zip archive '{name}': {e}",
                        self.progname
                    );
                    continue;
                }
            };
            let st_name = c_string(st.name.unwrap_or_default()).to_vec();
            let mut entry = Entry {
                name: st_name.clone(),
                size: st.size,
                crc: st.crc,
                ..Entry::default()
            };
            if self.test_files {
                let _ = self.test_file(&za, i, name, &st_name, st.size, st.crc);
            }
            if self.paranoid {
                entry.comp_method = u32::from(st.comp_method);
                entry.extra_fields = ef_read(&za, i);
                entry.comment = za
                    .file_get_comment(i, Flags::NONE)
                    .map(<[u8]>::to_vec)
                    .unwrap_or_default();
            }
            entry.last_modification_time = st.mtime;
            a.entry.push(entry);
        }
        if self.paranoid {
            a.comment = za.get_archive_comment(Flags::NONE).to_vec();
        }
        Ok(a)
    }

    /// `test_file`: whether entry `idx` reads back to its size and CRC.
    fn test_file(
        &self,
        za: &Archive<Src>,
        idx: u64,
        zipname: &str,
        filename: &[u8],
        size: u64,
        crc: u32,
    ) -> Result<(), ()> {
        let filename = String::from_utf8_lossy(filename);
        let progname = &self.progname;
        let mut zf = match za.fopen_index(idx, Flags::NONE) {
            Ok(zf) => zf,
            Err(e) => {
                eprintln!("{progname}: {zipname}: cannot open file {filename} (index {idx}): {e}");
                return Err(());
            }
        };
        let mut buf = vec![0; 8192];
        let (mut nsize, mut ncrc) = (0u64, crc32(0, &[]));
        loop {
            match zf.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    nsize += n as u64;
                    ncrc = crc32(ncrc, &buf[..n]);
                }
                Err(e) => {
                    eprintln!(
                        "{progname}: {zipname}: error reading file {filename} (index {idx}): {e}"
                    );
                    let _ = zf.fclose();
                    return Err(());
                }
            }
        }
        let _ = zf.fclose();
        if nsize != size {
            eprintln!(
                "{progname}: {zipname}: file {filename} (index {idx}): unexpected length {nsize} (should be {size})"
            );
            return Err(());
        }
        if ncrc != crc {
            // libzip's message says length here too.
            eprintln!(
                "{progname}: {zipname}: file {filename} (index {idx}): unexpected length {ncrc:x} (should be {crc:x})"
            );
            return Err(());
        }
        Ok(())
    }

    /// `compare_zip`: 0 if the archives are the same, 1 if they differ, 2
    /// on error.
    fn compare_zip(&mut self, zn: [&str; 2]) -> u8 {
        let mut a = [ArchiveList::default(), ArchiveList::default()];
        for i in 0..2 {
            if std::fs::metadata(zn[i]).is_ok_and(|m| m.is_dir()) {
                eprintln!("{}: reading directories not supported", self.progname);
                return 2;
            }
            match self.list_zip(zn[i]) {
                Ok(list) => a[i] = list,
                Err(()) => return 2,
            }
            // qsort, which glibc's sorts stably
            let mut entries = std::mem::take(&mut a[i].entry);
            entries.sort_by(|x, y| self.entry_cmp(x, y));
            a[i].entry = entries;
        }

        self.output = DiffOutput {
            archive_names: Some([zn[0].to_string(), zn[1].to_string()]),
            verbose: self.output.verbose,
            file: None,
        };

        let mut res = self.compare_entries(&a[0].entry, &a[1].entry);

        if self.paranoid && a[0].comment != a[1].comment {
            if !a[0].comment.is_empty() {
                self.output.data('-', &a[0].comment, "archive comment");
                self.minus_count += 1;
            }
            if !a[1].comment.is_empty() {
                self.output.data('+', &a[1].comment, "archive comment");
                self.plus_count += 1;
            }
            res = true;
        }

        if self.summary {
            println!(
                "{} files removed, {} files added",
                self.minus_count, self.plus_count
            );
        }
        u8::from(res)
    }

    /// `compare_list` of the entries, with `entry_paranoia_checks` for
    /// those in both with `-p`.
    fn compare_entries(&mut self, l0: &[Entry], l1: &[Entry]) -> bool {
        use std::cmp::Ordering;
        let (mut i0, mut i1) = (0, 0);
        let mut diff = false;
        while i0 < l0.len() && i1 < l1.len() {
            match self.entry_cmp(&l0[i0], &l1[i1]) {
                Ordering::Equal => {
                    if self.paranoid {
                        let e = &l0[i0];
                        self.output.start_file(
                            &e.name,
                            e.size,
                            e.crc,
                            e.last_modification_time as u64,
                        );
                        diff |= self.entry_paranoia_checks(&l0[i0], &l1[i1]);
                        self.output.end_file();
                    }
                    i0 += 1;
                    i1 += 1;
                }
                Ordering::Less => {
                    self.entry_print('-', &l0[i0]);
                    diff = true;
                    i0 += 1;
                }
                Ordering::Greater => {
                    self.entry_print('+', &l1[i1]);
                    diff = true;
                    i1 += 1;
                }
            }
        }
        for e in &l0[i0..] {
            self.entry_print('-', e);
            diff = true;
        }
        for e in &l1[i1..] {
            self.entry_print('+', e);
            diff = true;
        }
        diff
    }

    /// `entry_print`, counted as `compare_list`'s `PRINT` counts.
    fn entry_print(&mut self, side: char, e: &Entry) {
        self.output.file_line(
            side,
            &e.name,
            e.size,
            e.crc,
            e.last_modification_time as u64,
        );
        if side == '+' {
            self.plus_count += 1;
        } else {
            self.minus_count += 1;
        }
    }

    /// `entry_paranoia_checks`: the compression method, the extra fields
    /// and the comment.
    fn entry_paranoia_checks(&mut self, e1: &Entry, e2: &Entry) -> bool {
        let mut ret = false;
        if e1.comp_method != e2.comp_method {
            self.output.line(
                '-',
                &format!(
                    "  compression method {}",
                    map_enum(COMP_METHODS, e1.comp_method)
                ),
            );
            self.output.line(
                '+',
                &format!(
                    "  compression method {}",
                    map_enum(COMP_METHODS, e2.comp_method)
                ),
            );
            ret = true;
        }
        if self.ef_compare(e1, e2) {
            ret = true;
        }
        if e1.comment != e2.comment {
            self.output.data('-', &e1.comment, "  comment");
            self.output.data('+', &e2.comment, "  comment");
            ret = true;
        }
        ret
    }

    /// `ef_compare`: `compare_list` of the extra fields, sorted.
    fn ef_compare(&mut self, e1: &Entry, e2: &Entry) -> bool {
        use std::cmp::Ordering;
        let (l0, l1) = (&e1.extra_fields, &e2.extra_fields);
        let (mut i0, mut i1) = (0, 0);
        let mut diff = false;
        while i0 < l0.len() && i1 < l1.len() {
            match ef_order(&l0[i0], &l1[i1]) {
                Ordering::Equal => {
                    i0 += 1;
                    i1 += 1;
                }
                Ordering::Less => {
                    self.ef_print('-', &l0[i0]);
                    diff = true;
                    i0 += 1;
                }
                Ordering::Greater => {
                    self.ef_print('+', &l1[i1]);
                    diff = true;
                    i1 += 1;
                }
            }
        }
        for ef in &l0[i0..] {
            self.ef_print('-', ef);
            diff = true;
        }
        for ef in &l1[i1..] {
            self.ef_print('+', ef);
            diff = true;
        }
        diff
    }

    /// `ef_print`, counted as `compare_list`'s `PRINT` counts.
    fn ef_print(&mut self, side: char, ef: &Ef) {
        let header = if ef.flags == LOCAL {
            "local"
        } else {
            "central"
        };
        self.output.data(
            side,
            &ef.data,
            &format!(
                "  {header} extra field {}",
                map_enum(EXTRA_FIELDS, u32::from(ef.id))
            ),
        );
        if side == '+' {
            self.plus_count += 1;
        } else {
            self.minus_count += 1;
        }
    }
}

/// `ef_read`: the extra fields of both headers of entry `idx`, sorted, or
/// none if they cannot be counted.
fn ef_read(za: &Archive<Src>, idx: u64) -> Vec<Ef> {
    let (Ok(n_local), Ok(n_central)) = (
        za.file_extra_fields_count(idx, Flags::LOCAL),
        za.file_extra_fields_count(idx, Flags::CENTRAL),
    ) else {
        return Vec::new();
    };
    let mut fields = Vec::new();
    for (flags, count, flag) in [
        (LOCAL, n_local, Flags::LOCAL),
        (CENTRAL, n_central, Flags::CENTRAL),
    ] {
        for i in 0..count.max(0) as u16 {
            let (id, data) = za
                .file_extra_field_get(idx, i, flag)
                .map_or((0, Vec::new()), |(id, data)| (id, data.to_vec()));
            fields.push(Ef { flags, id, data });
        }
    }
    fields.sort_by(ef_order);
    fields
}

fn usage(progname: &str) -> String {
    format!("usage: {progname} [-{OPTIONS}] archive1 archive2")
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let progname = argv.first().cloned().unwrap_or_else(|| PROGRAM.into());
    let mut z = Zipcmp {
        progname: progname.clone(),
        ignore_case: false,
        test_files: false,
        paranoid: false,
        check_consistency: false,
        compare_time_stamps: false,
        summary: false,
        plus_count: 0,
        minus_count: 0,
        output: DiffOutput {
            archive_names: None,
            verbose: true,
            file: None,
        },
    };

    let mut getopt = Getopt::new(&argv);
    while let Some(option) = getopt.next(OPTIONS) {
        match option {
            Ok(('C', _)) => z.check_consistency = true,
            Ok(('h', _)) => {
                print!("{HELP_HEAD}");
                println!("{}", usage(&progname));
                print!("{HELP}");
                return ExitCode::SUCCESS;
            }
            Ok(('i', _)) => z.ignore_case = true,
            Ok(('p', _)) => z.paranoid = true,
            Ok(('q', _)) => z.output.verbose = false,
            Ok(('s', _)) => z.summary = true,
            Ok(('T', _)) => z.compare_time_stamps = true,
            Ok(('t', _)) => z.test_files = true,
            Ok(('V', _)) => {
                print!("{VERSION_STRING}");
                return ExitCode::SUCCESS;
            }
            Ok(('v', _)) => z.output.verbose = true,
            _ => {
                eprintln!("{}", usage(&progname));
                return ExitCode::from(2);
            }
        }
    }

    if argv.len() != getopt.optind + 2 {
        eprintln!("{}", usage(&progname));
        return ExitCode::from(2);
    }

    let names = [
        argv[getopt.optind].as_str(),
        argv[getopt.optind + 1].as_str(),
    ];
    ExitCode::from(z.compare_zip(names))
}
