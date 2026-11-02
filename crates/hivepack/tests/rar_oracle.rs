// hivepack::rar's tests. UnRAR's license, which they are under with the
// crate:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.

//! Comparison with UnRAR 7.3.2 through `tools/rar-oracle`: every header of
//! an archive, as UnRAR reads it, and every entry, as UnRAR tests it.
//!
//! The oracle is a small C++ program built with UnRAR's sources by
//! `scripts/testdata.py`. It answers `list <enable_broken> <hex>` by
//! opening the archive with UnRAR's `Archive`, reading every header, and
//! printing what UnRAR keeps of each: its fields, the archive's state and
//! the exit code. It answers `test <hex>` by going through the archive with
//! UnRAR's `CmdExtract`, printing what became of each header: how much data
//! came out, its hash, the position and the exit code. It answers
//! `hash <type> <chunk> <hex>` with UnRAR's `DataHash`, as no
//! archive at hand stores data under BLAKE2sp or RAR 1.4's checksum.
//! [`answer`] answers the same requests with the port, and the two are
//! compared as text, on libarchive's RAR test archives and on damaged copies
//! of them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Off Linux only the recorded answers are replayed, without the oracle.
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

#[path = "rar_support/mod.rs"]
mod support;

use std::fmt::Write as _;

use hivepack::rar::*;
use support::{Oracle, Rng, damage, hex, libarchive_archives, unhex};

/// The text the oracle prints, built from the port's state.
struct Out(String);

impl Out {
    fn put(&mut self, key: &str, value: u64) {
        let _ = write!(self.0, " {key}={value:x}");
    }

    fn bool(&mut self, key: &str, value: bool) {
        self.put(key, u64::from(value));
    }

    fn bytes(&mut self, key: &str, data: &[u8]) {
        let _ = write!(self.0, " {key}={}", hex(data));
    }

    fn wide(&mut self, key: &str, s: &[u32]) {
        let _ = write!(self.0, " {key}=");
        if s.is_empty() {
            self.0.push('-');
        }
        for (i, c) in s.iter().enumerate() {
            let _ = write!(self.0, "{}{c:x}", if i > 0 { "." } else { "" });
        }
    }

    /// `GetUnixNS`, which is the ticks less 1601 to 1970, as UnRAR
    /// computes it, wrapping.
    fn time(&mut self, key: &str, t: &RarTime) {
        self.put(key, t.ticks().wrapping_sub(11_644_473_600_000_000_000));
    }

    fn base(&mut self, b: &BaseBlock) {
        self.put("crc", u64::from(b.head_crc));
        self.put("type", u64::from(b.header_type));
        self.put("flags", u64::from(b.flags));
        self.put("size", u64::from(b.head_size));
        self.bool("skip", b.skip_if_unknown);
    }

    /// What UnRAR does not set is left out, as the oracle leaves it out.
    fn file(&mut self, h: &FileHeader, format: Format) {
        if format == Format::Rar14 {
            self.put("type", u64::from(h.base.header_type));
            self.put("flags", u64::from(h.base.flags));
            self.put("size", u64::from(h.base.head_size));
        } else {
            self.base(&h.base);
        }
        if format != Format::Rar50 {
            self.put("ds", u64::from(h.data_size));
        }
        self.put("host", u64::from(h.host_os));
        self.put("unpver", u64::from(h.unp_ver));
        self.put("method", u64::from(h.method));
        self.put("attr", u64::from(h.file_attr));
        self.wide("name", &h.file_name);
        self.bytes("subdata", &h.sub_data);
        self.time("mtime", &h.mtime);
        self.time("ctime", &h.ctime);
        self.time("atime", &h.atime);
        self.put("packsize", h.pack_size as u64);
        self.put("unpsize", h.unp_size as u64);
        if format == Format::Rar50 {
            self.put("maxsize", h.max_size as u64);
        }
        // UnRAR keeps the CRC and the digest in a union: only what the
        // type says is meaningful.
        self.put("hashtype", u64::from(h.file_hash.kind.number()));
        if matches!(h.file_hash.kind, HashType::Rar14 | HashType::Crc32) {
            self.put("crc32", u64::from(h.file_hash.crc32));
        }
        if h.file_hash.kind == HashType::Blake2 {
            self.bytes("digest", &h.file_hash.digest);
        }
        if format == Format::Rar50 {
            self.put("fileflags", u64::from(h.file_flags));
        }
        self.bool("splitbefore", h.split_before);
        self.bool("splitafter", h.split_after);
        self.bool("unknownsize", h.unknown_unp_size);
        self.bool("encrypted", h.encrypted);
        self.put("cryptmethod", u64::from(h.crypt_method.number()));
        self.bool("saltset", h.salt_set);
        if h.salt_set {
            let size = if format == Format::Rar50 {
                SIZE_SALT50
            } else {
                SIZE_SALT30
            };
            self.bytes("salt", &h.salt[..size]);
        }
        if h.crypt_method == CryptMethod::Rar50 {
            self.bytes("initv", &h.init_v);
        }
        self.bool("usepswcheck", h.use_psw_check);
        if h.use_psw_check {
            self.bytes("pswcheck", &h.psw_check);
        }
        self.bool("usehashkey", h.use_hash_key);
        self.put("lg2count", u64::from(h.lg2_count));
        self.bool("solid", h.solid);
        self.bool("dir", h.dir);
        self.bool("commentinheader", h.comment_in_header);
        self.bool("version", h.version);
        self.put("winsize", h.win_size);
        self.bool("inherited", h.inherited);
        self.bool("largefile", h.large_file);
        self.bool("subblock", h.sub_block);
        self.put(
            "hstype",
            match h.hs_type {
                HostSystem::Windows => 0,
                HostSystem::Unix => 1,
                HostSystem::Unknown => 2,
            },
        );
        self.put("redirtype", u64::from(h.redir_type.number()));
        if h.redir_type != Redirection::None {
            self.wide("redirname", &h.redir_name);
        }
        self.bool("dirtarget", h.dir_target);
        self.bool("ownerset", h.unix_owner_set);
        if h.unix_owner_set {
            self.bool("ownernumeric", h.unix_owner_numeric);
            self.bool("groupnumeric", h.unix_group_numeric);
            self.bytes("owner", &h.unix_owner_name);
            self.bytes("group", &h.unix_group_name);
            if h.unix_owner_numeric {
                self.put("ownerid", u64::from(h.unix_owner_id));
            }
            if h.unix_group_numeric {
                self.put("groupid", u64::from(h.unix_group_id));
            }
        }
    }

    fn state<R: ReadAt>(&mut self, a: &Archive<R>) {
        self.put(
            "format",
            match a.format {
                Format::None => 0,
                Format::Rar14 => 1,
                Format::Rar15 => 2,
                Format::Rar50 => 3,
                Format::Future => 4,
            },
        );
        self.bool("solid", a.solid);
        self.bool("volume", a.volume);
        self.bool("maincomment", a.main_comment);
        self.bool("locked", a.locked);
        self.bool("signed", a.signed);
        self.bool("firstvolume", a.first_volume);
        self.bool("newnumbering", a.new_numbering);
        self.bool("protected", a.protected);
        self.bool("encrypted", a.encrypted);
        self.put("sfx", a.sfx_size);
        self.bool("broken", a.broken_header);
        self.bool("faileddecryption", a.failed_header_decryption);
        self.put("volnumber", u64::from(a.vol_number));
        self.put("recovery", i64::from(a.recovery_percent) as u64);
        self.put("cur", a.cur_block_pos as u64);
        self.put("next", a.next_block_pos as u64);
        self.put("headertype", u64::from(a.cur_header_type));
    }

    /// Each header by its kind, for the kinds its format reads, as the
    /// oracle prints them.
    fn header<R: ReadAt>(&mut self, a: &Archive<R>) {
        let kind = match a.cur_header_type {
            t @ (HEAD_MAIN | HEAD_FILE | HEAD_SERVICE | HEAD_ENDARC) => Some(t),
            HEAD_CRYPT if a.format == Format::Rar50 => Some(HEAD_CRYPT),
            t @ (HEAD3_CMT | HEAD3_PROTECT | HEAD3_OLDSERVICE) if a.format == Format::Rar15 => {
                Some(t)
            }
            _ => None,
        };
        match kind.unwrap_or(HEAD_UNKNOWN) {
            HEAD_MAIN => {
                let m = &a.main_head;
                self.base(&m.base);
                self.put("highposav", u64::from(m.high_pos_av));
                self.put("posav", u64::from(m.pos_av));
                self.bool("commentinheader", m.comment_in_header);
                self.bool("packcomment", m.pack_comment);
                self.bool("locator", m.locator);
                self.put("qopen", m.qopen_offset);
                self.put("rr", m.rr_offset);
                self.wide("origname", &m.orig_name);
                self.time("origtime", &m.orig_time);
            }
            HEAD_FILE => self.file(&a.file_head, a.format),
            HEAD_SERVICE => self.file(&a.sub_head, a.format),
            HEAD_CRYPT => {
                let c = &a.crypt_head;
                self.base(&c.base);
                self.bool("usepswcheck", c.use_psw_check);
                self.put("lg2count", u64::from(c.lg2_count));
                self.bytes("salt", &c.salt);
                if c.use_psw_check {
                    self.bytes("pswcheck", &c.psw_check);
                }
            }
            HEAD_ENDARC => {
                let e = &a.end_arc_head;
                self.base(&e.base);
                self.bool("nextvolume", e.next_volume);
                self.bool("datacrc", e.data_crc);
                self.bool("revspace", e.rev_space);
                self.bool("storevolnumber", e.store_vol_number);
                if e.data_crc {
                    self.put("arcdatacrc", u64::from(e.arc_data_crc));
                }
                if e.store_vol_number {
                    self.put("endvolnumber", u64::from(e.vol_number));
                }
            }
            HEAD3_CMT => {
                let c = &a.comm_head;
                self.base(&c.base);
                self.put("unpsize", u64::from(c.unp_size));
                self.put("unpver", u64::from(c.unp_ver));
                self.put("method", u64::from(c.method));
                self.put("commcrc", u64::from(c.comm_crc));
            }
            HEAD3_PROTECT => {
                let p = &a.protect_head;
                self.base(&p.base);
                self.put("ds", u64::from(p.data_size));
                self.put("version", u64::from(p.version));
                self.put("recsectors", u64::from(p.rec_sectors));
                self.put("totalblocks", u64::from(p.total_blocks));
                self.bytes("mark", &p.mark);
            }
            HEAD3_OLDSERVICE => {
                let s = &a.sub_block_head;
                self.base(&s.base);
                self.put("ds", u64::from(s.data_size));
                self.put("subtype", u64::from(s.sub_type));
                self.put("level", u64::from(s.level));
                if s.sub_type == NTACL_HEAD || s.sub_type == STREAM_HEAD {
                    self.put("unpsize", u64::from(s.unp_size));
                    self.put("unpver", u64::from(s.unp_ver));
                    self.put("method", u64::from(s.method));
                    self.put("subcrc", u64::from(s.crc));
                }
                if s.sub_type == STREAM_HEAD {
                    self.bytes("streamname", &s.stream_name);
                }
            }
            _ => self.base(&a.short_block),
        }
    }
}

/// Whether UnRAR 7.3.2's mask `*` refuses a name, which the oracle passes
/// over as the port does here: a last part that starts with `*` and goes on,
/// as `match` takes that `*` for a plain character.
fn mask_refuses(name: &[u32]) -> bool {
    let last = name
        .rsplit(|&c| c == u32::from(b'/'))
        .next()
        .unwrap_or_default();
    last.len() >= 2 && last[0] == u32::from(b'*')
}

/// The port's answer to a `test` request, in the oracle's words.
fn answer_test(archive: &[u8], limit: Option<u64>, password: &str) -> String {
    answer_test_on(Archive::open_with_password(archive, true, password), limit)
}

/// The port's answer to a `testvol` request.
fn answer_test_volumes(words: &[&str]) -> String {
    let password = if words[1] == "-" {
        String::new()
    } else {
        String::from_utf8(unhex(words[1])).expect("a password")
    };
    let limit = words[2].parse().expect("a limit");
    let limit = (limit != 0).then_some(limit);
    let volumes: std::collections::HashMap<String, Vec<u8>> = words[3..]
        .chunks(2)
        .map(|pair| (pair[0].to_string(), unhex(pair[1])))
        .collect();
    let first = volumes[words[3]].clone();
    let name = words[3].to_string();
    let opened = Archive::open_volumes(
        first,
        &name,
        move |next: &str| volumes.get(next).cloned(),
        true,
        &password,
    );
    answer_test_on(opened, limit)
}

/// The port's answer to a `comment` request.
fn answer_comment(words: &[&str]) -> String {
    let password = if words[1] == "-" {
        String::new()
    } else {
        String::from_utf8(unhex(words[1])).expect("a password")
    };
    let data = unhex(words[2]);
    let mut out = Out("comment".to_string());
    let exit = match Archive::open_with_password(data.as_slice(), true, &password) {
        Err(Error::NotRar { exit_code }) => {
            out.0 += " notarchive";
            exit_code
        }
        Err(Error::MissingPassword { exit_code }) => {
            out.put("thrown", u64::from(ExitCode::UserBreak.number()));
            exit_code
        }
        Err(Error::BadSeek { exit_code }) => {
            out.put("thrown", u64::from(ExitCode::Fatal.number()));
            exit_code
        }
        Err(e) => panic!("{e}"),
        Ok(mut arc) => {
            let mut code = None;
            match arc.get_comment() {
                Ok(Some(comment)) => {
                    out.0 += " comment=";
                    for c in comment {
                        let _ = write!(out.0, "{c:x},");
                    }
                }
                Ok(None) => out.0 += " none",
                Err(Error::MissingPassword { exit_code }) => {
                    out.put("thrown", u64::from(ExitCode::UserBreak.number()));
                    code = Some(exit_code);
                }
                Err(Error::BadSeek { exit_code }) => {
                    out.put("thrown", u64::from(ExitCode::Fatal.number()));
                    code = Some(exit_code);
                }
                Err(Error::NoMemory) => {
                    out.0 += " badalloc";
                    code = Some(arc.exit_code());
                }
                Err(e) => panic!("{e}"),
            }
            if code.is_none() {
                out.put("pos", arc.position());
            }
            code.unwrap_or_else(|| arc.exit_code())
        }
    };
    out.put("exit", u64::from(exit.number()));
    out.0
}

fn answer_test_on<R: hivepack::rar::ReadAt>(
    opened: Result<Archive<R>, Error>,
    limit: Option<u64>,
) -> String {
    let mut out = Out("test".to_string());
    let exit = match opened {
        Err(Error::NotRar { exit_code }) => {
            out.0 += " notarchive";
            exit_code
        }
        Err(Error::MissingPassword { exit_code }) => {
            out.put("thrown", u64::from(ExitCode::UserBreak.number()));
            exit_code
        }
        Err(Error::BadSeek { exit_code }) => {
            out.put("thrown", u64::from(ExitCode::Fatal.number()));
            exit_code
        }
        Err(e) => panic!("{e}"),
        Ok(mut arc) => {
            out.0 += " archive";
            let mut extract = Extract::new();
            if let Some(limit) = limit {
                extract.win_size_limit = limit;
            }
            loop {
                let size = match arc.read_header() {
                    Ok(size) => size,
                    Err(Error::MissingPassword { exit_code }) => {
                        out.put("thrown", u64::from(ExitCode::UserBreak.number()));
                        break exit_code;
                    }
                    Err(Error::BadSeek { exit_code }) => {
                        out.put("thrown", u64::from(ExitCode::Fatal.number()));
                        break exit_code;
                    }
                    Err(e) => panic!("{e}"),
                };
                out.0 += " |";
                out.put("read", size as u64);
                out.put("headertype", u64::from(arc.cur_header_type));
                out.put("cur", arc.cur_block_pos as u64);
                out.put("next", arc.next_block_pos as u64);
                if size != 0
                    && arc.cur_header_type == HEAD_FILE
                    && mask_refuses(&arc.file_head.file_name)
                {
                    out.0 += " later";
                    arc.seek_to_next();
                    continue;
                }
                let (mut bytes, mut fnv) = (0u64, 0xcbf2_9ce4_8422_2325u64);
                let result = extract.current_file(&mut arc, size, &mut |data| {
                    bytes += data.len() as u64;
                    for &byte in data {
                        fnv = (fnv ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
                    }
                    Ok(())
                });
                match result {
                    Ok(go) => {
                        out.put("data", bytes);
                        out.put("fnv", fnv);
                        // One word for these in UnRAR, the last that can say so.
                        out.bool(
                            "baddata",
                            (extract.broken_file || extract.needs_previous_volume)
                                && !extract.missing_password
                                && !extract.bad_password
                                && !extract.missing_volume
                                && !extract.dictionary_too_large
                                && !extract.unknown_format,
                        );
                        out.bool("nopassword", extract.missing_password);
                        out.bool("badpassword", extract.bad_password);
                        out.bool("novolume", extract.missing_volume);
                        out.put("pos", arc.position());
                        out.bool("broken", arc.broken_header);
                        out.put("code", u64::from(arc.exit_code().number()));
                        if !go {
                            break arc.exit_code();
                        }
                    }
                    Err(Error::BadVolume { exit_code }) => {
                        out.put("thrown", u64::from(ExitCode::BadArchive.number()));
                        break exit_code;
                    }
                    Err(Error::MissingPassword { exit_code }) => {
                        out.put("thrown", u64::from(ExitCode::UserBreak.number()));
                        break exit_code;
                    }
                    Err(Error::BadSeek { exit_code }) => {
                        out.put("thrown", u64::from(ExitCode::Fatal.number()));
                        break exit_code;
                    }
                    Err(Error::NoMemory) => {
                        out.0 += " badalloc";
                        break arc.exit_code();
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        }
    };
    out.put("exit", u64::from(exit.number()));
    out.0
}

/// The port's answer to a `hash` request, in the oracle's words.
fn answer_hash(words: &[&str]) -> String {
    let kind = match words[1] {
        "1" => HashType::Rar14,
        "2" => HashType::Crc32,
        "3" => HashType::Blake2,
        other => panic!("hash type {other}"),
    };
    let chunk: usize = words[2].parse().expect("a chunk size");
    let mut hash = DataHash::new(kind);
    for piece in unhex(words[3]).chunks(chunk) {
        hash.update(piece);
    }
    let value = hash.result();
    let mut out = Out("hash".to_string());
    if kind == HashType::Blake2 {
        out.bytes("digest", &value.digest);
    } else {
        out.put("crc32", u64::from(value.crc32));
    }
    out.0
}

/// The port's answer to a request, in the oracle's words.
fn answer(request: &str) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    if words[0] == "test" {
        let limit = words.get(2).map(|n| n.parse().expect("a limit"));
        return answer_test(&unhex(words.get(1).copied().unwrap_or("-")), limit, "");
    }
    if words[0] == "testvol" {
        return answer_test_volumes(&words);
    }
    if words[0] == "comment" {
        return answer_comment(&words);
    }
    if words[0] == "testpw" {
        let password = String::from_utf8(unhex(words[1])).expect("a password");
        let limit = words.get(3).map(|n| n.parse().expect("a limit"));
        return answer_test(&unhex(words[2]), limit, &password);
    }
    if words[0] == "hash" {
        return answer_hash(&words);
    }
    let (password, words) = if words[0] == "listpw" {
        let password = String::from_utf8(unhex(words[1])).expect("a password");
        (password, &words[1..])
    } else {
        assert_eq!(words[0], "list", "{request:.80}");
        (String::new(), &words[..])
    };
    let enable_broken = words[1] == "1";
    let data = unhex(words.get(2).copied().unwrap_or("-"));
    let mut out = Out("list".to_string());
    let exit = match Archive::open_with_password(data.as_slice(), enable_broken, &password) {
        Err(Error::NotRar { exit_code }) => {
            // The oracle prints the state of an archive that failed
            // IsArchive; the port does not keep one, so these requests
            // compare by their first word and the exit code.
            out.0 += " notarchive";
            exit_code
        }
        Err(Error::MissingPassword { exit_code }) => {
            out.put("thrown", u64::from(ExitCode::UserBreak.number()));
            exit_code
        }
        Err(Error::BadSeek { exit_code }) => {
            out.put("thrown", u64::from(ExitCode::Fatal.number()));
            exit_code
        }
        Err(e) => panic!("{e}"),
        Ok(mut archive) => {
            out.0 += " archive";
            out.state(&archive);
            out.bytes(
                "mark",
                &archive.mark_head.mark[..archive.mark_head.head_size as usize],
            );
            loop {
                match archive.read_header() {
                    Ok(0) => {
                        out.0 += " | end";
                        out.state(&archive);
                        break archive.exit_code();
                    }
                    Ok(size) => {
                        out.0 += " |";
                        out.put("read", size as u64);
                        out.state(&archive);
                        out.header(&archive);
                        archive.seek_to_next();
                    }
                    Err(Error::MissingPassword { exit_code }) => {
                        out.put("thrown", u64::from(ExitCode::UserBreak.number()));
                        break exit_code;
                    }
                    Err(Error::BadSeek { exit_code }) => {
                        out.put("thrown", u64::from(ExitCode::Fatal.number()));
                        break exit_code;
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        }
    };
    out.put("exit", u64::from(exit.number()));
    out.0
}

/// An answer as the port can give it: the oracle prints the state of an
/// archive that failed IsArchive, which the port does not keep.
fn comparable(oracle: &str) -> String {
    if let Some(rest) = oracle.strip_prefix("list notarchive") {
        let exit = rest.rsplit(' ').next().unwrap_or_default();
        return format!("list notarchive {exit}");
    }
    oracle.to_string()
}

fn assert_same(request: &str, want: &str, context: &str) {
    let got = answer(request);
    let want = comparable(want);
    if got != want {
        // The first word that differs, and some context.
        let (g, w): (Vec<&str>, Vec<&str>) = (got.split(' ').collect(), want.split(' ').collect());
        let at = g
            .iter()
            .zip(&w)
            .position(|(a, b)| a != b)
            .unwrap_or(g.len().min(w.len()));
        let from = at.saturating_sub(8);
        panic!(
            "{context}: the port differs from UnRAR at word {at}\n port: {}\nunrar: {}",
            g[from..(at + 8).min(g.len())].join(" "),
            w[from..(at + 8).min(w.len())].join(" ")
        );
    }
}

// The oracle is compared with on Linux alone: the port reads names as UnRAR
// does on Linux, and UnRAR's macOS build decodes names another way
// (CharToWide is UtfToWide there). The recorded answers replay everywhere.
#[cfg(target_os = "linux")]
#[test]
fn libarchive_archives_list_like_unrar() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let archives = libarchive_archives();
    for (name, data) in &archives {
        for enable_broken in [0, 1] {
            let request = format!("list {enable_broken} {}", hex(data));
            let want = oracle.ask(&request);
            assert_same(&request, &want, &format!("{name}, broken {enable_broken}"));
        }
    }
    eprintln!("{} archives compared", archives.len());
}

#[cfg(target_os = "linux")]
#[test]
fn damaged_archives_list_like_unrar() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    // More with HIVEPACK_RAR_DAMAGED, and others with HIVEPACK_RAR_SEED,
    // for longer runs by hand.
    let seed = std::env::var("HIVEPACK_RAR_SEED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0x4152_0001);
    let mut rng = Rng(seed);
    let count: usize = std::env::var("HIVEPACK_RAR_DAMAGED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(20);
    let mut compared = 0;
    for (name, data) in &libarchive_archives() {
        // The large ones take the oracle's line too long for no gain.
        if data.len() > 64 << 10 {
            continue;
        }
        for i in 0..count {
            // Damage near the headers more often: the first kilobyte.
            let damaged = if i % 2 == 0 {
                let head = data.len().min(1024);
                let mut d = damage(&mut rng, &data[..head]);
                d.extend_from_slice(&data[head..]);
                d
            } else {
                damage(&mut rng, data)
            };
            let request = format!("list {} {}", i % 2, hex(&damaged));
            let want = oracle.ask(&request);
            assert_same(&request, &want, &format!("{name}, damaged {i}"));
            compared += 1;
        }
    }
    eprintln!("{compared} damaged archives compared");
}

#[cfg(target_os = "linux")]
#[test]
fn libarchive_archives_test_like_unrar() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let archives = libarchive_archives();
    let (mut with_data, mut later) = (0, 0);
    for (name, data) in &archives {
        let request = format!("test {}", hex(data));
        let want = oracle.ask(&request);
        assert_same(&request, &want, name);
        with_data += want
            .split(' ')
            .filter(|w| w.starts_with("data=") && *w != "data=0")
            .count();
        later += want.split(' ').filter(|w| *w == "later").count();
    }
    eprintln!(
        "{} archives tested: {with_data} entries with data, {later} left for later",
        archives.len()
    );
    // That the comparison compares something.
    assert!(
        archives.is_empty() || with_data >= 30,
        "only {with_data} entries with data"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn damaged_archives_test_like_unrar() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let seed = std::env::var("HIVEPACK_RAR_SEED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0x4152_0003);
    let mut rng = Rng(seed);
    let count: usize = std::env::var("HIVEPACK_RAR_DAMAGED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(20);
    let (mut compared, mut failed_hash) = (0, 0);
    for (name, data) in &libarchive_archives() {
        if data.len() > 64 << 10 {
            continue;
        }
        for i in 0..count {
            let damaged = if i % 2 == 0 {
                let head = data.len().min(1024);
                let mut d = damage(&mut rng, &data[..head]);
                d.extend_from_slice(&data[head..]);
                d
            } else {
                damage(&mut rng, data)
            };
            let request = format!("test {}", hex(&damaged));
            let want = oracle.ask(&request);
            assert_same(&request, &want, &format!("{name}, damaged {i}"));
            compared += 1;
            failed_hash += usize::from(want.contains(" code=3"));
        }
    }
    eprintln!("{compared} damaged archives tested, {failed_hash} with a bad hash or header");
}

// Damage with the headers' CRCs made right again: what random damage to a header
// would not get past. So solid flags, dictionaries, algorithms and sizes vary.
#[cfg(target_os = "linux")]
#[test]
fn damaged_headers_test_like_unrar() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let seed = std::env::var("HIVEPACK_RAR_SEED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0x4152_0004);
    let mut rng = Rng(seed);
    let count: usize = std::env::var("HIVEPACK_RAR_DAMAGED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(20);
    let mut compared = 0;
    for (name, data) in &libarchive_archives() {
        if data.len() > 64 << 10 {
            continue;
        }
        for i in 0..count {
            let head = data.len().min(512);
            let mut damaged = damage(&mut rng, &data[..head]);
            damaged.extend_from_slice(&data[head..]);
            support::patch::fix_header_crcs(&mut damaged);
            let request = format!("test {}", hex(&damaged));
            let want = oracle.ask(&request);
            assert_same(&request, &want, &format!("{name}, damaged {i}"));
            compared += 1;
        }
    }
    eprintln!("{compared} archives with damaged headers tested");
}

// Bytes as compressed data, and what the `rar_unpack` target found.
#[cfg(target_os = "linux")]
#[test]
fn packed_data_unpacks_like_unrar() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let seed = std::env::var("HIVEPACK_RAR_SEED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0x4152_0005);
    let mut rng = Rng(seed);
    let count: usize = std::env::var("HIVEPACK_RAR_DAMAGED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(20);
    for i in 0..count * 10 {
        let size = rng.below(4096) as usize;
        let mut input = vec![0; size];
        for byte in &mut input {
            *byte = rng.next() as u8;
        }
        let request = format!("test {}", hex(&support::patch::with_packed_data(&input)));
        let want = oracle.ask(&request);
        assert_same(&request, &want, &format!("random input {i}"));
    }
    for (input, _) in recorded_unpack() {
        let request = unpack_request(&input);
        let want = oracle.ask(&request);
        assert_same(&request, &want, &format!("recorded input {input:.40}"));
    }
    // PPMd over random bytes goes on for as long as there are bytes, and over
    // zeros it takes what it finds most likely, which makes long contexts. So
    // the model fills its memory and starts again, which is why the first
    // streams are long.
    let streams = (count / 4).max(3);
    for i in 0..streams {
        let size = if i < 2 {
            1 << 20
        } else {
            1 << (14 + rng.below(3))
        };
        let order = rng.below(32) as u8;
        // A PPMd block that resets, with the smallest memory: the byte says
        // so with its high bits, and the rest of its bits are the order.
        let mut input = vec![16, 0, 0, 0x80 | 0x20 | order, rng.below(2) as u8];
        while input.len() < size {
            let run = 256 + rng.below(4096) as usize;
            if rng.below(2) == 0 {
                input.resize(input.len() + run, 0);
            } else {
                for _ in 0..run {
                    input.push(rng.next() as u8);
                }
            }
        }
        let request = format!("test {}", hex(&support::patch::with_packed_data(&input)));
        let want = oracle.ask(&request);
        assert_same(&request, &want, &format!("PPMd stream {i}"));
    }
    let Some(folder) = std::env::var_os("HIVEPACK_RAR_UNPACK_CORPUS") else {
        return;
    };
    let mut compared = 0;
    for entry in std::fs::read_dir(folder).expect("the folder") {
        let path = entry.expect("an entry").path();
        let input = std::fs::read(&path).expect("an input");
        let request = format!("test {}", hex(&support::patch::with_packed_data(&input)));
        let want = oracle.ask(&request);
        assert_same(&request, &want, &path.display().to_string());
        compared += 1;
    }
    eprintln!("{compared} inputs compared");
}

// The same for RAR 1.5 and 2.x, which go on from each other, and into RAR 3.
#[cfg(target_os = "linux")]
#[test]
fn old_packed_data_unpacks_like_unrar() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let seed = std::env::var("HIVEPACK_RAR_SEED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0x4152_0006);
    let mut rng = Rng(seed);
    let count: usize = std::env::var("HIVEPACK_RAR_DAMAGED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(20);
    for i in 0..count * 10 {
        let size = rng.below(4096) as usize;
        let mut input = vec![0; size];
        for byte in &mut input {
            *byte = rng.next() as u8;
        }
        let request = old_unpack_request(&hex(&input));
        let want = oracle.ask(&request);
        assert_same(&request, &want, &format!("random input {i}"));
    }
    for (input, _) in recorded_old_unpack() {
        let request = old_unpack_request(&input);
        let want = oracle.ask(&request);
        assert_same(&request, &want, &format!("recorded input {input:.40}"));
    }
    let Some(folder) = std::env::var_os("HIVEPACK_RAR_OLD_UNPACK_CORPUS") else {
        return;
    };
    let mut compared = 0;
    for entry in std::fs::read_dir(folder).expect("the folder") {
        let path = entry.expect("an entry").path();
        let input = std::fs::read(&path).expect("an input");
        let request = old_unpack_request(&hex(&input));
        let want = oracle.ask(&request);
        assert_same(&request, &want, &path.display().to_string());
        compared += 1;
    }
    eprintln!("{compared} inputs compared");
}

// Archives that RAR itself made, of every age, and what other projects keep as
// tests for reading broken ones, as they are and damaged.
#[cfg(target_os = "linux")]
#[test]
fn other_projects_archives_test_like_unrar() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let seed = std::env::var("HIVEPACK_RAR_SEED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0x4152_0007);
    let mut rng = Rng(seed);
    let count: usize = std::env::var("HIVEPACK_RAR_DAMAGED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(2);
    let archives = support::other_projects_archives();
    let (mut with_data, mut encrypted, mut decrypted) = (0, 0, 0);
    for (name, data) in &archives {
        for request in [
            format!("list 0 {}", hex(data)),
            format!("list 1 {}", hex(data)),
            format!("test {}", hex(data)),
            // The dictionary of a RAR 7 archive may be over the default limit.
            format!("test {} {}", hex(data), 8u64 << 30),
        ] {
            let want = oracle.ask(&request);
            assert_same(&request, &want, name);
            with_data += want
                .split(' ')
                .filter(|w| w.starts_with("data=") && *w != "data=0")
                .count();
        }
        // With the passwords those projects use, and one that is wrong.
        let plain = oracle.ask(&format!("test {}", hex(data)));
        if !plain.contains("nopassword=1") && !plain.contains("thrown=") {
            continue;
        }
        encrypted += 1;
        for password in [
            "junrar",
            "password",
            "password222",
            "unrar",
            "пароль密码ü",
            "wrong",
        ] {
            let pw = hex(password.as_bytes());
            for request in [
                format!("listpw {pw} 1 {}", hex(data)),
                format!("testpw {pw} {}", hex(data)),
            ] {
                let want = oracle.ask(&request);
                assert_same(&request, &want, &format!("{name}, password {password}"));
                if request.starts_with("testpw") {
                    let good = want
                        .split(" | ")
                        .filter(|e| e.contains(" data=") && !e.contains(" data=0 "))
                        .filter(|e| e.contains("baddata=0"))
                        .count();
                    decrypted += good;
                }
            }
        }
        if data.len() > 64 << 10 {
            continue;
        }
        for i in 0..count {
            let mut damaged = damage(&mut rng, data);
            if i % 2 == 1 {
                support::patch::fix_header_crcs(&mut damaged);
            }
            let request = format!("test {}", hex(&damaged));
            let want = oracle.ask(&request);
            assert_same(&request, &want, &format!("{name}, damaged {i}"));
        }
    }
    eprintln!(
        "{} archives: {with_data} entries with data; {encrypted} encrypted, {decrypted} entries read",
        archives.len()
    );
    assert!(
        archives.is_empty() || with_data >= 200,
        "only {with_data} entries with data"
    );
    // Encrypted entries that a password really read, of each age.
    assert!(
        archives.is_empty() || decrypted >= 20,
        "only {decrypted} encrypted entries read"
    );
}

/// The volumes each archive goes with: those of its folder with the same name
/// up to the first dot, from it on, in the order UnRAR will ask for them.
fn volume_sets() -> Vec<Vec<(String, Vec<u8>)>> {
    let mut archives = support::other_projects_archives();
    archives.extend(
        libarchive_archives()
            .into_iter()
            .map(|(name, data)| (format!("libarchive/{name}"), data)),
    );
    let split = |name: &str| -> (String, String) {
        let (folder, file) = name.rsplit_once('/').unwrap_or(("", name));
        (folder.to_string(), file.to_string())
    };
    let mut sets = Vec::new();
    for (name, data) in &archives {
        if !matches!(Archive::open(data.as_slice(), true), Ok(arc) if arc.volume) {
            continue;
        }
        let (folder, file) = split(name);
        let stem = file.split('.').next().unwrap_or_default().to_string();
        let mut set = vec![(file.clone(), data.clone())];
        for (other, other_data) in &archives {
            let (other_folder, other_file) = split(other);
            if other_folder == folder
                && other_file != file
                && other_file.split('.').next() == Some(&stem)
            {
                set.push((other_file, other_data.clone()));
            }
        }
        sets.push(set);
    }
    sets
}

fn volumes_request(password: Option<&str>, set: &[(String, Vec<u8>)]) -> String {
    let mut request = format!(
        "testvol {} 0",
        password.map_or("-".to_string(), |p| hex(p.as_bytes()))
    );
    for (name, data) in set {
        let _ = write!(request, " {name} {}", hex(data));
    }
    request
}

// Volumes whole, from any of them, with one missing, and with one damaged.
#[cfg(target_os = "linux")]
#[test]
fn volumes_test_like_unrar() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let seed = std::env::var("HIVEPACK_RAR_SEED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0x4152_000a);
    let mut rng = Rng(seed);
    let count: usize = std::env::var("HIVEPACK_RAR_DAMAGED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(2);
    let sets = volume_sets();
    let (mut compared, mut merged) = (0, 0);
    for set in &sets {
        for password in [None, Some("password"), Some("junrar")] {
            let request = volumes_request(password, set);
            let want = oracle.ask(&request);
            assert_same(&request, &want, &set[0].0);
            compared += 1;
            if !want.contains("novolume=1") && !want.contains("code=6") {
                merged += 1;
            }
            // The last volume of the set missing.
            if set.len() > 1 {
                let request = volumes_request(password, &set[..set.len() - 1]);
                let want = oracle.ask(&request);
                assert_same(&request, &want, &format!("{}, one missing", set[0].0));
                compared += 1;
            }
            for i in 0..count {
                let mut damaged = set.clone();
                let which = rng.below(set.len() as u64) as usize;
                let copy = damage(&mut rng, &damaged[which].1);
                damaged[which].1 = copy;
                if i % 2 == 1 {
                    support::patch::fix_header_crcs(&mut damaged[which].1);
                }
                let request = volumes_request(password, &damaged);
                let want = oracle.ask(&request);
                assert_same(&request, &want, &format!("{}, damaged {i}", set[0].0));
                compared += 1;
            }
        }
    }
    if let Some(folder) = std::env::var_os("HIVEPACK_RAR_VOLUMES_CORPUS") {
        for entry in std::fs::read_dir(folder).expect("the folder") {
            let input = std::fs::read(entry.expect("an entry").path()).expect("an input");
            for request in volume_requests(&hex(&input)) {
                let want = oracle.ask(&request);
                assert_same(&request, &want, &format!("input {:.40}", hex(&input)));
                compared += 1;
            }
        }
    }
    eprintln!("{} sets, {compared} compared, {merged} went on", sets.len());
    assert!(
        sets.is_empty() || merged > 10,
        "only {merged} sets went through"
    );
}

// Comments of every kind of archive, as they are and damaged.
#[cfg(target_os = "linux")]
#[test]
fn comments_are_unrars() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let seed = std::env::var("HIVEPACK_RAR_SEED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0x4152_000b);
    let mut rng = Rng(seed);
    let count: usize = std::env::var("HIVEPACK_RAR_DAMAGED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(5);
    let mut archives = support::other_projects_archives();
    archives.extend(libarchive_archives());
    let (mut compared, mut comments) = (0, 0);
    for (name, data) in &archives {
        for password in ["-", "password", "junrar"] {
            let pw = if password == "-" {
                "-".to_string()
            } else {
                hex(password.as_bytes())
            };
            let request = format!("comment {pw} {}", hex(data));
            let want = oracle.ask(&request);
            assert_same(&request, &want, &format!("{name}, password {password}"));
            compared += 1;
            if want.contains(" comment=") {
                comments += 1;
            } else if data.len() > 64 << 10 || !want.contains(" none") {
                continue;
            }
            if data.len() > 64 << 10 {
                continue;
            }
            for i in 0..count {
                let mut damaged = damage(&mut rng, data);
                if i % 2 == 1 {
                    support::patch::fix_header_crcs(&mut damaged);
                }
                let request = format!("comment {pw} {}", hex(&damaged));
                let want = oracle.ask(&request);
                assert_same(&request, &want, &format!("{name}, damaged {i}"));
                compared += 1;
            }
        }
    }
    eprintln!("{compared} compared, {comments} comments read");
    assert!(
        archives.is_empty() || comments >= 15,
        "only {comments} comments read"
    );
}

// Encrypted archives damaged, with their password, and what the `rar_password`
// target found. Each kind of encryption keeps its own password.
#[cfg(target_os = "linux")]
#[test]
fn encrypted_archives_damaged_test_like_unrar() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let seed = std::env::var("HIVEPACK_RAR_SEED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0x4152_0009);
    let mut rng = Rng(seed);
    let count: usize = std::env::var("HIVEPACK_RAR_DAMAGED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(3);
    let mut compared = 0;
    for (name, data) in support::other_projects_archives() {
        let plain = oracle.ask(&format!("test {}", hex(&data)));
        if data.len() > 64 << 10 || !plain.contains("nopassword=1") && !plain.contains("thrown=") {
            continue;
        }
        for password in ["junrar", "password"] {
            let pw = hex(password.as_bytes());
            for i in 0..count {
                let mut damaged = damage(&mut rng, &data);
                if i % 2 == 1 {
                    support::patch::fix_header_crcs(&mut damaged);
                }
                let request = format!("testpw {pw} {}", hex(&damaged));
                let want = oracle.ask(&request);
                assert_same(&request, &want, &format!("{name}, damaged {i}"));
                compared += 1;
            }
        }
    }
    for (input, _) in recorded_volumes() {
        for request in volume_requests(&input) {
            let want = oracle.ask(&request);
            assert_same(&request, &want, &format!("recorded input {input:.40}"));
        }
    }
    for (input, _) in recorded_password() {
        let request = password_request(&input);
        let want = oracle.ask(&request);
        assert_same(&request, &want, &format!("recorded input {input:.40}"));
    }
    if let Some(folder) = std::env::var_os("HIVEPACK_RAR_PASSWORD_CORPUS") {
        for entry in std::fs::read_dir(folder).expect("the folder") {
            let input = std::fs::read(entry.expect("an entry").path()).expect("an input");
            let request = password_request(&hex(&input));
            let want = oracle.ask(&request);
            assert_same(&request, &want, &format!("input {:.40}", hex(&input)));
            compared += 1;
        }
    }
    eprintln!("{compared} encrypted archives compared");
}

// QuickOpen records, whose copies of headers need not say what the headers say:
// three ways of reading what the `rar_quick_open` target finds.
fn quick_open_requests(input: &[u8]) -> [String; 4] {
    let archive = hex(&support::patch::with_quick_open(input));
    [
        format!("list 1 {archive}"),
        format!("test {archive}"),
        format!("testpw {} {archive}", hex(FUZZ_PASSWORD.as_bytes())),
        format!("comment - {archive}"),
    ]
}

#[cfg(target_os = "linux")]
#[test]
fn quick_open_records_read_like_unrar() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let seed = std::env::var("HIVEPACK_RAR_SEED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0x4152_000a);
    let mut rng = Rng(seed);
    let count: usize = std::env::var("HIVEPACK_RAR_DAMAGED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(40);
    let compare = |oracle: &mut Oracle, input: &[u8], context: &str| {
        for request in quick_open_requests(input) {
            let want = oracle.ask(&request);
            assert_same(&request, &want, context);
        }
    };
    // What random bytes seldom come to: the file's header in another size, by
    // way of a record that is not one, a second main header, a block of a size
    // that does not end, and around the end of the record's buffer.
    let other = [1 | 5 << 3, 42];
    let mut cases: Vec<Vec<u8>> = vec![
        [&[3][..], &other].concat(),
        [&[4][..], &other].concat(),
        [&[0, 5 | 1 << 3][..], &other].concat(),
        [&[0, 5][..], &other].concat(),
        vec![0, 3 | 1 << 3, 0xfe, 7],
        vec![0, 3 | 1 << 3, 0xff, 7],
        vec![0, 3, 0xfe, 7, 1 | 5 << 3, 42],
        vec![0, 3, 0xff, 7, 1 | 5 << 3, 42],
    ];
    for (low, high) in [(0xfd, 0), (0xfe, 0), (0xff, 0), (0, 1)] {
        for filler in 0..40 {
            // Up to where the next block starts past the buffer's last 256
            // bytes, or crosses its end, then the file's header in another size.
            let mut input = vec![0, 3, low, high];
            for _ in 0..filler {
                input.extend_from_slice(&[3, 0, 0]);
            }
            input.extend_from_slice(&other);
            cases.push(input);
        }
    }
    for (i, input) in cases.iter().enumerate() {
        compare(&mut oracle, input, &format!("case {i}"));
    }
    for i in 0..count {
        let mut input = vec![0; rng.below(256) as usize];
        for byte in &mut input {
            *byte = rng.next() as u8;
        }
        compare(&mut oracle, &input, &format!("random input {i}"));
    }
    for (input, _) in recorded_quick_open() {
        compare(
            &mut oracle,
            &unhex(&input),
            &format!("recorded input {input:.40}"),
        );
    }
    let Some(folder) = std::env::var_os("HIVEPACK_RAR_QUICK_OPEN_CORPUS") else {
        return;
    };
    let mut compared = 0;
    for entry in std::fs::read_dir(folder).expect("the folder") {
        let path = entry.expect("an entry").path();
        let input = std::fs::read(&path).expect("an input");
        compare(&mut oracle, &input, &path.display().to_string());
        compared += 1;
    }
    eprintln!("{compared} inputs compared");
}

fn recorded_quick_open_path() -> std::path::PathBuf {
    support::repository().join("testdata/oracle/rar-quick-open.txt")
}

/// The same from the `rar_quick_open` target.
fn recorded_quick_open() -> Vec<(String, String)> {
    let path = recorded_quick_open_path();
    if path.exists() {
        recorded_inputs(&path)
    } else {
        Vec::new()
    }
}

// The copies are what is read: a copy of the file's header with another size
// and name stands for it, in UnRAR and here. If this fails the inputs above say
// nothing of QuickOpen, as records that are not found compare the same.
#[test]
fn quick_open_copies_stand_for_headers() {
    // Block 1: the file's header, its name cut to 5 bytes and its size 42.
    let input = [0, 1 | 5 << 3, 42];
    let got = answer(&format!(
        "list 1 {}",
        hex(&support::patch::with_quick_open(&input))
    ));
    assert!(got.contains(" name=68.65.6c.6c.6f "), "{got:.2000}");
    assert!(got.contains(" unpsize=2a "), "{got:.2000}");
}

#[test]
fn port_reads_quick_open_as_recorded() {
    for (input, want) in recorded_quick_open() {
        let got: Vec<String> = quick_open_requests(&unhex(&input))
            .iter()
            .map(|request| support::recorded_form(&answer(request)))
            .collect();
        assert_eq!(got.join(" # "), want, "{input:.300}");
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "rewrites testdata/oracle/rar-quick-open.txt from the oracle"]
fn record_quick_open_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut text = String::from(
        "# Answers from UnRAR 7.3.2 (tools/rar-oracle) for inputs the rar_quick_open fuzz target found, as support::patch::with_quick_open makes archives of them, replayed by crates/rar/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test rar_oracle record_quick_open_answers -- --ignored\n",
    );
    for (input, _) in recorded_quick_open() {
        let replies: Vec<String> = quick_open_requests(&unhex(&input))
            .iter()
            .map(|request| support::recorded_form(&oracle.ask(request)))
            .collect();
        let _ = writeln!(text, "{input}\t{}", replies.join(" # "));
    }
    std::fs::write(recorded_quick_open_path(), text).expect("written");
}

// A dictionary too large for the limit, on archives that hold what they say:
// random damage rarely gets to a size past the default 4 GiB.
#[cfg(target_os = "linux")]
#[test]
fn dictionary_limits_are_unrars() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut stopped = 0;
    for (name, data) in &libarchive_archives() {
        if data.len() > 64 << 10 {
            continue;
        }
        for limit in [0x1000, 0x1_ffff, 0x2_0000, 0x40_0000] {
            let request = format!("test {} {limit}", hex(data));
            let want = oracle.ask(&request);
            assert_same(&request, &want, &format!("{name}, limit {limit:#x}"));
            stopped += usize::from(want.contains(" code=2 ") || want.contains(" exit=2"));
        }
    }
    let archives = libarchive_archives();
    assert!(
        archives.is_empty() || stopped > 10,
        "only {stopped} stopped"
    );
}

/// Bytes that are the same run to run.
fn hash_input(rng: &mut Rng, size: usize) -> Vec<u8> {
    (0..size).map(|_| rng.next() as u8).collect()
}

/// A `hash` request of each kind, for sizes around the block sizes.
fn hash_requests(rng: &mut Rng, sizes: &[usize]) -> Vec<String> {
    let mut requests = Vec::new();
    for &size in sizes {
        let data = hash_input(rng, size);
        for kind in [1, 2, 3] {
            let chunk = rng.pick(&[1, 7, 64, 512, 4096, 1 << 20]);
            requests.push(format!("hash {kind} {chunk} {}", hex(&data)));
        }
    }
    requests
}

#[cfg(target_os = "linux")]
#[test]
fn hashes_are_unrars() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x4152_0005);
    let sizes = [
        0,
        1,
        2,
        63,
        64,
        65,
        511,
        512,
        513,
        4096,
        0x8000,
        0x8001,
        200_000,
        1 << 20,
    ];
    for request in hash_requests(&mut rng, &sizes) {
        let want = oracle.ask(&request);
        assert_same(&request, &want, &format!("{:.20}", request));
    }
}

fn recorded_path() -> std::path::PathBuf {
    support::repository().join("testdata/oracle/rar-list.txt")
}

fn recorded_test_path() -> std::path::PathBuf {
    support::repository().join("testdata/oracle/rar-test.txt")
}

/// The archives whose testing is recorded: those of 64 KB or less as they
/// are, for the stored ones with something to hash, and the same requests
/// as `recorded_requests`' for the damaged ones.
fn recorded_test_requests() -> Vec<String> {
    let mut rng = Rng(0x4152_0004);
    let mut requests = Vec::new();
    for (name, data) in libarchive_archives() {
        if data.len() <= 2048 || name.contains("stored") || name.contains("blake2") {
            requests.push(format!("test {}", hex(&data)));
        }
        if data.len() <= 2048 {
            for _ in 0..3 {
                requests.push(format!("test {}", hex(&damage(&mut rng, &data))));
            }
        }
    }
    requests.extend(hash_requests(&mut rng, &[0, 1, 63, 64, 65, 512, 513, 4096]));
    requests
}

/// The requests whose answers are recorded: libarchive's archives of 2 KB
/// or less, as they are both ways and six times damaged, so that they
/// replay where neither the oracle nor the archives are, as on Windows and
/// in the cross-compiled jobs.
fn recorded_requests() -> Vec<String> {
    let mut rng = Rng(0x4152_0002);
    let mut requests = Vec::new();
    for (_, data) in libarchive_archives() {
        if data.len() > 2048 {
            continue;
        }
        for enable_broken in [0, 1] {
            requests.push(format!("list {enable_broken} {}", hex(&data)));
        }
        for i in 0..6 {
            let damaged = damage(&mut rng, &data);
            requests.push(format!("list {} {}", i % 2, hex(&damaged)));
        }
    }
    requests
}

#[test]
fn port_lists_as_recorded() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/rar-list.txt");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(
            support::recorded_form(&answer(request)),
            want,
            "{request:.300}"
        );
        checked += 1;
    }
    assert!(checked > 500, "only {checked} recorded answers");
}

#[test]
fn port_tests_as_recorded() {
    let text = std::fs::read_to_string(recorded_test_path()).expect("testdata/oracle/rar-test.txt");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        let got = answer(request);
        // UnRAR's 32-bit builds refuse a dictionary over 2 GiB, which the
        // answers were not recorded on.
        if usize::BITS == 32 && got.contains(" badalloc") {
            continue;
        }
        assert_eq!(support::recorded_form(&got), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked > 200, "only {checked} recorded answers");
}

fn recorded_unpack_path() -> std::path::PathBuf {
    support::repository().join("testdata/oracle/rar-unpack.txt")
}

fn unpack_request(input: &str) -> String {
    format!(
        "test {}",
        hex(&support::patch::with_packed_data(&unhex(input)))
    )
}

fn recorded_old_unpack_path() -> std::path::PathBuf {
    support::repository().join("testdata/oracle/rar-unpack-old.txt")
}

fn old_unpack_request(input: &str) -> String {
    format!(
        "test {}",
        hex(&support::patch::with_old_packed_data(&unhex(input)))
    )
}

/// What the `rar_unpack` target found, which damage does not get to: the
/// inputs, and UnRAR's answers for where the oracle is not.
fn recorded_unpack() -> Vec<(String, String)> {
    recorded_inputs(&recorded_unpack_path())
}

/// The same from the `rar_unpack_old` target.
fn recorded_old_unpack() -> Vec<(String, String)> {
    recorded_inputs(&recorded_old_unpack_path())
}

fn recorded_password_path() -> std::path::PathBuf {
    support::repository().join("testdata/oracle/rar-password.txt")
}

/// The password the `rar_password` target goes by.
const FUZZ_PASSWORD: &str = "password";

fn password_request(input: &str) -> String {
    format!("testpw {} {input}", hex(FUZZ_PASSWORD.as_bytes()))
}

/// The same from the `rar_password` target.
fn recorded_password() -> Vec<(String, String)> {
    recorded_inputs(&recorded_password_path())
}

fn recorded_volumes_path() -> std::path::PathBuf {
    support::repository().join("testdata/oracle/rar-volumes.txt")
}

/// The requests a `rar_volumes` input stands for: testing and its comment.
fn volume_requests(input: &str) -> [String; 2] {
    let input = unhex(input);
    let (at, flags, rest) = match input.as_slice() {
        [a, b, c, rest @ ..] => (usize::from(*a) | usize::from(*b) << 8, *c, rest),
        _ => (0, 0, &[][..]),
    };
    let (first, second) = rest.split_at(at.min(rest.len()));
    let (mut first, mut second) = (first.to_vec(), second.to_vec());
    if flags & 1 != 0 {
        support::patch::fix_header_crcs(&mut first);
        support::patch::fix_header_crcs(&mut second);
    }
    let pw = hex(FUZZ_PASSWORD.as_bytes());
    // Files of nothing are written all the same.
    [
        volumes_request(
            Some(FUZZ_PASSWORD),
            &[
                ("a.part1.rar".to_string(), first.clone()),
                ("a.part2.rar".to_string(), second),
            ],
        ),
        format!("comment {pw} {}", hex(&first)),
    ]
}

/// The same from the `rar_volumes` target.
fn recorded_volumes() -> Vec<(String, String)> {
    recorded_inputs(&recorded_volumes_path())
}

fn recorded_inputs(path: &std::path::Path) -> Vec<(String, String)> {
    let text = std::fs::read_to_string(path).expect("the recorded inputs");
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|line| {
            let (input, want) = line.split_once('\t').expect("input, tab, answer");
            (input.to_string(), want.to_string())
        })
        .collect()
}

#[test]
fn port_unpacks_as_recorded() {
    let recorded = recorded_unpack();
    assert!(recorded.len() > 50, "only {} inputs", recorded.len());
    for (input, want) in recorded {
        let request = unpack_request(&input);
        let got = answer(&request);
        // As in `port_tests_as_recorded`.
        if usize::BITS == 32 && got.contains(" badalloc") {
            continue;
        }
        assert_eq!(support::recorded_form(&got), want, "{input:.300}");
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "rewrites testdata/oracle/rar-unpack.txt from the oracle"]
fn record_unpack_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut text = String::from(
        "# Answers from UnRAR 7.3.2 (tools/rar-oracle) for inputs the rar_unpack fuzz target found, replayed by crates/rar/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test rar_oracle record_unpack_answers -- --ignored\n",
    );
    for (input, _) in recorded_unpack() {
        let reply = oracle.ask(&unpack_request(&input));
        let _ = writeln!(text, "{input}\t{}", support::recorded_form(&reply));
    }
    std::fs::write(recorded_unpack_path(), text).expect("written");
}

#[test]
fn port_unpacks_old_as_recorded() {
    let recorded = recorded_old_unpack();
    assert!(recorded.len() > 50, "only {} inputs", recorded.len());
    for (input, want) in recorded {
        let got = answer(&old_unpack_request(&input));
        assert_eq!(support::recorded_form(&got), want, "{input:.300}");
    }
}

#[test]
fn port_reads_encrypted_as_recorded() {
    let recorded = recorded_password();
    assert!(recorded.len() > 50, "only {} inputs", recorded.len());
    for (input, want) in recorded {
        let got = answer(&password_request(&input));
        if usize::BITS == 32 && got.contains(" badalloc") {
            continue;
        }
        assert_eq!(support::recorded_form(&got), want, "{input:.300}");
    }
}

#[test]
fn port_reads_volumes_as_recorded() {
    let recorded = recorded_volumes();
    assert!(recorded.len() > 50, "only {} inputs", recorded.len());
    for (input, want) in recorded {
        let [test, comment] = volume_requests(&input);
        let got = format!(
            "{} {}",
            support::recorded_form(&answer(&test)),
            support::recorded_form(&answer(&comment))
        );
        if usize::BITS == 32 && got.contains(" badalloc") {
            continue;
        }
        assert_eq!(got, want, "{input:.300}");
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "rewrites testdata/oracle/rar-volumes.txt from the oracle"]
fn record_volumes_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut text = String::from(
        "# Answers from UnRAR 7.3.2 (tools/rar-oracle) for inputs the rar_volumes fuzz target found, replayed by crates/rar/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test rar_oracle record_volumes_answers -- --ignored\n",
    );
    for (input, _) in recorded_volumes() {
        let [test, comment] = volume_requests(&input);
        let _ = writeln!(
            text,
            "{input}\t{} {}",
            support::recorded_form(&oracle.ask(&test)),
            support::recorded_form(&oracle.ask(&comment))
        );
    }
    std::fs::write(recorded_volumes_path(), text).expect("written");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "rewrites testdata/oracle/rar-password.txt from the oracle"]
fn record_password_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut text = String::from(
        "# Answers from UnRAR 7.3.2 (tools/rar-oracle) for inputs the rar_password fuzz target found, as archives with the password \"password\", replayed by crates/rar/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test rar_oracle record_password_answers -- --ignored\n",
    );
    for (input, _) in recorded_password() {
        let reply = oracle.ask(&password_request(&input));
        let _ = writeln!(text, "{input}\t{}", support::recorded_form(&reply));
    }
    std::fs::write(recorded_password_path(), text).expect("written");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "rewrites testdata/oracle/rar-unpack-old.txt from the oracle"]
fn record_old_unpack_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut text = String::from(
        "# Answers from UnRAR 7.3.2 (tools/rar-oracle) for inputs the rar_unpack_old fuzz target found, replayed by crates/rar/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test rar_oracle record_old_unpack_answers -- --ignored\n",
    );
    for (input, _) in recorded_old_unpack() {
        let reply = oracle.ask(&old_unpack_request(&input));
        let _ = writeln!(text, "{input}\t{}", support::recorded_form(&reply));
    }
    std::fs::write(recorded_old_unpack_path(), text).expect("written");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "rewrites testdata/oracle/rar-test.txt from the oracle"]
fn record_test_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut text = String::from(
        "# Answers from UnRAR 7.3.2 (tools/rar-oracle), replayed by crates/rar/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test rar_oracle record_test_answers -- --ignored\n",
    );
    for request in recorded_test_requests() {
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{}", support::recorded_form(&reply));
    }
    std::fs::write(recorded_test_path(), text).expect("written");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "rewrites testdata/oracle/rar-list.txt from the oracle"]
fn record_list_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut text = String::from(
        "# Answers from UnRAR 7.3.2 (tools/rar-oracle), replayed by crates/rar/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test rar_oracle record_list_answers -- --ignored\n",
    );
    for request in recorded_requests() {
        let reply = comparable(&oracle.ask(&request));
        let _ = writeln!(text, "{request}\t{}", support::recorded_form(&reply));
    }
    std::fs::write(recorded_path(), text).expect("written");
}

/// The inputs in the folder HIVEPACK_RAR_CORPUS, such as a fuzzer's
/// corpus, their first byte choosing whether a broken main header is read
/// past as the `rar_headers` target's does: for runs by hand.
#[cfg(target_os = "linux")]
#[test]
fn corpus_lists_like_unrar() {
    let Some(folder) = std::env::var_os("HIVEPACK_RAR_CORPUS") else {
        return;
    };
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut compared = 0;
    for entry in std::fs::read_dir(folder).expect("the folder") {
        let path = entry.expect("an entry").path();
        let data = std::fs::read(&path).expect("an input");
        let Some((&choice, archive)) = data.split_first() else {
            continue;
        };
        for request in [
            format!("list {} {}", choice & 1, hex(archive)),
            format!("test {}", hex(archive)),
        ] {
            let want = oracle.ask(&request);
            assert_same(&request, &want, &path.display().to_string());
        }
        compared += 1;
    }
    eprintln!("{compared} inputs compared");
}
