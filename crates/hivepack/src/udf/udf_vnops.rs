//! Port of NetBSD's `udf_vnops.c`, for reading: directories as
//! `udf_readdir` lists them and `udf_lookup_name_in_dir` searches them,
//! attributes as `udf_getattr` gives them, and symbolic links as
//! `udf_do_readlink` reads them.

use std::io::{Read, Seek};

use crate::udf::ecma167_udf::{
    DEV_MAJOR, DEV_MINOR, EFE_ATIME, EFE_ATTRTIME, EFE_CTIME, EFE_MTIME, FE_ATIME, FE_ATTRTIME,
    FE_GID, FE_LINK_CNT, FE_MTIME, FE_UID, FT_EXISTENCE, FT_TIMES, LongAd, UDF_DEVICESPEC_ATTR_NO,
    UDF_EXTFENTRY_SIZE, UDF_FENTRY_SIZE, UDF_FILE_CHAR_DEL, UDF_FILE_CHAR_DIR, UDF_FILE_CHAR_PAR,
    UDF_FILE_CHAR_VIS, UDF_FILETIMES_ATTR_NO, UDF_FILETIMES_FILE_CREATION, UDF_PATH_COMP_CURDIR,
    UDF_PATH_COMP_MOUNTROOT, UDF_PATH_COMP_NAME, UDF_PATH_COMP_PARENTDIR, UDF_PATH_COMP_ROOT,
    UDF_PATH_COMP_SIZE, UDF_TIMESTAMP_SIZE, rd8, rd16, rd32, rd64,
};
use crate::udf::error::{Errno, Error, Result};
use crate::udf::udf::{Device, MAXPATHLEN, PATH_MAX, UDF_SYMLINKBUFLEN, UdfMount, UdfNode, VType};
use crate::udf::udf_subr::{
    DirBlocks, Fid, Timespec, udf_extattr_search_intern, udf_getaccessmode, udf_is_osta_typ0,
    udf_read_fid_stream, udf_timestamp_to_timespec, udf_to_unix_name, vn_rdwr,
};

/// An entry of a directory: a FID that is not deleted.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DirEntry {
    /// Its name: UTF-8 from OSTA compressed Unicode, with what UNIX can
    /// not have in a name replaced (`UDFTransName`); `..` for the parent.
    pub name: Vec<u8>,
    /// Where its node is.
    pub icb: LongAd,
    /// Its file characteristics: hidden, directory, deleted, parent.
    pub file_characteristics: u8,
}

impl DirEntry {
    /// The entry of the parent directory, `..`.
    pub fn is_parent(&self) -> bool {
        self.file_characteristics & UDF_FILE_CHAR_PAR != 0
    }

    /// Marked as a directory (the node says what it is).
    pub fn is_dir(&self) -> bool {
        self.file_characteristics & UDF_FILE_CHAR_DIR != 0
    }

    /// Hidden: not listed, but for [`Options::unhide`](crate::udf::Options::unhide).
    pub fn is_hidden(&self) -> bool {
        self.file_characteristics & UDF_FILE_CHAR_VIS != 0
    }

    /// The `d_fileno` NetBSD gives it.
    pub fn ino(&self) -> u64 {
        u64::from(self.icb.lb_num) + 1
    }
}

impl From<Fid> for DirEntry {
    fn from(fid: Fid) -> DirEntry {
        DirEntry {
            name: fid.name,
            icb: fid.icb,
            file_characteristics: fid.file_char,
        }
    }
}

/// The listing of a directory, as `udf_readdir` reads it, without its `.`.
#[derive(Debug)]
pub(crate) struct DirStream {
    pub(crate) dir: UdfNode,
    pub(crate) offset: u64,
    pub(crate) blocks: DirBlocks,
    pub(crate) done: bool,
}

impl DirStream {
    pub(crate) fn new(dir: &UdfNode) -> Result<DirStream> {
        // This operation only makes sense on directory nodes.
        if dir.v_type != VType::VDIR {
            return Err(Error::new(Errno::ENOTDIR, "not a directory"));
        }
        Ok(DirStream {
            dir: dir.clone(),
            offset: 0,
            blocks: DirBlocks::default(),
            done: false,
        })
    }

    /// The next FID of the stream that is not deleted, or not listed.
    pub(crate) fn next_fid<R: Read + Seek>(
        &mut self,
        dev: &mut Device<R>,
        ump: &UdfMount,
        listed: bool,
    ) -> Option<Result<Fid>> {
        let is_osta_typ0 = udf_is_osta_typ0(ump);
        while !self.done && self.offset < self.dir.file_size() {
            // Transfer a new fid/dirent.
            let fid = match udf_read_fid_stream(
                dev,
                ump,
                &self.dir,
                &mut self.blocks,
                &mut self.offset,
                is_osta_typ0,
            ) {
                Ok(fid) => fid,
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            };

            // Skip deleted entries.
            if fid.file_char & UDF_FILE_CHAR_DEL != 0 {
                continue;
            }

            // Skip not visible files.
            if listed && fid.file_char & UDF_FILE_CHAR_VIS != 0 && !ump.unhide {
                continue;
            }
            return Some(Ok(fid));
        }
        self.done = true;
        None
    }
}

/// `udf_lookup_name_in_dir`: the entry named `name`, of all the entries
/// that are not deleted, hidden ones too; none if one is broken.
pub(crate) fn udf_lookup_name_in_dir<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &UdfMount,
    dir: &UdfNode,
    name: &[u8],
) -> Result<Option<LongAd>> {
    let mut stream = DirStream::new(dir)?;
    let mut found = None;
    while let Some(fid) = stream.next_fid(dev, ump, false) {
        let fid = fid?;
        if found.is_none() && fid.name == name {
            found = Some(fid.icb);
        }
    }
    Ok(found)
}

/// The attributes of a node, as `udf_getattr` gives them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Stat {
    /// What the node is.
    pub kind: VType,
    /// The permissions, setuid, setgid and sticky, and the file type
    /// (`S_IFMT`) its ICB tag gives: `udf_getaccessmode`. For a device
    /// without its device specification, 0.
    pub mode: u32,
    /// The links, one more for a directory (UDF does not count `.`).
    pub nlink: u32,
    /// The owner; for none recorded (-1), [`Options::anon_uid`](crate::udf::Options::anon_uid).
    pub uid: u32,
    /// The group; for none recorded (-1), [`Options::anon_gid`](crate::udf::Options::anon_gid).
    pub gid: u32,
    /// The node's number: its block, plus one.
    pub ino: u64,
    /// The length of its data; for a symbolic link, of its target.
    pub size: u64,
    /// The size of a block.
    pub blksize: u32,
    /// Last accessed.
    pub atime: Timespec,
    /// Last modified.
    pub mtime: Timespec,
    /// Its attributes last changed.
    pub ctime: Timespec,
    /// Created: from the file times extended attribute of a file entry,
    /// else its modification; that of an extended file entry.
    pub birthtime: Timespec,
    /// What it takes on the volume: its blocks.
    pub bytes: u64,
    /// For a device, its major and minor numbers.
    pub rdev: Option<(u32, u32)>,
}

/// `udf_getattr`.
pub(crate) fn udf_getattr<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &UdfMount,
    udf_node: &UdfNode,
) -> Stat {
    let dscr = udf_node.dscr();
    let time = |at: usize| {
        udf_timestamp_to_timespec(ump, dscr.get(at..at + UDF_TIMESTAMP_SIZE).unwrap_or(&[]))
    };

    // Get descriptor information.
    let nlink = u32::from(rd16(dscr, FE_LINK_CNT));
    let mut uid = rd32(dscr, FE_UID);
    let mut gid = rd32(dscr, FE_GID);
    let filesize = udf_node.file_size();
    let (blkssize, atime, mtime, attrtime, creatime, filedata);
    if udf_node.fe.is_some() {
        blkssize = rd64(dscr, 64);
        atime = time(FE_ATIME);
        mtime = time(FE_MTIME);
        attrtime = time(FE_ATTRTIME);
        filedata = UDF_FENTRY_SIZE;

        // Initial guess, then our extended attribute if present.
        let mut at = FE_MTIME;
        if let Ok((offset, _)) =
            udf_extattr_search_intern(ump, udf_node, UDF_FILETIMES_ATTR_NO, b"")
        {
            let ft_extattr = filedata + offset as usize;
            if rd32(dscr, ft_extattr + FT_EXISTENCE) & UDF_FILETIMES_FILE_CREATION != 0 {
                at = ft_extattr + FT_TIMES;
            }
        }
        creatime = time(at);
    } else {
        blkssize = rd64(dscr, 72);
        atime = time(EFE_ATIME);
        mtime = time(EFE_MTIME);
        attrtime = time(EFE_ATTRTIME);
        creatime = time(EFE_CTIME);
        filedata = UDF_EXTFENTRY_SIZE;
    }

    // Do the uid/gid translation game.
    if uid == u32::MAX {
        uid = ump.anon_uid;
    }
    if gid == u32::MAX {
        gid = ump.anon_gid;
    }

    let mut stat = Stat {
        kind: udf_node.v_type,
        mode: udf_getaccessmode(udf_node),
        nlink,
        uid,
        gid,
        ino: u64::from(udf_node.loc.lb_num) + 1,
        size: filesize,
        blksize: ump.sector_size,
        atime,
        mtime,
        ctime: attrtime,
        birthtime: creatime,
        bytes: blkssize.wrapping_mul(u64::from(ump.sector_size)),
        rdev: None,
    };

    // BUG-ALERT: UDF doesn't count '.' as an entry, so we'll have to add
    // 1 to the link count if its a directory we're requested attributes
    // of.
    if stat.kind == VType::VDIR {
        stat.nlink += 1;
    }

    // BUG-ALERT: Posix requires the va_size to be pathlength for symbolic
    // links.
    if stat.kind == VType::VLNK
        && let Ok(target) = udf_do_readlink(dev, ump, udf_node)
    {
        stat.size = target.len() as u64;
    }

    if stat.kind == VType::VBLK || stat.kind == VType::VCHR {
        match udf_extattr_search_intern(ump, udf_node, UDF_DEVICESPEC_ATTR_NO, b"") {
            // If error, deny access.
            Err(_) => stat.mode = 0,
            Ok((offset, _)) => {
                // NetBSD adds the offset to the attribute's pointer, which
                // moves it by as many attributes; here by bytes.
                let devattr = filedata + offset as usize;
                stat.rdev = Some((
                    rd32(dscr, devattr + DEV_MAJOR),
                    rd32(dscr, devattr + DEV_MINOR),
                ));
            }
        }
    }

    stat
}

/// `udf_do_readlink`: the target of a symbolic link, from its path
/// components.
pub(crate) fn udf_do_readlink<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &UdfMount,
    udf_node: &UdfNode,
) -> Result<Vec<u8>> {
    let einval = || Error::new(Errno::EINVAL, "bad symbolic link");
    let filesize = udf_node.file_size();

    // Not in NetBSD: its buffer would overflow.
    if filesize > UDF_SYMLINKBUFLEN as u64 {
        return Err(Error::new(Errno::EINVAL, "symbolic link too long"));
    }

    // Read contents of file in our temporary buffer.
    let mut pathbuf = vn_rdwr(dev, ump, udf_node, 0, filesize as usize, true)?;
    pathbuf.resize(UDF_SYMLINKBUFLEN, 0);

    // Convert to a unix path.
    let is_osta_typ0 = udf_is_osta_typ0(ump);
    let mut target = Vec::new();
    let mut targetlen = PATH_MAX;
    let mntonname = &ump.mntonname;

    let mut pathpos: usize = 0;
    let mut pathlen: u64 = 0;
    let mut first = true;
    while filesize.wrapping_sub(pathlen) >= UDF_PATH_COMP_SIZE as u64 {
        let comp_type = rd8(&pathbuf, pathpos);
        let l_ci = usize::from(rd8(&pathbuf, pathpos + 1));
        let more = filesize.wrapping_sub(pathlen) > (UDF_PATH_COMP_SIZE + l_ci) as u64;
        match comp_type {
            UDF_PATH_COMP_ROOT => {
                // XXX should check for l_ci; bugcompatible now.
                if targetlen < 1 || !first {
                    return Err(einval());
                }
                target.push(b'/');
                targetlen -= 1;
            }
            UDF_PATH_COMP_MOUNTROOT => {
                // XXX what should it be if l_ci > 0 ? [4/48.16.1.2]
                if l_ci != 0 || targetlen < mntonname.len() + 1 || !first {
                    return Err(einval());
                }
                target.extend_from_slice(mntonname);
                targetlen -= mntonname.len();
                if more {
                    // More follows, so must be directory.
                    target.push(b'/');
                    targetlen -= 1;
                }
            }
            UDF_PATH_COMP_PARENTDIR => {
                // XXX should check for l_ci; bugcompatible now.
                if targetlen < 3 {
                    return Err(einval());
                }
                target.extend_from_slice(b"../");
                targetlen -= 3;
            }
            UDF_PATH_COMP_CURDIR => {
                // XXX should check for l_ci; bugcompatible now.
                if targetlen < 2 {
                    return Err(einval());
                }
                target.extend_from_slice(b"./");
                targetlen -= 2;
            }
            UDF_PATH_COMP_NAME => {
                if l_ci == 0 {
                    return Err(einval());
                }
                let ident = pathbuf.get(pathpos + UDF_PATH_COMP_SIZE..).unwrap_or(&[]);
                let tmpname = udf_to_unix_name(MAXPATHLEN, ident, l_ci, is_osta_typ0);
                let namelen = tmpname.len();
                if targetlen < namelen + 1 {
                    return Err(einval());
                }
                target.extend_from_slice(&tmpname);
                targetlen -= namelen;
                if more {
                    // More follows, so must be directory.
                    target.push(b'/');
                    targetlen -= 1;
                }
            }
            _ => return Err(einval()),
        }
        first = false;
        pathpos += UDF_PATH_COMP_SIZE + l_ci;
        pathlen += (UDF_PATH_COMP_SIZE + l_ci) as u64;
    }
    // All processed?
    if filesize.wrapping_sub(pathlen) > 0 {
        return Err(einval());
    }
    Ok(target)
}
