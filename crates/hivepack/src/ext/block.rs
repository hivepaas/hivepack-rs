//! Where a file's data is: the block numbers ext2 had, and the tree of
//! extents ext4 brought.

use crate::image::Disk;

use super::Ext;
use super::error::Error;
use super::inode::Node;
use super::sb::{le16, le32};

/// What every node of a tree of extents begins with, and how long a node's
/// header and each of its entries are.
const MAGIC: u16 = 0xF30A;
const HEADER: usize = 12;
const ENTRY: usize = 12;

/// How deep a tree of extents may be: the format's own most is five, and
/// four reaches further than a file may be long.
const MOST_DEPTH: u16 = 5;

/// An extent of more than this many blocks is one that was allocated and
/// never written, and how long it is, is what is left over. It reads as
/// zeroes, like a hole, because that is what is in it.
const WRITTEN: u32 = 1 << 15;

impl<D: Disk> Ext<D> {
    /// Where the `at` logical block of `node` is, and how many blocks from
    /// `at` onwards lie the same way, at most `most` of them: `None` for a
    /// hole, which reads as zeroes.
    ///
    /// `most` is never 0, and what comes back is never 0 either, so a read
    /// always moves on.
    pub(crate) fn run(&self, node: &Node, at: u64, most: u64) -> Result<(Option<u64>, u64), Error> {
        let most = most.max(1);
        if node.extents() {
            self.extent_run(node, at, most)
        } else {
            self.mapped_run(node, at, most)
        }
    }

    /// The same, through a tree of extents.
    fn extent_run(&self, node: &Node, at: u64, most: u64) -> Result<(Option<u64>, u64), Error> {
        // An extent says its logical block in four bytes, so a file longer
        // than that many blocks has nothing there.
        let Ok(want) = u32::try_from(at) else {
            return Ok((None, most));
        };
        let mut raw = node.map.to_vec();
        for _ in 0..=MOST_DEPTH {
            if le16(&raw, 0) != MAGIC {
                return Err(Error::ExtentTree);
            }
            let entries = usize::from(le16(&raw, 2));
            let depth = le16(&raw, 6);
            // What the node has room for, which is what it may say it
            // holds: a header and then entries, to the end of the node.
            let room = (raw.len() - HEADER) / ENTRY;
            if depth > MOST_DEPTH || entries > room {
                return Err(Error::ExtentTree);
            }
            if depth == 0 {
                return Ok(leaf(&raw, entries, want, most));
            }
            // The last entry whose own logical block is not past the one
            // wanted: the entries are in order.
            let mut found = None;
            for i in 0..entries {
                let at = HEADER + i * ENTRY;
                if le32(&raw, at) > want {
                    break;
                }
                found = Some(at);
            }
            let Some(at) = found else {
                // Nothing in the tree reaches back this far: a hole.
                return Ok((None, most));
            };
            let leaf = u64::from(le32(&raw, at + 4)) | (u64::from(le16(&raw, at + 8)) << 32);
            raw = self.block(leaf)?;
        }
        Err(Error::ExtentTree)
    }

    /// The same, through the block numbers in the inode and the indirect
    /// blocks they lead to.
    fn mapped_run(&self, node: &Node, at: u64, most: u64) -> Result<(Option<u64>, u64), Error> {
        // How many numbers an indirect block holds.
        let per = u64::from(self.sb.block / 4);
        // The twelve in the inode itself.
        if at < 12 {
            let most = most.min(12 - at);
            return Ok(scan(&node.map, at as usize, most));
        }
        let at = at - 12;
        // One block of numbers.
        if at < per {
            return self.through(le32(&node.map, 12 * 4), at, most.min(per - at));
        }
        let at = at - per;
        // A block of numbers of blocks of numbers.
        if at < per * per {
            let first = self.pointer(le32(&node.map, 13 * 4), at / per)?;
            let into = at % per;
            return self.through(first, into, most.min(per - into));
        }
        let at = at - per * per;
        // And one level deeper, which is as far as the map goes.
        if at < per * per * per {
            let first = self.pointer(le32(&node.map, 14 * 4), at / (per * per))?;
            let first = self.pointer(first, (at / per) % per)?;
            let into = at % per;
            return self.through(first, into, most.min(per - into));
        }
        Ok((None, most))
    }

    /// The `i` number of the indirect block `block`, or 0 where there is no
    /// such block at all, which is a hole.
    fn pointer(&self, block: u32, i: u64) -> Result<u32, Error> {
        if block == 0 {
            return Ok(0);
        }
        let Some(at) = self.sb.at(u64::from(block)) else {
            return Err(Error::PastTheEnd {
                block: u64::from(block),
            });
        };
        let mut raw = [0u8; 4];
        self.disk.read_exact_at(at + i * 4, &mut raw)?;
        Ok(u32::from_le_bytes(raw))
    }

    /// A run read out of the indirect block `block`, from its `i` number
    /// onwards.
    fn through(&self, block: u32, i: u64, most: u64) -> Result<(Option<u64>, u64), Error> {
        if block == 0 {
            // No block of numbers at all: a hole as long as it may be.
            return Ok((None, most));
        }
        let raw = self.block(u64::from(block))?;
        Ok(scan(&raw, i as usize, most))
    }
}

/// The extent of a leaf node that holds the `want` logical block, as a run.
fn leaf(raw: &[u8], entries: usize, want: u32, most: u64) -> (Option<u64>, u64) {
    for i in 0..entries {
        let at = HEADER + i * ENTRY;
        let first = le32(raw, at);
        let told = u32::from(le16(raw, at + 4));
        let (len, written) = if told > WRITTEN {
            (told - WRITTEN, false)
        } else {
            (told, true)
        };
        if len == 0 {
            continue;
        }
        if want < first {
            // The extents are in order, so the one that would have held it
            // is not there: a hole, up to where this extent begins.
            return (None, most.min(u64::from(first - want)));
        }
        if want - first < len {
            let into = want - first;
            let left = most.min(u64::from(len - into));
            if !written {
                // Allocated and never written, which reads as zeroes.
                return (None, left);
            }
            let start = u64::from(le32(raw, at + 8)) | (u64::from(le16(raw, at + 6)) << 32);
            return (Some(start + u64::from(into)), left);
        }
    }
    (None, most)
}

/// A run of block numbers from the `i` number of `raw`: where it begins,
/// and how many after it follow it in the file system, so that a file
/// written in one piece is read in one go. A number of 0 is a hole, and the
/// run is then how many holes follow.
fn scan(raw: &[u8], i: usize, most: u64) -> (Option<u64>, u64) {
    let first = le32(raw, i * 4);
    let mut run = 1u64;
    if first == 0 {
        while run < most && le32(raw, (i + run as usize) * 4) == 0 {
            run += 1;
        }
        return (None, run);
    }
    while run < most {
        if u64::from(le32(raw, (i + run as usize) * 4)) != u64::from(first) + run {
            break;
        }
        run += 1;
    }
    (Some(u64::from(first)), run)
}
