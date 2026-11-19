//! hivepack::image on any input: the partition tables of a raw disk, in
//! both sector sizes a table can be counted in, and the six containers,
//! each opened on the same bytes and the disk it holds read through it.
//!
//! What is read is read twice, in pieces of different sizes the first eight
//! bytes' hash picks, and the two must agree: a disk answers for a place,
//! not for the order its places were asked for. A panic is a bug, and so is
//! a disagreement.
//!
//! Up to 4 MiB of a disk is read: a container of a few hundred bytes can
//! say it holds terabytes, and what is past the file reads as zeroes.

#![no_main]

use hivepack::image::{
    AndroidSparse, Disk, Part, Qcow2, Vdi, Vhd, Vhdx, Vmdk, partitions, partitions_in,
};
use libfuzzer_sys::fuzz_target;

const MAX_DATA: u64 = 4 << 20;

/// The next size to read in, between 1 byte and 64 KiB.
fn next(seed: &mut u64) -> usize {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    1 + (*seed >> 48) as usize
}

/// The front of a disk, in pieces of the sizes `seed` picks.
fn read_some<D: Disk>(disk: &D, mut seed: u64) -> Result<Vec<u8>, String> {
    let size = disk.size().map_err(|e| e.to_string())?.min(MAX_DATA);
    let mut out = Vec::new();
    while (out.len() as u64) < size {
        let room = (size - out.len() as u64) as usize;
        let mut buf = vec![0u8; next(&mut seed).min(room)];
        match disk.read_at(out.len() as u64, &mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(out)
}

/// What a disk holds and what its table says: neither may depend on the
/// sizes the reads were made in.
fn look<D: Disk>(disk: &D, seed: u64) -> (Result<Vec<u8>, String>, String) {
    let table = match partitions(disk) {
        Ok(found) => format!("{found:?}"),
        Err(e) => e.to_string(),
    };
    (read_some(disk, seed), table)
}

fuzz_target!(|data: &[u8]| {
    let seed = data
        .iter()
        .take(8)
        .fold(0u64, |h, &b| h.rotate_left(8) ^ u64::from(b));

    // A raw disk, and a table counted in either sector size.
    assert_eq!(look(&data, seed), look(&data, !seed));
    for sector in [512, 1024, 4096] {
        let _ = partitions_in(&data, sector);
    }

    // Each partition as a disk of its own, which is how a file system in
    // one is read: a table inside it too, as a partition of a partition is
    // refused rather than followed.
    if let Ok(Some(found)) = partitions(&data) {
        for part in found.partitions.iter().take(8) {
            let part = Part::new(data, part.at, part.size);
            assert_eq!(look(&part, seed), look(&part, !seed));
        }
    }

    // The containers. Each says what is not its own, so all six are tried
    // on every input; whichever opens is read as a disk.
    if let Ok(vhd) = Vhd::open(data) {
        assert_eq!(look(&vhd, seed), look(&vhd, !seed));
    }
    if let Ok(qcow2) = Qcow2::open(data) {
        assert_eq!(look(&qcow2, seed), look(&qcow2, !seed));
    }
    if let Ok(vhdx) = Vhdx::open(data) {
        assert_eq!(look(&vhdx, seed), look(&vhdx, !seed));
    }
    if let Ok(vmdk) = Vmdk::open(data) {
        assert_eq!(look(&vmdk, seed), look(&vmdk, !seed));
    }
    if let Ok(vdi) = Vdi::open(data) {
        assert_eq!(look(&vdi, seed), look(&vdi, !seed));
    }
    if let Ok(sparse) = AndroidSparse::open(data) {
        assert_eq!(look(&sparse, seed), look(&sparse, !seed));
    }
});
