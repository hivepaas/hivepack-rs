//! Huffman coding low-level stuff: port of `huffman.c`.

use crate::bzip2::private::{BZ_MAX_ALPHA_SIZE, BZ_MAX_CODE_LEN};

/// `WEIGHTOF`.
fn weight_of(zz0: i32) -> i32 {
    zz0 & !0xff
}

/// `DEPTHOF`.
fn depth_of(zz1: i32) -> i32 {
    zz1 & 0x0000_00ff
}

/// `ADDWEIGHTS`.
fn add_weights(zw1: i32, zw2: i32) -> i32 {
    (weight_of(zw1) + weight_of(zw2)) | (1 + depth_of(zw1).max(depth_of(zw2)))
}

/// `BZ2_hbMakeCodeLengths`: the lengths of a Huffman code for `freq`,
/// none longer than `max_len`.
pub(crate) fn make_code_lengths(len: &mut [u8], freq: &[i32], alpha_size: i32, max_len: i32) {
    // Nodes and heap entries run from 1. Entry 0 for both the heap and
    // nodes is a sentinel.
    let mut heap = [0i32; BZ_MAX_ALPHA_SIZE + 2];
    let mut weight = [0i32; BZ_MAX_ALPHA_SIZE * 2];
    let mut parent = [0i32; BZ_MAX_ALPHA_SIZE * 2];
    let alpha_size = alpha_size as usize;

    for i in 0..alpha_size {
        weight[i + 1] = (if freq[i] == 0 { 1 } else { freq[i] }) << 8;
    }

    // `UPHEAP`.
    let upheap = |heap: &mut [i32], weight: &[i32], z: usize| {
        let mut zz = z;
        let tmp = heap[zz];
        while weight[tmp as usize] < weight[heap[zz >> 1] as usize] {
            heap[zz] = heap[zz >> 1];
            zz >>= 1;
        }
        heap[zz] = tmp;
    };
    // `DOWNHEAP`.
    let downheap = |heap: &mut [i32], weight: &[i32], n_heap: usize, z: usize| {
        let mut zz = z;
        let tmp = heap[zz];
        loop {
            let mut yy = zz << 1;
            if yy > n_heap {
                break;
            }
            if yy < n_heap && weight[heap[yy + 1] as usize] < weight[heap[yy] as usize] {
                yy += 1;
            }
            if weight[tmp as usize] < weight[heap[yy] as usize] {
                break;
            }
            heap[zz] = heap[yy];
            zz = yy;
        }
        heap[zz] = tmp;
    };

    loop {
        let mut n_nodes = alpha_size;
        let mut n_heap = 0;

        heap[0] = 0;
        weight[0] = 0;
        parent[0] = -2;

        for i in 1..=alpha_size {
            parent[i] = -1;
            n_heap += 1;
            heap[n_heap] = i as i32;
            upheap(&mut heap, &weight, n_heap);
        }

        // AssertH(nHeap < BZ_MAX_ALPHA_SIZE + 2, 2001): alpha_size is at
        // most 258.

        while n_heap > 1 {
            let n1 = heap[1] as usize;
            heap[1] = heap[n_heap];
            n_heap -= 1;
            downheap(&mut heap, &weight, n_heap, 1);
            let n2 = heap[1] as usize;
            heap[1] = heap[n_heap];
            n_heap -= 1;
            downheap(&mut heap, &weight, n_heap, 1);
            n_nodes += 1;
            parent[n1] = n_nodes as i32;
            parent[n2] = n_nodes as i32;
            weight[n_nodes] = add_weights(weight[n1], weight[n2]);
            parent[n_nodes] = -1;
            n_heap += 1;
            heap[n_heap] = n_nodes as i32;
            upheap(&mut heap, &weight, n_heap);
        }

        // AssertH(nNodes < BZ_MAX_ALPHA_SIZE * 2, 2002): a tree of
        // alpha_size leaves has alpha_size - 1 inner nodes.

        let mut too_long = false;
        for i in 1..=alpha_size {
            let mut j = 0;
            let mut k = i;
            while parent[k] >= 0 {
                k = parent[k] as usize;
                j += 1;
            }
            len[i - 1] = j as u8;
            if j > max_len {
                too_long = true;
            }
        }

        if !too_long {
            break;
        }

        // Scale the counts down and try again; see huffman.c for why
        // max_len is 17 since bzip2 1.0.3.
        for i in 1..=alpha_size {
            let mut j = weight[i] >> 8;
            j = 1 + (j / 2);
            weight[i] = j << 8;
        }
    }
}

/// `BZ2_hbAssignCodes`: canonical codes for the lengths `length`.
pub(crate) fn assign_codes(
    code: &mut [i32],
    length: &[u8],
    min_len: i32,
    max_len: i32,
    alpha_size: i32,
) {
    let mut vec = 0;
    for n in min_len..=max_len {
        for i in 0..alpha_size as usize {
            if i32::from(length[i]) == n {
                code[i] = vec;
                vec += 1;
            }
        }
        vec <<= 1;
    }
}

/// `BZ2_hbCreateDecodeTables`: the tables the decoder reads a code with,
/// for the lengths `length`.
pub(crate) fn create_decode_tables(
    limit: &mut [i32],
    base: &mut [i32],
    perm: &mut [i32],
    length: &[u8],
    min_len: i32,
    max_len: i32,
    alpha_size: i32,
) {
    let alpha_size = alpha_size as usize;
    let mut pp = 0;
    for i in min_len..=max_len {
        for j in 0..alpha_size {
            if i32::from(length[j]) == i {
                perm[pp] = j as i32;
                pp += 1;
            }
        }
    }

    for b in base.iter_mut().take(BZ_MAX_CODE_LEN) {
        *b = 0;
    }
    for i in 0..alpha_size {
        base[usize::from(length[i]) + 1] += 1;
    }

    for i in 1..BZ_MAX_CODE_LEN {
        base[i] += base[i - 1];
    }

    for l in limit.iter_mut().take(BZ_MAX_CODE_LEN) {
        *l = 0;
    }
    let mut vec = 0;

    for i in min_len as usize..=max_len as usize {
        vec += base[i + 1] - base[i];
        limit[i] = vec - 1;
        vec <<= 1;
    }
    for i in min_len as usize + 1..=max_len as usize {
        base[i] = ((limit[i - 1] + 1) << 1) - base[i];
    }
}
