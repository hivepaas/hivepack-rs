//! The output queue of the threaded coders: port of `common/outqueue.c`.
//!
//! liblzma's buffers are a linked list of structures with the data after
//! them, which a worker thread writes while the main thread reads what it
//! has finished. Here the queue is a `VecDeque` of [`OutBuf`] behind the
//! coder's mutex, as liblzma reads it, and a worker takes the data of its
//! buffer ([`OutBuf::buf`]) while it writes, and gives it back when it has
//! finished: the encoder's main thread reads only finished data. The
//! decoder's reads what a worker has moved there so far, under the mutex.

use std::collections::VecDeque;

use crate::xz::common::{Ret, bufcpy};

/// `LZMA_THREADS_MAX`: the most threads a threaded coder takes.
pub(crate) const THREADS_MAX: u32 = 16384;

/// `sizeof(lzma_outbuf)` in liblzma on 64-bit systems, which its memory
/// usage counts for each buffer.
const OUTBUF_SIZE: u64 = 64;

/// `GET_BUFS_LIMIT`: the number of buffers that may be allocated.
const fn get_bufs_limit(threads: u32) -> u32 {
    2 * threads
}

/// `lzma_outq_outbuf_memusage`: the memory of one buffer.
pub(crate) fn outbuf_memusage(buf_size: usize) -> u64 {
    OUTBUF_SIZE + buf_size as u64
}

/// `lzma_outbuf`: the output buffer of a thread.
pub(crate) struct OutBuf {
    /// The buffer's number, from the first one, so that a worker can find
    /// its buffer again.
    pub(crate) id: u64,
    /// The worker that writes to this buffer, for
    /// `lzma_outq_enable_partial_output()`.
    worker: Option<usize>,
    /// Amount of memory allocated for buf[].
    pub(crate) allocated: usize,
    /// Writing position in the worker thread or, in other words, the
    /// amount of finished data written to buf[] which can be copied out
    pub(crate) pos: usize,
    /// Decompression: Position in the input buffer in the worker thread
    /// that matches the output "pos" above. This is used to detect if more
    /// output might be possible from the worker thread: if it has consumed
    /// all its input, then more output isn't possible.
    pub(crate) decoder_in_pos: usize,
    /// True when no more data will be written into this buffer.
    pub(crate) finished: bool,
    /// Return value for `lzma_outq_read()` when the last byte from a
    /// finished buffer has been read. Defaults to LZMA_STREAM_END.
    pub(crate) finish_ret: Ret,
    /// Additional size information. `lzma_outq_read()` may read these when
    /// "finished" is true.
    pub(crate) unpadded_size: u64,
    pub(crate) uncompressed_size: u64,
    /// The data: empty while a worker has taken it to write to.
    pub(crate) buf: Vec<u8>,
}

/// `lzma_outq`.
#[derive(Default)]
pub(crate) struct OutQueue {
    /// The buffers in use, from the one the next output byte is read
    /// from (head) to the one the latest thread writes (tail).
    bufs: VecDeque<OutBuf>,
    /// Number of bytes read from the head's buf[] in `lzma_outq_read()`
    read_pos: usize,
    /// Allocated buffers that aren't currently used, all of the same
    /// allocated size.
    cache: Vec<Vec<u8>>,
    /// The allocated size of the cached buffers.
    cache_allocated: usize,
    /// Total amount of memory allocated for buffers
    pub(crate) mem_allocated: u64,
    /// Amount of memory used by the buffers that are in use.
    pub(crate) mem_in_use: u64,
    /// Number of buffers allocated (in use + cached)
    bufs_allocated: u32,
    /// Maximum allowed number of allocated buffers
    bufs_limit: u32,
    /// The number the next buffer gets.
    next_id: u64,
}

/// `lzma_outq_memusage`: the memory of the buffers of `threads` threads of
/// up to `buf_size_max` bytes, u64::MAX on error.
pub(crate) fn outq_memusage(buf_size_max: u64, threads: u32) -> u64 {
    // This is to ease integer overflow checking: We may allocate up to
    // GET_BUFS_LIMIT(LZMA_THREADS_MAX) buffers and we need some extra
    // memory for other data structures too (that's the /2).
    //
    // lzma_outq_prealloc_buf() will still accept bigger buffers than this.
    let limit = u64::MAX / u64::from(get_bufs_limit(THREADS_MAX)) / 2;

    if threads > THREADS_MAX || buf_size_max > limit {
        return u64::MAX;
    }

    u64::from(get_bufs_limit(threads)) * (OUTBUF_SIZE + buf_size_max)
}

impl OutQueue {
    /// `move_head_to_cache`.
    fn move_head_to_cache(&mut self) {
        let Some(buf) = self.bufs.pop_front() else {
            return;
        };

        // If a different size is needed, clear the cache first.
        if !self.cache.is_empty() && self.cache_allocated != buf.allocated {
            self.clear_cache();
        }

        self.mem_in_use -= outbuf_memusage(buf.allocated);
        self.cache_allocated = buf.allocated;
        self.cache.push(buf.buf);
    }

    /// `free_one_cached_buffer`.
    fn free_one_cached_buffer(&mut self) {
        if self.cache.pop().is_some() {
            self.bufs_allocated -= 1;
            self.mem_allocated -= outbuf_memusage(self.cache_allocated);
        }
    }

    /// `lzma_outq_clear_cache`: free all cached buffers that consume
    /// memory but aren't in use.
    pub(crate) fn clear_cache(&mut self) {
        while !self.cache.is_empty() {
            self.free_one_cached_buffer();
        }
    }

    /// `lzma_outq_clear_cache2`: like `lzma_outq_clear_cache()` but one
    /// buffer is not freed if its size is equal to `keep_size`.
    pub(crate) fn clear_cache2(&mut self, keep_size: usize) {
        if self.cache.is_empty() {
            return;
        }

        while self.cache.len() > 1 {
            self.free_one_cached_buffer();
        }

        if self.cache_allocated != keep_size {
            self.free_one_cached_buffer();
        }
    }

    /// `lzma_outq_init`: ready for `threads` threads, keeping what buffers
    /// it can.
    pub(crate) fn init(&mut self, threads: u32) -> Ret {
        if threads > THREADS_MAX {
            return Ret::OptionsError;
        }

        let bufs_limit = get_bufs_limit(threads);

        while !self.bufs.is_empty() {
            self.move_head_to_cache();
        }

        while bufs_limit < self.bufs_allocated {
            self.free_one_cached_buffer();
        }

        self.bufs_limit = bufs_limit;
        self.read_pos = 0;

        Ret::Ok
    }

    /// `lzma_outq_prealloc_buf`: a buffer of `size` bytes in the cache,
    /// so that `lzma_outq_get_buf()` cannot fail.
    ///
    /// Differs from liblzma, without a difference to see: the memory is
    /// reserved, not initialized; the worker initializes what it writes.
    pub(crate) fn prealloc_buf(&mut self, size: usize) -> Ret {
        // If there is already a cached buffer of the right size, use it.
        if !self.cache.is_empty() && self.cache_allocated == size {
            return Ret::Ok;
        }

        // Free all cached buffers, as they are of the wrong size, and
        // allocate a new one.
        self.clear_cache();

        let mut buf = Vec::new();
        if buf.try_reserve_exact(size).is_err() {
            return Ret::MemError;
        }

        self.cache.push(buf);
        self.cache_allocated = size;
        self.bufs_allocated += 1;
        self.mem_allocated += outbuf_memusage(size);

        Ret::Ok
    }

    /// `lzma_outq_get_buf`: a new buffer at the tail, for `worker`; its
    /// number.
    pub(crate) fn get_buf(&mut self, worker: Option<usize>) -> u64 {
        let buf = self.cache.pop().unwrap_or_default();
        let id = self.next_id;
        self.next_id += 1;

        self.mem_in_use += outbuf_memusage(self.cache_allocated);
        self.bufs.push_back(OutBuf {
            id,
            worker,
            allocated: self.cache_allocated,
            pos: 0,
            decoder_in_pos: 0,
            finished: false,
            finish_ret: Ret::StreamEnd,
            unpadded_size: 0,
            uncompressed_size: 0,
            buf,
        });

        id
    }

    /// The buffer numbered `id`, if it is still in use.
    pub(crate) fn buf_mut(&mut self, id: u64) -> Option<&mut OutBuf> {
        let head = self.bufs.front()?.id;
        let index = usize::try_from(id.checked_sub(head)?).ok()?;
        self.bufs.get_mut(index)
    }

    /// Takes back the data of a buffer that is no longer in use: into the
    /// cache if it is of the cached size, else freed.
    pub(crate) fn give_back(&mut self, buf: Vec<u8>, allocated: usize) {
        if allocated == self.cache_allocated && !self.cache.is_empty() {
            self.cache.push(buf);
        } else {
            // It was counted among the allocated ones.
            self.bufs_allocated -= 1;
            self.mem_allocated -= outbuf_memusage(allocated);
        }
    }

    /// `lzma_outq_is_readable`: whether there is data ready to be read.
    pub(crate) fn is_readable(&self) -> bool {
        match self.bufs.front() {
            None => false,
            Some(head) => self.read_pos < head.pos || head.finished,
        }
    }

    /// `lzma_outq_read`: copies finished data to `out`. LZMA_OK if no data
    /// was available or the buffer being read didn't become empty yet,
    /// else the buffer's `finish_ret` with its Unpadded Size and
    /// Uncompressed Size.
    pub(crate) fn read(&mut self, out: &mut [u8], out_pos: &mut usize) -> (Ret, u64, u64) {
        let Some(buf) = self.bufs.front() else {
            return (Ret::Ok, 0, 0);
        };

        bufcpy(&buf.buf[..buf.pos], &mut self.read_pos, out, out_pos);

        if !buf.finished || self.read_pos < buf.pos {
            return (Ret::Ok, 0, 0);
        }

        let sizes = (buf.finish_ret, buf.unpadded_size, buf.uncompressed_size);

        self.move_head_to_cache();
        self.read_pos = 0;

        sizes
    }

    /// `lzma_outq_enable_partial_output`: the worker to tell to give
    /// partial output, if the buffer at the head of the queue isn't
    /// finished and it has not been told yet.
    pub(crate) fn enable_partial_output(&mut self) -> Option<usize> {
        let head = self.bufs.front_mut()?;
        if head.finished {
            return None;
        }
        head.worker.take()
    }

    /// The `decoder_in_pos` of the buffer at the head of the queue.
    pub(crate) fn head_decoder_in_pos(&self) -> Option<usize> {
        self.bufs.front().map(|head| head.decoder_in_pos)
    }

    /// `lzma_outq_has_buf`: whether a buffer can be taken.
    pub(crate) fn has_buf(&self) -> bool {
        (self.bufs.len() as u32) < self.bufs_limit
    }

    /// `lzma_outq_is_empty`: whether no buffer is in use.
    pub(crate) fn is_empty(&self) -> bool {
        self.bufs.is_empty()
    }
}
