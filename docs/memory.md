# Memory

Threads multiply what a coder takes: each has its own encoder or decoder, and its own data in and out. Running out of memory cannot be recovered from: Rust aborts when an allocation fails, and Linux's OOM killer ends the process before it does. So an application has to choose its threads before it starts. Each coder of hivepack that uses threads takes a limit, and lowers its threads until what it would take fits it; and each tells, before it starts, what a configuration takes, so that an application that cannot fit even one thread can say how much it needs. Where the limit comes from is the application's to say: `hivepack::memory`, behind the feature `memory`, measures how much the program may still take, and shares it between the jobs that run at once ([Measuring what is available](#measuring-what-is-available), [Wiring it to the coders](#wiring-it-to-the-coders)). The coders never call it on their own.

Lowering the threads is always safe: every coder gives the same output whatever its threads, one or many (see `hivepack::Threads`), so the limit changes how fast something is made, never what is made.

## How the threads are chosen

- **The most that fit.** A coder asked for `n` threads (`Threads::Exactly(n)`, or `Threads::Auto` for as many as the machine runs at once) uses the most threads, `n` or fewer, whose estimate is no more than its limit.
- **One is always allowed**, even where one takes more than the limit, as liblzma's `memlimit_threading` allows one thread. A limit never makes a coder fail: it can only make it slower. Where one thread does not fit, the estimate of one says how much it takes, for the application to tell the user, or to refuse the job itself.
- **No limit by default.** Every new limit is `u64::MAX` unless set, so nothing changes for a caller that does not set one. The readers' limits that were there before keep their defaults (`sevenz::Options::decoder_memory_limit`, `open::Limits::xz_memlimit`).
- **The estimates are upper bounds** of what the coder allocates, whatever the data: they count each buffer at the size it is allocated with, where the memory a process uses (its resident set) counts only the pages written. A block's output is given room for the most it can compress to, which data that compresses never fills: so the memory used is often well below the estimate, never above it.

## Writers

| Coder | The limit | The estimate | The threads it takes |
|---|---|---|---|
| 7z, LZMA2 in blocks | `sevenz::WriteOptions::memory_limit` | `WriteOptions::memory_usage(threads)` | `WriteOptions::threads_used()` |
| zstd with workers | `zstd::CCtx::set_workers_memory_limit(limit)` | `CCtx::estimate_memory(nb_workers)` | `CCtx::nb_workers_within_limit()` |
| bzip2 in threads | `bzip2::MtOptions::memory_limit` | `MtOptions::memory_usage(threads)` | `MtOptions::threads_used()` |

What they take, from the estimates, in MiB:

| Coder | One thread | Each thread more |
|---|---|---|
| 7z, LZMA2 preset 1, blocks of 4 MiB | 21.7 | 16.6 |
| 7z, LZMA2 preset 6, blocks of 32 MiB | 190 | 157 |
| 7z, LZMA2 preset 9, blocks of 256 MiB | 1,442 | 1,185 |
| 7z, LZMA2 preset 6 in one stream (one thread only) | 95 | |
| zstd level 3, jobs of 8 MiB | 69 (none: 4.5) | 18.5, and more where the job table grows |
| zstd level 19, jobs of 32 MiB | 373 (none: 90) | 153, and more where the job table grows |
| bzip2 level 9 | 18.4 | 15.8 |

zstd's workers do not cost the same each: the job table, which holds a copy of the output of each job not yet written out, grows by powers of 2 (4 places for 1 worker, 8 for 2 to 5, 16 for 6 to 13, 32 for 14 to 29), each place the output of a job. Level 3 takes 69 MiB with one worker, 120 with 2, 157 with 4 and 572 with 16; level 19 373, 656, 964 and 3,588.

### 7z: LZMA2 in blocks

With `WriteOptions::lzma2_blocks`, `Writer` compresses each block in a thread of its own ([7z.md](7z.md#lzma2-in-blocks-in-threads)). With `B` the size of a block, `E` the memory of an LZMA2 encoder whose dictionary is no larger than `B` (`xz::raw_encoder_memusage`, liblzma's count: 9.6 MiB for preset 1, 94 MiB for 6, 674 MiB for 9), and `O = B + 6 × ⌈B / 64 KiB⌉ + 16`, the most a block compresses to (an LZMA2 chunk of at most 64 KiB, each with a header of at most 6 bytes):

```
memory_usage(n) = max(n × (E + B + O) + O, H) + 1 MiB + 64 KiB
```

Each thread keeps its encoder from one block to the next, and holds the block it compresses and room for its output, reserved once, whole; a block more, compressed and waiting to be written, or being filled, which is no larger. The writer's own buffer is 64 KiB, and AES, a filter before the blocks (BCJ or delta) and the threads' channels fit in the 1 MiB. The other methods use one thread: LZMA and LZMA2 in one stream their encoder (`E`, the chain's, filter included), Deflate 512 KiB at most, BZip2 `Compress`'s 14 MB at level 9, Copy nothing.

`H` is the encoder of the header, written at the end, once the coders are let go: LZMA2 of preset 6 with a dictionary as large as the header, from 64 KiB (2 MiB in all) to 64 MiB. What is not counted is what grows with the files rather than with the threads: the list of files, and a header of more than 64 KiB, some thousands of files, whose encoder takes about 12 times its size.

The threads are chosen when a folder starts: a folder after `Writer::set_method` takes the threads that fit its own method. Before this, the writer made an encoder of one stream when it was made, and kept it beside the threads' encoders all along, for nothing: that is gone, and so are the copies of a block as it grew, as its room is now reserved whole.

### zstd with workers

libzstd estimates a context without workers (`ZSTD_estimateCStreamSize`) and refuses to estimate one with them. `CCtx::estimate_memory` counts what the port allocates, with workers or without (`zstd_compress/memory.rs`, beside the port). With the frame's parameters as the next frame resolves them (level, window `W`, hash, chain and strategy, its size if pledged), `S` the size of a job (`CParameter::JobSize`, or 4 times the window: 8 MiB at level 3, 32 MiB at level 19), `P` the overlap of a job with the one before (a fraction of the window by the strategy: 256 KiB at level 3, 8 MiB at level 19), `D = ZSTD_compressBound(S)`, `T` the job table's places (a power of 2 over `n + 2`), and `C` a context for blocks of `K` = 128 KiB at most:

```
C = 4 × (2^hashLog + 2^chainLog + 2^hashLog3) + 2^hashLog (the row match finder's tags),
      each where the strategy has it
  + K + 11 × K / 3 (a block's literals and sequences) + the optimal parser's tables (from btopt)
  + 2 entropy tables + 1 MiB

without workers: C + (W + K) + ZSTD_compressBound(K) (the buffers, when buffered)
with n workers:  n × (C + D) + (n + 2) × (P + S) + P + T × D + 2 MiB
```

Each worker has a context and a buffer for a job's output; a job's input, after its overlap, is held in a buffer of its own until the job is done (one for each worker, one made and waiting for a worker, one being filled); and what each job writes is copied for the caller until it is written out, which the job table bounds. A caller that writes out a little at a time can fill the table. Long distance matching adds its tables, the sequences of each job, and the input its window reaches, which its buffer may hold twice and with room for twice that: `4 × (W + S)`.

The limit (`CCtx::set_workers_memory_limit`) lowers each frame's workers, from those `CParameter::NbWorkers` sets, at least to one, never to none: a frame with workers is not the frame without them, while it is the same with one worker or 200. A frame of a known size of 512 KB or less takes no workers, and no limit. Under a limit, the workers' context is made again for a frame that would take other than the frame before, so that it keeps no contexts or buffers of a larger frame (libzstd's pools only grow); without a limit, it is kept, as libzstd keeps it.

`xz`'s encoder in threads (`Stream::stream_encoder_mt`) is liblzma's, which has no limit for it either: `xz::stream_encoder_mt_memusage` counts what it takes, for the caller to choose its threads, as `xz --memlimit-compress` does.

### bzip2 in threads

`CompressMt` ([bzip2.md](bzip2.md#threads-beside-the-port)) holds at most two pieces in flight for each thread, each read, being compressed, or compressed and waiting. With `P` the size of a piece (855,000 bytes at level 9), `O = P + P / 100 + 601` the room for its stream, and `C` a `Compress` (about 15 bytes for each byte of a block: 14 MB at level 9):

```
memory_usage(n) = n × (P + C + 2 × O) + P + O + 1 MiB
```

## Readers

Each reader that uses threads is bounded by a limit, as with one thread:

| Reader | The limit | What it bounds |
|---|---|---|
| 7z, LZMA2 in blocks (`sevenz::Archive::set_threads`, `extract::Options::threads`) | `sevenz::Options::decoder_memory_limit`, 4 GiB by default; in an extraction, also the part of `extract::Options::memory_limit` the next row gives each folder | The folder's dictionaries, and the blocks given to threads and not yet read: their packed bytes, their output, and their decoders' dictionaries. Jobs wait while they would hold more; one that would hold more alone is decoded on the caller's thread. Beside it: the packed bytes of one job read ahead, at most 64 MiB and no more than the limit, and each thread's decoder's state, about 30 KiB. |
| 7z, folders in threads (`extract::extract_7z` with `extract::Options::threads`) | `extract::Options::memory_limit`, none by default, and `extract::Options::memory_budget` | The folders decoded at once are lowered until `n × E` fits, `E` the most a folder's decoder takes, for the folder of the archive that takes the most: each coder's dictionary or model as the archive says it (LZMA's and LZMA2's no larger than the coder's output, PPMd's model), LZMA's probabilities (`1.5 KiB << (lc + lp)`, and 64 KiB), BZip2's 4 MiB, Zstandard's window no larger than the output (as a frame that says its size takes), 128 KiB for each coder's input and buffers, and 1 MiB for filters', BCJ2's and AES's buffers and the thread's own; no more than `sevenz::Options::decoder_memory_limit` in all, past which the folder fails; and with more than one thread, for each LZMA2 coder, its input read ahead to find where its blocks start, up to 64 MiB and no more than the folder's packed size. The threads left over, and those of the folders done as the last are decoded, decode LZMA2 in blocks: the jobs of each folder hold no more than an equal part of what is left of the limit once the `n` decoders are counted, and of `decoder_memory_limit`; a folder started while no thread is left over decodes LZMA2 as one thread does. With the budget, `n × E` is held, and the blocks' jobs share what it had left, not held. One thread, which decodes the folders one after another as before, is always allowed. |
| xz (`open::Opener::threads`) | `open::Limits::xz_memlimit`, 1 GiB by default | liblzma's `memlimit_threading`: its threads are lowered until they fit, one always allowed; and its `memlimit_stop`, past which one Block fails, as with one thread. |
| bzip2 (`open::Opener::threads`) | `open::Limits::bzip2_memlimit`, none by default | The threads are lowered until `n × 20.5 MiB + 13 MiB` fits: for each piece in flight, two for each thread, at most 2.25 MiB read (counted twice, for the copy made when the rest goes to one thread) and 4 MiB of output; a decoder for each thread, 3.6 MB; what is read ahead, and the output being read. One thread, the caller's decoder of about 4 MiB, is always allowed. A stream of one, decoded a block in each thread, holds the same: two blocks in flight for each thread, each at most 2 MiB packed and 4 MiB decoded; `tests/memory_limits.rs` measures 31 MiB for 4 threads on a stream of `bzip2 -9`. |
| RAR (`extract::extract_rar` with `extract::Options::threads`) | `extract::Options::memory_limit`, none by default, and `extract::Options::memory_budget` | The threads are lowered until `n × E` fits, `E` the most a thread holds for the entry that takes the most of those it writes: its window, as large as the entry's dictionary asks and no larger than `2 × (size + 8 MiB + 64 KiB)`, at least 1 MiB (it grows to twice what a match reaches, and a stream is stopped once past its size, which a write of 4 MiB and a filter's block of 4 MiB can take it); 257 MiB for RAR 2.9 to 4, whose stream may switch to PPMd, of a model of up to 256 MiB, within any entry; and 5 MiB of filters' blocks and buffers. A thread keeps the largest window it has had. One thread, the caller's, is always allowed. |
| RAR 5's blocks in threads (`rar::Extract::threads`) | none: what they hold does not grow with the threads | Beside the window, as with one thread: the packed data read ahead, at most 8 MiB behind the scan and the block it is at (4 MiB at most, larger ones decoded on the caller's thread) and 1 MiB more; the packed data handed to threads and not yet taken, at most 8 MiB and a block; and what they decode of it, at most 6 bytes for each byte and 64 KiB for each block, past which a block is decoded on the caller's thread: about 100 MiB at most. Measured on Silesia's 211 MB as one entry, `-m3`: the process's resident set 19 MB more than with one thread on 8 threads, 28 MB on 16, the threads' own stacks and allocators' arenas included. |
| tar and cpio (`extract::extract_tar`, `extract::extract_cpio`, and a XAR package's payloads, with `extract::Options::threads`) | `extract::Options::memory_limit`, none by default, and `extract::Options::memory_budget` | The data the caller has read and handed to threads to write, and that they have not written yet: at most 32 MiB, or the limit if less, whatever the threads, and at most 1,024 entries. The caller waits for room before it reads a file's data. A file larger than an eighth of that (4 MiB), or sparse, is written on the caller's thread from a buffer of 64 KiB, as with one thread; so is a file whose data does not read as its header says, cut short or damaged, from what was read of it, which stays counted until it is written. With `memory_budget`, those 32 MiB (or the limit) are held for two threads or more, and the threads lowered to one where they do not fit. Beside it, each thread's stack, and nothing that grows with the archive. |
| pbzx (`open::Opener::threads`) | `open::Limits::xz_memlimit`, 1 GiB by default; in `extract::extract_xar`, also `extract::Options::memory_limit` and what is held from `extract::Options::memory_budget` | The chunks in flight, two for each thread at most, and the one being read out: what stores each, what it decodes to, and its decoder's memory as liblzma counts it from the first Block Header (an xz chunk of Apple's, 16 MiB of `xz -6`, about 41 MiB); a chunk that would go past waits for those before it, and one that alone would is read with the rest by one thread. In `extract_xar`, a payload's decoding threads are held from the budget at 48 MiB each besides the caller's, and their chunks bounded by what was held. `tests/memory_limits.rs` measures 18 MiB under a limit of 20 MiB and 36 MiB under 40 MiB, eight threads on chunks of 512 KiB with dictionaries of 8 MiB. |
| zstd's frames (`open::Opener::threads`) | `open::Limits::zstd_memlimit`, 1 GiB by default | The frames in flight, two for each thread at most, and the one being read out: each frame's bytes, what it is decoded into (its size as its header says, or as its blocks may hold, at most 64 MiB) and 256 KiB for its decoder; a frame that would go past waits for those before it, and one that alone would is read with the rest by one thread, whose window `zstd_window_log_max` holds as before. What is read ahead to find a frame's end, up to 64 MiB, is not counted. `tests/memory_limits.rs` measures 2.3 MiB under a limit of 2 MiB and 6.0 MiB under 6 MiB, eight threads on frames of 256 KiB. |
| zstd of one frame, gzip, LZ4, lzip (`open`) | `open::Limits::zstd_window_log_max` for zstd | One thread each. |

Extracting a ZIP archive in threads (`extract::Options::threads`) decodes an entry in each thread, each with what one thread takes for it; it is not counted here.

7z's bound is close to what a thread holds where a dictionary is large, and above it where it is small, by the megabyte counted for buffers: `tests/memory_limits.rs` measures, with eight folders of text in eight threads, 12.2 MiB a thread for LZMA2 of preset 6 in folders of 12 MB, 3.0 MiB of it their packed data read ahead (12.2 MiB counted), 1.9 MiB for preset 1 in folders of 1.5 MB (2.7 MiB counted), 0.8 MiB for LZMA of preset 1 (1.8 MiB counted), 3.7 MiB for BZip2 (5.1 MiB counted) and 0.2 MiB for stored data (1.1 MiB counted).

RAR's bound is far above what a thread holds for most archives: `tests/memory_limits.rs` measures 1.2 to 1.5 MiB a thread for LZ (9 MiB counted for RAR 5's, 274 MiB for RAR 4's, which counts PPMd's model each could take), and 16 MiB a thread for RAR 4's PPMd, where a stream asks for a model of 16 MiB. What a stream asks of PPMd is in its data, not in the headers the threads are chosen by.

## What is not counted

- The caller's data and buffers: what is given to a coder, and the buffer it writes into.
- The threads' stacks, which the system maps (2 MiB of address space for each of Rust's threads, of which a few KiB are touched).
- The list of files of an archive being written, and its header, as above.
- A zstd context's own tables, kept from frames without workers before, as libzstd keeps them; and dictionaries.

## How it is shown

`tests/memory_limits.rs` counts what is allocated, with an allocator that hands each call to the system's and keeps the most held at once (the one `unsafe` of the tests, outside the library). For each coder, data that compresses about as text does, enough for every thread to have work and some to wait, goes through it, and what it held at most must be no more than its estimate, and the estimate no more than twice it. Under a limit, the threads are lowered, what is written is the same as with one thread, and what is held is within the limit; a limit below one thread's estimate takes one. Data that does not compress, whose output grows, fits its room too. The default run takes the small presets and levels; `cargo test --release -p hivepack --test memory_limits -- --ignored --nocapture` takes the rest, up to 13 GB at once and 20 minutes on a machine of 32 threads, and prints what each held at most and its estimate, in MiB (November 2026):

| Coder | Threads | Held | Estimated | Estimate / held |
|---|---|---|---|---|
| 7z, LZMA2 preset 1, blocks of 4 MiB | 1 | 20.5 | 21.7 | 1.06 |
| | 4 | 69.7 | 71.5 | 1.03 |
| | 16 | 266.4 | 270.6 | 1.02 |
| 7z, LZMA2 preset 6, blocks of 32 MiB | 1 | 189.1 | 190.2 | 1.01 |
| | 4 | 660.4 | 661.5 | 1.00 |
| | 16 | 2,545.2 | 2,546.7 | 1.00 |
| 7z, LZMA2 preset 9, blocks of 256 MiB | 1 | 1,441.2 | 1,442.2 | 1.00 |
| | 4 | 4,996.5 | 4,997.6 | 1.00 |
| 7z, LZMA2 preset 9, blocks of 64 MiB | 16 | 12,881.2 | 12,882.7 | 1.00 |
| zstd level 3 | none | 3.5 | 4.5 | 1.29 |
| | 1 | 42.1 | 69.4 | 1.65 |
| | 4 | 126.8 | 157.0 | 1.24 |
| | 16 | 433.3 | 571.9 | 1.32 |
| zstd level 19 | none | 89.5 | 90.5 | 1.01 |
| | 1 | 265.6 | 372.9 | 1.40 |
| | 4 | 854.2 | 964.4 | 1.13 |
| | 16 | 3,047.9 | 3,587.8 | 1.18 |
| zstd level 3, long distance matching, window of 16 MiB | 4 | 69.9 | 122.3 | 1.75 |
| bzip2 level 9 | 1 | 15.8 | 18.4 | 1.17 |
| | 4 | 64.8 | 65.8 | 1.02 |
| | 16 | 254.1 | 255.1 | 1.00 |
| bzip2 read by `Opener` | 4 | 23.4 | 97.0 | 4.15 |
| | 16 | 91.9 | 349.0 | 3.80 |

7z and bzip2 hold what they are counted to hold, each buffer at its size: their estimates are a megabyte over, the slack for the writer's own. zstd's are further over with few workers, as its job table has room for more jobs waiting to be written out than a caller that writes out all it is given lets wait; and long distance matching counts room for its window that it only takes over a long input. bzip2's reader is counted for pieces of 2 MiB that decode to 4 MiB, the most its threads take, where `CompressMt`'s are a quarter of that: it is checked to hold no more, not to be near it.

## Measuring what is available

`hivepack::memory`, behind the feature `memory`, off by default, tells how much memory the program may still take now: `memory::available()` gives the bytes, and which bound applied (`Bound::System`, `Bound::ControlGroup`, `Bound::Ulimit`, `Bound::JobObject`), so that an application can say why it took fewer threads or a lower level. It is the least of what the system has free and of what each limit put on the program leaves it, measured each time it is called: a few files read on Linux, two or three calls elsewhere.

| System | Bound | What is read | What it counts |
|---|---|---|---|
| Linux | `System` | `MemAvailable` in `/proc/meminfo` | Free memory, and the page cache and other memory the kernel gives back without swapping |
| Linux | `ControlGroup` | `/proc/self/cgroup`. Version 2 (`0::/path`): each group from `/sys/fs/cgroup/path` up to `/sys/fs/cgroup` whose `memory.max` is not `max`. Version 1 (the line of the `memory` controller): each group from `/sys/fs/cgroup/memory/path` up, whose `memory.limit_in_bytes` there is | The least, of each group, of its limit less what it holds: `memory.current` (version 1: `memory.usage_in_bytes`) less its file pages not in use, `inactive_file` in `memory.stat` (`total_inactive_file`), which the kernel drops before it refuses memory, as container runtimes count a working set |
| Linux | `Ulimit` | `getrlimit` of `RLIMIT_AS` (`ulimit -v`) and `RLIMIT_DATA` (`ulimit -d`), through rustix; `VmSize` and `VmData` in `/proc/self/status` | Each limit less what the program holds of it |
| Windows | `System` | `GlobalMemoryStatusEx`: `ullAvailPhys` | Physical memory free, and on the standby list |
| Windows | `JobObject` | `IsProcessInJob`; `QueryInformationJobObject` of the program's job, `JobObjectExtendedLimitInformation`; `GetProcessMemoryInfo`'s `PrivateUsage` | With `JOB_OBJECT_LIMIT_PROCESS_MEMORY`, `ProcessMemoryLimit` less what the process has committed; with `JOB_OBJECT_LIMIT_JOB_MEMORY`, `JobMemoryLimit` less `PeakJobMemoryUsed`, the most the job's processes have committed at once, no less than what they hold |
| macOS | `System` | `host_statistics64(HOST_VM_INFO64)` and the page size | Pages free (speculative ones among them), holding files' data (`external_page_count`) and purgeable, as Activity Monitor counts the memory not used. Apps' inactive pages are not counted: to take them the system compresses or swaps them |

The control groups are read from the program's own group up, not at the root alone: systemd puts its limits on slices and scopes (a user's slice, `systemd-run --scope -p MemoryMax=600M`), which the root does not show, where a container's runtime puts its limit on the container's root. A path the program's `/proc/self/cgroup` gives that is not under `/sys/fs/cgroup`, as in a container without a cgroup namespace, is walked up until it is: the container's own limit is at its root. A path outside the program's namespace (`/../..`) leaves only the root to read.

Under `ulimit -v`, each thread takes address space besides what it allocates: its stack, 2 MiB for Rust's threads, and the arena glibc's allocator may reserve for it, 64 MiB on 64-bit systems (1 MiB on 32-bit ones, none with musl). `Available::thread_overhead` says so, 66 MiB there; under `ulimit -d` alone, 2 MiB, the stack, which is mapped writable; 0 elsewhere, where what a thread does not touch costs nothing. `Budget::of_available` counts it for each thread.

What is not measured:

- On Linux: `memory.high`, which slows a group down rather than refusing it memory; swap, in `memory.swap.max` and beside `MemAvailable`; the commit limit of `vm.overcommit_memory = 2` (`CommitLimit` less `Committed_AS`); and groups above the program's cgroup namespace, which it cannot see.
- On Windows: the jobs that the program's job is in, as Windows tells only the program's own (nested jobs), and the commit limit, the page file.
- On macOS, no limit applies: the figure is how much the program can take without making the system compress or swap, not a limit, and the program goes on past it, slower.
- Other systems (the BSDs, illumos, Android): `available()` is `None`.
- Memory the program has freed may stay with its allocator: it is not counted as available again until the allocator gives it back.

hivepack does not depend on `sysinfo`, which packwing used for the system's figure: it reads much more than this needs, with `unsafe` code of its own on each system, and it reads only the root control group's limit, which misses systemd's: pkw was killed by the OOM killer in `systemd-run --user --scope -p MemoryMax=600M`, its threads chosen for the machine's free memory. The figures here are a few files on Linux, and two system calls on Windows and macOS: in `src/memory/windows.rs` and `src/memory/macos.rs`, the only `unsafe` code of the module, each call with what makes it sound ([unsafe.md](unsafe.md)).

### A budget for the jobs

`memory::Budget` shares memory between the jobs that run at once, as an application chooses: `Budget::new(bytes)`, or `Budget::of_available(1, 2)` for half of what is available now. Each job asks `budget.hold_threads(wanted, need)` for the most threads, `wanted` or fewer, whose memory, `need(n)` (a coder's estimate) with each thread's overhead, fits what is left, and holds that memory until the `Held` it gets is dropped. One thread is always given, holding what it needs even where that is more than is left, as each coder allows one under its limit; `budget.left()` tells beforehand, for an application that would rather wait or lower a level. A budget's clones share one account, so it can be handed to each job, or kept in a `static`. `Budget::set_bytes` measures it again for a program that lasts, keeping what is held.

What a job holds is counted until it is done, and what it has taken is also no longer available, so jobs that start while others run get fewer threads than they could, never too many. The rest is the application's to choose, and not in the API: how much of what is available it gives its jobs (packwing half, so that what else it does, and other programs, have room), the least it gives them on a busy system (packwing 64 MiB), a variable that sets the figure (packwing's `PACKWING_MEMORY`, for `Budget::new`), and what to do where one thread does not fit.

## Wiring it to the coders

Each coder that uses threads takes the threads held, and the bytes held as its limit where it has one. A level whose one thread does not fit is the application's to lower, as packwing does, and say so; or to keep, with one thread past the budget. This is `tests/memory_wiring.rs`, which CI builds and runs; each function returns the `Held` beside its coder, for the job to keep until the coder is done:

```rust
use std::io::{self, Read, Seek, Write};

use hivepack::Threads;
use hivepack::memory::{Budget, Held};
use hivepack::{bzip2, open, sevenz, xz, zip, zstd};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// What the application gives its jobs, between them: half of what is
/// available now, as packwing does, or 1 GiB where it is not measured.
fn budget() -> Budget {
    Budget::of_available(1, 2).unwrap_or_else(|| Budget::new(1 << 30))
}

/// 7z with LZMA2 in blocks, in the most threads, `wanted` or fewer, that
/// fit. An estimate that fails is of options the writer refuses: counted
/// as too much, it gives one thread, and the writer tells the error.
fn sevenz_writer<W: Write + Seek>(
    out: W,
    budget: &Budget,
    preset: u32,
    wanted: u32,
) -> Result<(sevenz::Writer<W>, Held)> {
    let mut options = sevenz::WriteOptions {
        method: sevenz::Method::Lzma2 { preset },
        lzma2_blocks: sevenz::Lzma2Blocks::Auto,
        ..Default::default()
    };
    let (threads, held) =
        budget.hold_threads(wanted, |n| options.memory_usage(n).unwrap_or(u64::MAX));
    options.threads = Threads::of(threads);
    options.memory_limit = held.bytes();
    Ok((sevenz::Writer::with_options(out, options)?, held))
}

/// zstd with workers: each frame takes the workers held, fewer where it
/// would take more than the limit (a frame of another size).
fn zstd_cctx(budget: &Budget, level: i32, wanted: u32) -> Result<(zstd::CCtx, Held)> {
    let mut cctx = zstd::CCtx::new();
    cctx.set_parameter(zstd::CParameter::CompressionLevel(level))?;
    let (workers, held) =
        budget.hold_threads(wanted, |n| cctx.estimate_memory(n).unwrap_or(u64::MAX));
    cctx.set_parameter(zstd::CParameter::NbWorkers(workers))?;
    cctx.set_workers_memory_limit(held.bytes());
    Ok((cctx, held))
}

/// bzip2 in threads, as pbzip2 compresses.
fn bzip2_compressor(budget: &Budget, level: i32, wanted: u32) -> Result<(bzip2::CompressMt, Held)> {
    let mut options = bzip2::MtOptions {
        block_size_100k: level,
        ..Default::default()
    };
    let (threads, held) =
        budget.hold_threads(wanted, |n| options.memory_usage(n).unwrap_or(u64::MAX));
    options.threads = Threads::of(threads);
    options.memory_limit = held.bytes();
    Ok((bzip2::CompressMt::with_options(&options)?, held))
}

/// xz in threads: liblzma's encoder has no limit of its own, so the
/// threads held are all it is told.
fn xz_encoder(budget: &Budget, preset: u32, wanted: u32) -> Result<(xz::Stream, Held)> {
    let mut options = xz::MtOptions {
        preset,
        ..Default::default()
    };
    let (threads, held) = budget.hold_threads(wanted, |n| {
        xz::stream_encoder_mt_memusage(&xz::MtOptions {
            threads: n,
            ..options.clone()
        })
    });
    options.threads = threads;
    Ok((xz::Stream::stream_encoder_mt(&options)?, held))
}

/// What each thread of `zip::Archive::set_threads` takes: up to 32 MiB of
/// entries compressed ahead, waiting to be written, and its compressor:
/// Deflate's, 512 KiB at most (bzip2's 7 MiB, LZMA's and XZ's 94 MiB at
/// preset 6). ZIP's threads take no limit: the threads are all it is told.
fn zip_threads<R>(archive: &mut zip::Archive<R>, budget: &Budget, wanted: u32) -> Held {
    let (threads, held) =
        budget.hold_threads(wanted, |n| u64::from(n) * ((32 << 20) + (512 << 10)));
    archive.set_threads(Threads::of(threads));
    held
}

/// Reading through `open::Opener`, bzip2 in threads: 20.5 MiB a thread, and
/// 13 MiB (`docs/memory.md`, "Readers"). xz's threads are bounded by
/// `Limits::xz_memlimit`, which is also the most one Block may take before
/// it fails: it is left as it is.
fn opener<F, R>(open: F, budget: &Budget, wanted: u32) -> (open::Opener<F>, Held)
where
    F: FnMut() -> io::Result<R>,
    R: Read + Send,
{
    let (threads, held) = budget.hold_threads(wanted, |n| u64::from(n) * (41 << 19) + (13 << 20));
    let mut limits = open::Limits::default();
    limits.bzip2_memlimit = held.bytes();
    let opener = open::Opener::new(open)
        .threads(Threads::of(threads))
        .limits(limits);
    (opener, held)
}

/// The preset of 7z's LZMA2 in blocks to compress with: `preset`, or the
/// highest below it whose one thread fits what is left, as packwing lowers
/// a level the machine has no room for, and says so. `None` where not even
/// preset 0 fits: the application may wait for other jobs to end, refuse,
/// or go on past the budget with one thread.
fn sevenz_preset_that_fits(budget: &Budget, preset: u32) -> Option<u32> {
    (0..=preset).rev().find(|&preset| {
        let options = sevenz::WriteOptions {
            method: sevenz::Method::Lzma2 { preset },
            lzma2_blocks: sevenz::Lzma2Blocks::Auto,
            ..Default::default()
        };
        options
            .memory_usage(1)
            .is_ok_and(|one| one <= budget.left())
    })
}

/// A job: `data` in a 7z archive, at preset 9 or the highest that fits,
/// and said so, in as many threads as the machine runs at once, or as fit.
/// What it holds is given back when it ends, for the jobs after it.
fn compress_job<W: Write + Seek>(budget: &Budget, out: W, name: &str, data: &[u8]) -> Result<W> {
    let preset = match sevenz_preset_that_fits(budget, 9) {
        Some(9) => 9,
        Some(lower) => {
            eprintln!("{name}: preset 9 does not fit in the memory left: made at preset {lower}");
            lower
        }
        // Not even preset 0 fits: the least there is, past the budget.
        None => 0,
    };
    let (mut writer, _held) = sevenz_writer(out, budget, preset, Threads::Auto.count())?;
    writer.start_file(sevenz::NewEntry::new(name))?;
    writer.write_all(data)?;
    Ok(writer.finish()?)
}
```
