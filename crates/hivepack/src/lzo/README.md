# hivepack::lzo

LZO1X decompression in safe Rust, ported from [lzokay](https://github.com/jackoalan/lzokay)'s decompressor (commit `db2df1f`; lzokay has no releases), with the results of liblzo2 2.10's `lzo1x_decompress_safe`: the decoder SquashFS calls on each block of an image made with `-comp lzo`.

> **Status:** decodes LZO1X blocks with liblzo2's results: the same bytes on every stream liblzo2's compressors make (`lzo1x_1` and its forms, `lzo1x_999` at every level), and on damaged ones the same error, with the same bytes left in the output and nothing written past them. Decompression only, of raw blocks: no compression, no `.lzo` files. 1.48× liblzo2's speed on average on `lzo1x_1`'s blocks of the Silesia corpus, and 1.32× on `lzo1x_999`'s (0.97× at worst).

```rust
// "hello" six times, between commas, as lzo1x_999_compress makes it.
let block = [
    0x18, b'h', b'e', b'l', b'l', b'o', b',', b' ', 0x3f, 0x19, 0x00, b'\n',
    0x11, 0x00, 0x00,
];
let mut text = [0; 64];
let len = hivepack::lzo::decompress(&block, &mut text)?;
assert_eq!(&text[..len], b"hello, hello, hello, hello, hello, hello\n");
# Ok::<(), hivepack::lzo::Error>(())
```

`decompress(input, output)` returns the number of bytes written, or an `Error` that says why it failed, liblzo2's `LZO_E_*`: the input ends too soon (`InputOverrun`), the output is too small (`OutputOverrun`), a match refers to before the start of the output (`LookbehindOverrun`), or bytes follow the end-of-stream marker (`InputNotConsumed`). It never panics, whatever the input.

The goals:

- **No unsafe code.** The module forbids it; see [docs/safety.md](../../../../docs/safety.md).
- **The same results as liblzo2's safe decoder**, where lzokay's differ (the order of its checks, the end-of-stream marker, and a read past the input on some damaged streams).
- **At least liblzo2's speed.**

How the port follows lzokay, where lzokay and liblzo2 differ, how it is checked, and the speed are in [docs/lzo.md](../../../../docs/lzo.md).

## Speed

Against liblzo2 2.10's `lzo1x_decompress_safe`, with `tools/lzo-bench`, on the 12 Silesia files compressed in SquashFS's blocks of 128 KiB. Above 1× the port is faster.

| Compressor | Mean | Range |
|---|---|---|
| `lzo1x_1` | 1.48× | 1.11–1.63× |
| `lzo1x_999` (`mksquashfs -comp lzo`'s default) | 1.32× | 0.97–1.53× |

**Measured on:** AMD Ryzen 9 9950X (x86-64, Linux), in November 2026, the best of five rounds taken in turn. The port is 1.21–7.49× lzokay on `lzo1x_1`'s blocks and 0.96–1.66× on `lzo1x_999`'s. More is in [docs/lzo.md](../../../../docs/lzo.md#the-speed-target).

## License

The MIT license, lzokay's, the license of the code it is ported from. See [LICENSE](LICENSE). Copyright (c) 2018 Jack Andersen, and (c) 2026 HivePaaS. liblzo2, under the GPL, is only built into the test oracle, `tools/lzo-oracle`, never into the crate.
