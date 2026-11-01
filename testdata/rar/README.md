# RAR archives for tools/rar-bench

hivepack never writes RAR. `scripts/make_rar_testdata.py` made these on November 1, 2026 with RARLAB's `rar`, in its trial version: RAR 7.20 for RAR 5, and RAR 6.24 for RAR 4, which RAR 7 no longer writes. Neither program is in this repository.

All hold the same 8.3 MB, made by that script: 6 MB of this repository's own `crates/*/src/*.rs` and `docs/*.md`, each under the license its crate has, in the order `git ls-files` gives, and 2 MB of bytes the script makes. Those with `password` in their name take the password `hivepack`.
