# Security policy

hivepack reads files from strangers and extracts them to disk, so a flaw in it can be a security flaw: a file written outside the destination, a limit that does not hold, a panic or a runaway allocation on a crafted input, a signature that checks when it should not.

## Reporting

Please report privately, not in a public issue: use GitHub's "Report a vulnerability" under the repository's Security tab ([hivepaas/hivepack-rs](https://github.com/hivepaas/hivepack-rs/security/advisories/new)).

Say which crate and version, and send the smallest input that shows it. You will get an answer within a week; a fix is released as a patch version, with an advisory, and you are credited if you wish.

## Supported versions

The latest minor release (0.1.x for now).

## Scope

- In scope: every crate in `crates/`.
- `ml-dsa` (in `hivepack-sign`'s hybrid keys) has not been audited independently, as [docs/crypto.md](docs/crypto.md) says; it never signs alone.
- Flaws in the libraries hivepack is ported from belong to them, but tell us too if the port has the same flaw.
