# Agent guide — kt

Entry contract for any agent working in this repository. Follows the
[AGENTS.md](https://agents.md) standard.

## What this is

A Rust implementation of IETF Key Transparency (`draft-ietf-keytrans-protocol`,
currently -05) built to interoperate byte-for-byte with the Go implementations.
Read [`README.md`](README.md) for the shape, [`docs/interop.md`](docs/interop.md)
for the plan, [`docs/licensing.md`](docs/licensing.md) before you read any Go.

## Hard rules

1. **The draft is normative.** Implement from `upstream/draft-protocol/`. Cite the
   section you implemented: `// draft-ietf-keytrans-protocol-05 §11.6`.
2. **Never port Go into Rust.** `upstream/katie` is AGPL-3.0;
   `upstream/keytrans-verification` has no license at all. Read them to
   understand, run them to compare, but write the Rust from the draft. A
   line-by-line translation would relicense this repository. This is not
   negotiable — see [`docs/licensing.md`](docs/licensing.md).
3. **`upstream/` is read-only.** It is four pinned submodules. Do not commit
   modifications inside them. Bumping a pin is its own commit, with a reason.
4. **No unproven interop claims.** "Interoperates" means there is a vector or a
   live test asserting it. Until then say "implemented, not yet verified against Go."
5. **No `unsafe`, no panics on untrusted input.** This is verification code that
   parses adversary-controlled bytes. Every parse returns `Result`. Indexing and
   arithmetic on wire-derived values must be checked.

## Working here

```sh
git submodule update --init          # first time
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
go -C upstream/katie test ./tree/... ./crypto/...   # the peer's own suite
```

Branch and PR like the rest of the fleet: one kebab-case slug for branch and PR
title, draft PR on first push, merge when green.

## Layout

- `crates/kt-wire` — TLS presentation language + protocol structs (§2.1, §11–§13)
- `crates/kt-crypto` — suites, VRF, commitments, signatures (§11)
- `crates/kt-tree` — log / prefix / combined trees, IBST, ladders (§3–§5, §11.8–§11.9, §12)
- `crates/kt-client` — search, monitor, update, distinguished heads (§4.2, §6–§10, §13)
- `interop/go` — **separate Go module, AGPL-3.0** (it links katie). Emits JSON vectors only.
- `interop/vectors` — committed JSON test vectors, each stamped with its generator's SHA.
- `interop/report` — workspace member `kt-interop`: checks the vectors, and renders
  the evidence page at [or13.github.io/kt](https://or13.github.io/kt/). Not published.
- `upstream/` — pinned submodules: two drafts, two Go implementations.

The vector checks live in `interop/report`, not in the individual crates, because
the published page and the test suite must run the same code. If you add a vector
file, add it to `kt_interop::check::FILES` and to the coverage table in
`kt_interop::report`; a test fails if the table claims evidence that the report
does not contain or that does not pass. Rule 4 is enforced there, not by good
intentions.

Dependency direction is strictly bottom-up; `kt-wire` depends on no other in-tree crate.

## Current state

`docs/interop.md` Tier 1 steps 1, 2, and 6 are done and pinned against the Go
peer: the §2.1 codec, `UpdateValue`/`CommitmentValue` (§11.5, §11.6), the §11.6
commitment, the implicit binary search tree (§4.1), and the binary ladders (§5).
Three vector files — `commitment.json`, `ibst.json`, `binary-ladder.json` — are
generated from the pinned katie, and CI fails if regeneration produces a diff.

`kt-tree::log`, `kt-tree::prefix`, `kt-tree::combined`, `kt-crypto::vrf`,
`kt-crypto::signature`, and all of `kt-client` are still stubs. Next up is the
VRF (§11.7), then the log tree, then the prefix tree — bottom-up, because a
vector for a layer whose foundation disagrees proves nothing.

Verified facts worth not rediscovering:

- katie's library builds and its tests pass; its `cmd/katie-server` is entirely
  `//go:build ignore`'d, so there is no runnable Go server at this pin.
- The draft puts `opening` inside `CommitmentValue`; katie keeps it outside the
  struct and writes it to the HMAC first. Same bytes, different factoring.
  Follow the draft.
- katie's binary ladder does not terminate for a greatest version at or above
  `2^31-1` (`uint32` midpoint overflow), and the draft cannot express the ladder
  for `2^32-1` at all. Both are written up under "Findings" in
  `docs/interop.md`; don't re-derive them, and don't put those inputs in a vector.
- §2.1.2 means *element* counts where RFC 8446 means byte counts. It matters for
  any vector of a type wider than a byte. `kt_wire::codec::VectorSpec` is where
  that lives.
- Appendix A and B are Python: unbounded integers, exceptions for missing cases.
  The Rust equivalents take `u64` indices and `u32` versions and return `Result`.
  Every such deviation is documented at the function that makes it.
