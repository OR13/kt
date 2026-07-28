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
- `upstream/` — pinned submodules: two drafts, two Go implementations.

Dependency direction is strictly bottom-up; `kt-wire` depends on no other in-tree crate.

## Current state

The Rust crates compile and are empty. The interop pipeline works end to end:
`interop/go/cmd/gen` emits `interop/vectors/commitment.json` (§11.6) from the
pinned katie, and CI fails if regeneration produces a diff.

The first real work is the Rust side of `docs/interop.md` Tier 1 steps 1, 2, and
6 — commitment, wire codec, and the integer math for the implicit binary search
tree and binary ladders. Each is self-contained and each is a prerequisite for
everything above it. Step 1 already has its vectors waiting.

Verified facts worth not rediscovering:

- katie's library builds and its tests pass; its `cmd/katie-server` is entirely
  `//go:build ignore`'d, so there is no runnable Go server at this pin.
- The draft puts `opening` inside `CommitmentValue`; katie keeps it outside the
  struct and writes it to the HMAC first. Same bytes, different factoring.
  Follow the draft.
