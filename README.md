# kt — a Rust implementation of IETF Key Transparency

A Rust implementation of the IETF KEYTRANS protocol, built to **interoperate
byte-for-byte with the existing Go implementations**.

The specification is normative; the Go implementations are the interop peers.
Where this repository and the drafts disagree, the drafts win — and the
disagreement is a bug report, either against this code or against the draft.

## Goal

1. **Correct** — implement `draft-ietf-keytrans-protocol` (currently -05) and the
   architecture in `draft-ietf-keytrans-architecture`.
2. **Interoperable** — produce and consume the same bytes as
   [`Bren2010/katie`](https://github.com/Bren2010/katie): same tree hashes, same
   VRF outputs, same commitments, same TLS-presentation-language encodings, same
   proofs. A Rust client must verify proofs from a Go server, and a Go client
   must verify proofs from a Rust server.
3. **Verifiable** — stay aligned with
   [`felixlinker/keytrans-verification`](https://github.com/felixlinker/keytrans-verification),
   the Gobra security proof of the client. Its invariants are free test oracles.

## Upstreams

Pinned as git submodules under `upstream/` — read as specification and used as
interop peers, never copied into `crates/` (see [`docs/licensing.md`](docs/licensing.md)).

| Path | Upstream | What it is | License |
|---|---|---|---|
| `upstream/draft-protocol` | [ietf-wg-keytrans/draft-protocol](https://github.com/ietf-wg-keytrans/draft-protocol) | `draft-ietf-keytrans-protocol` — the normative wire protocol | IETF Trust (BSD for code) |
| `upstream/draft-arch` | [ietf-wg-keytrans/draft-arch](https://github.com/ietf-wg-keytrans/draft-arch) | `draft-ietf-keytrans-architecture` — deployment models, threat model | IETF Trust (BSD for code) |
| `upstream/katie` | [Bren2010/katie](https://github.com/Bren2010/katie) | Go transparency log — trees, crypto, client, auditor; the primary interop peer. Library only at this pin; its server is build-ignored | **AGPL-3.0** |
| `upstream/keytrans-verification` | [felixlinker/keytrans-verification](https://github.com/felixlinker/keytrans-verification) | Gobra-verified Go client; the formal-proof reference | unlicensed (all rights reserved) |

```sh
git clone --recurse-submodules https://github.com/OR13/kt.git
# or, in an existing clone:
git submodule update --init
```

Bump an upstream deliberately, never incidentally:

```sh
git -C upstream/katie fetch && git -C upstream/katie checkout <sha>
git add upstream/katie && git commit -m "upstream: bump katie to <sha>"
```

## Layout

```text
crates/
  kt-wire/     TLS presentation language codec + protocol structs   (draft §2.1, §11-§13)
  kt-crypto/   cipher suites, VRF, commitments, tree-head signature (draft §11)
  kt-tree/     log tree, prefix tree, combined tree, binary ladder  (draft §3-§5, §11.8-§11.9, §12)
  kt-client/   search / monitor / update / distinguished heads       (draft §4.2, §6-§10, §13)
interop/       cross-implementation test-vector harness (Go generates, Rust verifies, and back)
upstream/      pinned submodules — spec + interop peers, read-only
docs/          interop plan, licensing boundary
```

Crates are layered bottom-up: `kt-wire` depends on nothing in-tree, `kt-crypto`
on `kt-wire`, `kt-tree` on both, `kt-client` on all three.

## Build

```sh
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

## Interop

The interop strategy — differential test vectors first, live wire second — is in
[`docs/interop.md`](docs/interop.md). Short version:

- **Tier 1, vectors.** Go emits JSON vectors for each primitive (commitment, VRF,
  log/prefix tree roots, proofs, encoded structs); Rust asserts equality. Then
  the reverse direction, so neither side is only ever the oracle.
- **Tier 2, live.** Drive a Go server with the Rust client over HTTP, then serve
  from Rust and drive it with katie's Go client. Note the blocker: at the current
  pin, katie's `cmd/katie-server` is entirely `//go:build ignore`'d and its HTTP
  dependencies are missing from `go.mod`, so a Go server has to be stood up over
  katie's `wire.Interface` first.

## Cipher suites

Both registered suites use SHA-256, `Nc = 16`, and
`Kc = d821f8790d97709796b4d7903357c3f5`:

| Value | Name | Signature | VRF |
|---|---|---|---|
| `0x0001` | `KT_128_SHA256_P256` | ECDSA / P-256 | ECVRF-P256-SHA256-TAI |
| `0x0002` | `KT_128_SHA256_Ed25519` | Ed25519 | ECVRF-EDWARDS25519-SHA512-TAI |

`KT_128_SHA256_Ed25519` is the first target: katie implements both, and Ed25519
has fewer encoding traps.

## Status

Scaffolding plus a working interop pipeline. No Rust protocol logic yet — the
crates exist to fix the module boundaries and the draft-section mapping.

What does work: `interop/go/cmd/gen` generates
[`interop/vectors/commitment.json`](interop/vectors/commitment.json) — 6 positive
and 1 negative case for the §11.6 commitment — from the pinned katie. Those
values were independently re-derived from the draft's own `CommitmentValue`
definition, so katie and the draft agree here and the Rust side has a
trustworthy first target. CI regenerates the vectors and fails on any diff.

Next: the same treatment for the wire codec (§2.1) and the integer math for the
implicit binary search tree and binary ladders (§4.1, §5) — both self-contained,
both prerequisites for everything above them.

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your
option — the Rust ecosystem default. This choice is only defensible if the
AGPL boundary in [`docs/licensing.md`](docs/licensing.md) is respected.
