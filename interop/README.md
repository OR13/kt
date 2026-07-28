# interop

Cross-implementation testing between this Rust implementation and the Go ones.
The plan lives in [`../docs/interop.md`](../docs/interop.md); this file is the
contract for the artifacts in here.

```text
go/        separate Go module — links katie. AGPL-3.0.
           cmd/gen     emits vectors for the Rust side to check   (Go -> Rust)
           cmd/verify  checks proofs the Rust side built           (Rust -> Go)
vectors/   committed JSON test vectors. Data, not code.
report/    Rust crate — checks the vectors, emits proofs, renders the evidence page.
```

## Both directions

`docs/interop.md` asks for two directions, and both now run:

| Direction | Producer | Checker | Files |
|---|---|---|---|
| Go → Rust | `interop/go/cmd/gen` | `cargo test` via `kt_interop::check` | `vectors/{commitment,ibst,binary-ladder,log-tree,prefix-tree}.json` |
| Rust → Go | `kt-interop-emit` | `interop/go/cmd/verify` | `vectors/from-kt.json` |

The second is not symmetry for its own sake. Recomputing the peer's values cannot
catch an implementation that is self-consistently wrong, and it cannot catch
**over-acceptance** — a verifier that accepts a proof the peer would reject, which
is precisely how a broken client gets exploited. So half of `from-kt.json` is
deliberately corrupted proofs that katie must reject, including a forged inclusion
result. Our own verifier is asserted to reject each one before it is written, so a
case katie accepts is a real disagreement about validity rather than a broken
fixture.

```sh
cargo run -p kt-interop --bin kt-interop-emit -- --out interop/vectors/from-kt.json
cd interop/go && go run ./cmd/verify -in ../vectors/from-kt.json
```

## The evidence page

[`or13.github.io/kt`](https://or13.github.io/kt/) publishes the results, and
[`report.json`](https://or13.github.io/kt/report.json) is the same thing
machine-readable. Both are rebuilt on every push to `main`.

`report/` is what makes that page trustworthy rather than decorative:

- `kt_interop::check` loads the vectors and compares every case, returning
  results instead of panicking.
- `report/tests/vectors.rs` fails the build if any comparison disagrees, and also
  asserts that the vectors still contain their negative and refusal cases — a file
  that quietly lost them would keep passing while testing much less.
- `kt-interop-report` renders those same results as HTML and JSON, and **exits
  non-zero if anything disagrees**, so a red result cannot be deployed as a green
  page.

One code path, three consumers. The page is the output of `cargo test`, not a
description of it, which is what `AGENTS.md` rule 4 requires: no interop claim
without a vector or a live test behind it.

```sh
cargo test --workspace          # the suite
cargo run -p kt-interop --bin kt-interop-report -- \
  --vectors interop/vectors --out site   # the page, into ./site
```

## Why `go/` is its own module, and AGPL-3.0

The generator imports `github.com/Bren2010/katie`, which is AGPL-3.0. Linking an
AGPL library makes the linking program a derivative work, so **`interop/go/` is
licensed AGPL-3.0** — see [`interop/go/LICENSE`](go/LICENSE).

It is a separate Go module (its own `go.mod`, outside the Cargo workspace) so that
boundary is structural rather than a promise. The Rust crates in `crates/` never
link, import, or build against it; they only read the JSON it writes. Test
vectors are data — facts about what the protocol requires — and carry no license
obligation into `crates/`.

If that reading ever looks shaky, the fallback is to move `go/` to a separate
repository entirely and commit only `vectors/` here. Nothing in the Rust build
depends on `go/`, so that move costs a URL change.

katie is consumed through the pinned submodule, not the network:

```gomod
replace github.com/Bren2010/katie => ../../upstream/katie
```

Bumping the submodule therefore bumps the generator, and regenerated vectors that
differ are a visible diff — which is the point.

## Running the generator

```sh
git submodule update --init                 # katie must be present
cd interop/go && go run ./cmd/gen -out ../vectors
cargo test --workspace                      # Rust asserts against the vectors
```

## Vector format

One JSON file per primitive, named after it (`commitment.json`, `vrf.json`,
`log-tree.json`, …). Every file carries provenance:

```json
{
  "primitive": "commitment",
  "draft": "draft-ietf-keytrans-protocol-05 §11.6",
  "generator": { "impl": "katie", "sha": "00da52541f6ae6a7f3905181e2ba9de8ec0d6cdc" },
  "cipher_suite": 2,
  "cases": [
    {
      "name": "empty-label",
      "input": { "opening": "…", "label": "…", "version": 0, "update": "…" },
      "expect": { "commitment": "…" }
    }
  ]
}
```

Rules:

- All byte strings are lowercase hex, no `0x` prefix.
- `cipher_suite` is the IANA `CipherSuite` value: `1` = `KT_128_SHA256_P256`,
  `2` = `KT_128_SHA256_Ed25519`. It is **omitted** for primitives that do not
  depend on a suite — the implicit binary search tree and the binary ladders are
  integer math with no hash, key, or suite parameter in sight, and a value there
  would only imply otherwise.
- `generator.sha` is the submodule commit the values came from. A vector without
  it cannot be regenerated and is worthless when it fails.
- `name` is stable and unique within the file; it becomes the test identifier.
- Negative cases use `"expect": { "error": true }` — never an error string, since
  error text is implementation-specific and would make the vector untestable
  across implementations.
- Where a case is a table of sub-results rather than one value, an expected
  `null` means **must refuse**: the input has no answer and an implementation that
  produces one is wrong. `ibst.json` uses this for a leaf's child and for the
  rightmost log entry's right child.
- Vectors are deterministic. No randomness at generation time: openings, keys,
  and labels are fixed in the generator so regeneration is a no-op diff and real
  drift stands out.

Where the peer cannot produce a value at all — because it hangs, panics, or
disagrees with the draft — the generator says so in a comment and in the file's
`notes`, and the case is covered by Rust-side tests instead of being quietly
dropped. `binary-ladder.json` stops at version `2^31-2` for exactly that reason.

## Current files

| File | Primitive | Draft | Cases |
|---|---|---|---|
| `commitment.json` | commitment | §11.6 | 6 positive, 1 negative |
| `ibst.json` | implicit binary search tree | §4.1, Appendix A | 38 log sizes |
| `binary-ladder.json` | binary ladder | §5, Appendix B | 76 across base, search, monitoring |
| `vrf.json` | VRF | §11.7 | 10 positive, 1 negative |
| `log-tree.json` | log tree | §3.2, §11.8, §12.1 | 19 sizes, 297 batch proofs |
| `prefix-tree.json` | prefix tree | §3.3, §11.9, §12.2 | 11 trees |
| `tampered.json` | **must reject** | §11.6, §11.7, §12.1, §12.2 | 18, all negative |
| `from-kt.json` | must accept / must reject, in reverse | as above | 201, half negative |

## Asking a verifier to say no

`tampered.json` is the odd one out: one file across four primitives rather than one
per primitive. That is deliberate. Every other file asks "the peer computed this, do
you compute it too?", which a verifier that accepted everything would pass, because
nothing in those files asks it to reject anything. Before `tampered.json` there was
exactly **one** must-reject case in the whole Go → Rust direction, and the reason
nobody noticed is that rejection coverage was scattered across per-primitive files
where its absence looked like nothing at all. One file makes "how many must-reject
cases are there?" a question with an obvious answer.

Each case was built by katie, corrupted in a described way, and then **confirmed
rejected by katie's own verifier** before being written out. That confirmation is
what makes it a shared oracle rather than an opinion: the peer is asserting the proof
is invalid, so a verifier that accepts it is wrong rather than merely different.
`from-kt.json` runs the same idea in the opposite direction. Between them, the two
implementations have to agree about what is *invalid* and not only about what is
valid.

The evidence page reflects this in a **Refuses** column: an area whose only evidence
is a file of values is marked "values only", which is a weaker claim than it looks.
