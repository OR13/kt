# interop

Cross-implementation testing between this Rust implementation and the Go ones.
The plan lives in [`../docs/interop.md`](../docs/interop.md); this file is the
contract for the artifacts in here.

```text
go/        separate Go module — links katie, emits vectors. AGPL-3.0.
vectors/   committed JSON test vectors. Data, not code.
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
