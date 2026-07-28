# Interop plan

The point of this repository is not "a Rust KT implementation." It is "a Rust KT
implementation that provably agrees with the Go ones, byte for byte." That
requires a harness, and the harness constrains the design — so it is planned
first.

## What we are interoperating with

**`upstream/katie`** ([Bren2010/katie](https://github.com/Bren2010/katie), pinned at
`00da5254`) is the primary peer. Its library layers map cleanly onto ours:

| katie package | our crate | draft |
|---|---|---|
| `crypto/suites` | `kt-crypto::suite` | §11.1, §17.1 |
| `crypto/commitments` | `kt-crypto::commitment` | §11.6 |
| `crypto/vrf/{edwards25519,p256}` | `kt-crypto::vrf` | §11.7 |
| `tree/log`, `tree/log/math` | `kt-tree::log` | §3.2, §11.8, §12.1 |
| `tree/prefix` | `kt-tree::prefix` | §3.3, §11.9, §12.2 |
| `tree/transparency/math` (ladders, tracker) | `kt-tree::ladder`, `kt-tree::ibst` | §4.1, §5, App. A/B |
| `tree/transparency/structs` | `kt-wire` | §2.1, §11-§13 |
| `tree/transparency/algorithms` | `kt-client` | §6-§10, §13 |
| `tree/transparency/auditor` | `kt-client::auditor` | §15.2 |

**`upstream/keytrans-verification`** ([felixlinker](https://github.com/felixlinker/keytrans-verification),
pinned at `a2c77bff`) is a second, independent Go client whose `pkg/` mirrors the
same primitives and is **Gobra-verified**. Two independent Go implementations to
agree with is strictly better than one: where katie and keytrans-verification
disagree, the draft is ambiguous and that is worth an upstream issue.

Its Gobra specifications are also a source of properties to test, not just
values: preconditions and postconditions on `pkg/trees`, `pkg/proofs`,
`pkg/search` restate the draft's invariants precisely. Restate them as Rust
`proptest` properties (in your own words — see [`licensing.md`](licensing.md)).

## Known blocker: katie has no runnable server

Every file in `upstream/katie/cmd/katie-server/` carries `//go:build ignore`, and
its HTTP dependencies (`gorilla/mux`, Prometheus) are absent from `go.mod`. The
library builds and its tests pass; **the server does not exist as a buildable
artifact.** Verified at pin `00da5254`:

```sh
go -C upstream/katie build ./...          # succeeds — because cmd/ is all ignored
go -C upstream/katie test ./tree/... ./crypto/...   # all pass
```

So live-wire interop over `/v1/meta`, `/v1/consistency/{older}/{newer}`,
`/v1/account/{account}` (the routes `main.go` registers) is **not** available
out of the box. Consequences:

- Tier 1 (vectors, below) is the only interop path that works today. Build it first.
- Tier 2 requires either reviving the server behind a local build tag, or writing
  our own thin Go HTTP shim over `tree/transparency` + `wire.Interface`. Prefer
  the shim: it does not require patching a submodule, and `wire.Interface` is
  explicitly documented upstream as the wire-compatibility seam.
- Worth an upstream question either way — the server may simply be mid-refactor.

## Tier 1 — differential test vectors

Data, not linkage. A Go generator emits JSON; Rust tests assert equality; then the
directions reverse so neither implementation is permanently the oracle.

```text
interop/
  go/            separate Go module (AGPL-3.0, links katie) — emits vectors
  vectors/       committed JSON, each file stamped with the upstream SHA
  README.md      the vector format contract
```

Both directions matter:

1. **Go → Rust.** Go generates inputs + outputs; Rust recomputes and asserts
   byte equality. Catches our misreadings of the draft.
2. **Rust → Go.** Rust generates; the Go harness verifies. Catches cases where we
   are self-consistently wrong, and cases where we accept proofs Go rejects —
   the security-relevant direction, since a client that over-accepts is broken in
   a way that equality-of-happy-path never reveals.

Negative vectors are as important as positive ones: a tampered proof that Go
rejects must be rejected by Rust too, and vice versa.

### Order of attack

Bottom-up, because every later layer's vectors are meaningless if the layer below
disagrees:

| # | Primitive | Vector content | Why first | State |
|---|---|---|---|---|
| 1 | Commitment (§11.6) | `opening`, `label`, `version`, `update` → `commitment` | Pure HMAC-SHA256 over a `CommitmentValue` struct; no tree state. Doubles as the first `kt-wire` encoding test. | **agrees** |
| 2 | Wire codec (§2.1, §11) | struct → hex bytes, both directions | Everything downstream is defined over these bytes. Include the optional-value and variable-length-vector edge cases. | **agrees** for `CommitmentValue`/`UpdateValue`; other structs pending |
| 3 | VRF (§11.7) | key, `VrfInput{label, version}` → proof, output | Must match ECVRF exactly; katie has both suites and its own tests. | todo — next |
| 4 | Log tree (§3.2, §11.8) | leaf sequence → root, inclusion/consistency proofs | katie's `tree/log/math` is a good oracle for node indexing. | **agrees**, both directions |
| 5 | Prefix tree (§3.3, §11.9) | insert sequence → root, membership proofs | The subtlest hashing rules in the draft. | **agrees**, both directions |
| 6 | IBST + ladders (§4.1, §5) | tree size → node sequence; version → ladder | Pure integer math, cheap and high-yield; the draft ships pseudocode in App. A/B. | **agrees** below version `2^31-1`; see the finding below |
| 7 | Combined tree + full head (§3.4, §11.4) | full `FullTreeHead` verification | First point where signatures enter. | todo |
| 8 | Algorithms (§6-§10, §13) | search / monitor / update transcripts | Composite; only meaningful once 1–7 agree. | todo |

Steps 1, 2, 4, 5, and 6 are done. `commitment.json`, `ibst.json`,
`binary-ladder.json`, `log-tree.json`, and `prefix-tree.json` all pass from the
Rust side — 3540 checks — and `from-kt.json` runs the other way: 201 proofs built
by the Rust side, 101 of which katie must accept and 100 of which it must reject.
"Agrees" here means a committed vector asserts it, not that the two
implementations were eyeballed.

The reverse direction earned its keep immediately. It found that §12.1's proofs
carry heads of **balanced** subtrees only: an implementation that hands over the
head of an unbalanced node — the right subtree of a seven-leaf log, or the root of
any log whose size is not a power of two — builds proofs that verify against
themselves and disagree with the peer everywhere. Recomputing katie's values would
have caught it too, but only once proofs were being compared; nothing in the
hashing rules of §11.8 says it.

### Findings from steps 1, 2, and 6

Recorded here rather than rediscovered, and each is worth an upstream report.

**katie's binary ladder does not terminate for versions at or above `2^31-1`.**
`tree/transparency/math.baseBinaryLadder` computes in `uint32` and takes the
binary-search midpoint as `(lower + upper) / 2`. Once that sum passes `MaxUint32`
it wraps, the midpoint lands *below* the lower bound, and the loop walks away from
its own interval, appending rungs until the process is killed. The first affected
greatest-version is `2^31-1`, where the upper bound becomes `2^32-1`; verified at
pin `00da5254`, where `2^31-2` returns a 62-rung ladder and `2^31-1` is OOM-killed.
Separately, at `MaxUint32` the powers-of-two phase spins on its own, because
`uint32(1) << 32` is 0 in Go and the rung wraps back to `MaxUint32`. A client's
`n` comes from what the log proves to it, so a log picks this value — which makes
it a remote hang, not just a robustness nit. Consequence for us:
`binary-ladder.json` stops at `2^31-2`, and the range above it is covered by
Rust-side tests.

**A greatest version of `2^32-1` cannot be proven at all.** Appendix B is Python,
so the ladder for `n = 2^32-1` contains `2^33-1`; on the wire a version is a
`uint32` (§11.7), so that lookup does not exist. Establishing `2^32-1` as the
greatest version requires a non-inclusion proof for version `2^32`, which is
unrepresentable. `kt-tree::ladder` reports this rather than truncating. This is a
draft-level gap: either the version space needs to exclude its own maximum, or
Appendix B needs to say what happens there.

**katie's search ladder is indexed on the target, Appendix B's on the greatest
version — and they agree anyway.** draft-05's `search_binary_ladder` iterates
`base_binary_ladder(n)`; katie iterates `baseBinaryLadder(t)`. The outputs are
identical, because the two base ladders agree rung by rung until the first rung
where a comparison against `n` differs from one against `t` — i.e. the first rung
in `(min(t,n), max(t,n)]` — and that is exactly Appendix B's `would_end`
condition, which both variants include before stopping. The generator checks this
over a 131×131 grid at generation time and refuses to emit vectors if it ever
fails, and `kt-tree` asserts it again from the Rust side. So katie-generated
ladder vectors are a valid oracle for a draft-shaped implementation.

**katie's monitoring ladder predates draft-05's deduplication parameter.**
Appendix B's `monitoring_binary_ladder(t, left_inclusion)` drops lookups already
proven to the left; katie's `MonitoringBinaryLadder(t)` takes only `t`. Monitoring
vectors are therefore emitted with an empty set only, and the deduplication is
covered by Rust-side tests. Not a disagreement, just a pin that is behind.

**§12.2 leaves two things implicit about prefix proofs.** First, what `depth`
counts for a `nonInclusionParent` result: §12.2 calls the terminal node "a parent
node that lacks the desired child" and says `depth` is "the depth of the terminal
node", and those give numbers one apart. katie counts the bits consumed to reach
the *absent child slot*, which is one below the parent, and which makes `depth`
mean the same thing for all three result types. Second, whether that absent slot
consumes an element of `elements`: it does not — the result type already says it is
empty — while a copath sibling that happens not to exist does consume one, listed
as all-zero per §12.2's own sentence. Both readings are now pinned by
`prefix-tree.json`; both are worth an upstream question, since a second
implementation reading them the other way would be silently incompatible.

**`opening` sits in a different place in the two implementations.** The draft puts
`opaque opening[Nc]` inside `CommitmentValue`; katie keeps it outside the struct
and writes it to the HMAC first. Same bytes, different factoring — the vectors
record the full `CommitmentValue` encoding as well as the commitment, so both
halves are pinned.

### Vector format contract

One JSON file per primitive. Every file records provenance so a vector can be
regenerated and a mismatch can be blamed:

```json
{
  "primitive": "commitment",
  "draft": "draft-ietf-keytrans-protocol-05 §11.6",
  "generator": { "impl": "katie", "sha": "00da52541f6ae6a7f3905181e2ba9de8ec0d6cdc" },
  "cipher_suite": 2,
  "cases": [
    {
      "name": "empty-label",
      "input": { "opening": "hex…", "label": "hex…", "version": 0, "update": "hex…" },
      "expect": { "commitment": "hex…" }
    }
  ]
}
```

Rules: all byte strings hex-encoded lowercase; `cipher_suite` is the IANA
`CipherSuite` value (`1` = P-256, `2` = Ed25519); every case has a stable `name`
usable as a test identifier; negative cases carry `"expect": {"error": true}`
rather than an error string, since error text is implementation-specific.

## Tier 2 — live wire

Once Tier 1 is green through step 7:

1. Stand up a Go HTTP shim over katie's `wire.Interface` (see blocker above).
2. Drive it with `kt-client`: search, contact-monitor, owner-init, owner-monitor,
   update. Assert the Rust client verifies every proof.
3. Reverse it: serve from Rust, drive with katie's Go client
   (`tree/transparency/client.go`) and with `keytrans-verification`'s client.
4. Fork detection (§10.2, and §14.2.1 for provisional credentials) is the interesting adversarial case — have the
   Rust server deliberately equivocate and confirm the Go clients catch it.

CI runs Tier 1 on every push (Go and Rust toolchains, vectors regenerated and
diffed so a silent upstream drift fails loudly). Tier 2 runs on demand until it
is stable.

## Reporting upstream

Interop work finds spec bugs; that is the most valuable output here. Draft issues
go to [ietf-wg-keytrans/draft-protocol](https://github.com/ietf-wg-keytrans/draft-protocol/issues).
Implementation disagreements go to the respective repository. Record every
resolved ambiguity as a comment in the Rust code citing the issue, so the next
reader does not re-derive it.
