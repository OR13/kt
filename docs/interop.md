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
| 3 | VRF (§11.7) | key, `VrfInput{label, version}` → proof, output | Must match ECVRF exactly; katie has both suites and its own tests. | **agrees** for Ed25519, against RFC 9381 *and* katie; P-256 todo |
| 4 | Log tree (§3.2, §11.8) | leaf sequence → root, inclusion/consistency proofs | katie's `tree/log/math` is a good oracle for node indexing. | **agrees**, both directions |
| 5 | Prefix tree (§3.3, §11.9) | insert sequence → root, membership proofs | The subtlest hashing rules in the draft. | **agrees**, both directions |
| 6 | IBST + ladders (§4.1, §5) | tree size → node sequence; version → ladder | Pure integer math, cheap and high-yield; the draft ships pseudocode in App. A/B. | **agrees** below version `2^31-1`; see the finding below |
| 7 | Combined tree + full head (§3.4, §11.4) | full `FullTreeHead` verification | First point where signatures enter. | signatures **agree** (§11.2–§11.4); combined tree todo |
| 8 | Algorithms (§6-§10, §13) | search / monitor / update transcripts | Composite; only meaningful once 1–7 agree. | todo |
| 9 | Auditing (§15.2) | `AuditorUpdate` bytes; before/after prefix roots; accept-or-reject; the log root signed | Sits on the prefix tree, and the auditor is the one role whose whole job is a verdict. | **agrees** on all 12 verdicts, every encoding, and every log root; three divergences recorded, see below |

Steps 1 through 6 are done, along with step 9 and the signature half of step 7.
Fourteen vector files pass from the Rust side — 6255 checks across 660 cases — and
`from-kt.json` runs the other way: 209 artifacts built by the Rust side, 109 of which
katie must accept and 100 of which it must reject. "Agrees" here means a committed
vector asserts it, not that the two implementations were eyeballed.

The reverse direction earned its keep immediately. It found that §12.1's proofs
carry heads of **balanced** subtrees only: an implementation that hands over the
head of an unbalanced node — the right subtree of a seven-leaf log, or the root of
any log whose size is not a power of two — builds proofs that verify against
themselves and disagree with the peer everywhere. Recomputing katie's values would
have caught it too, but only once proofs were being compared; nothing in the
hashing rules of §11.8 says it.

### Two ways to reach the same root

`log-append.json` exists because an auditor computes a root nobody else computes the same
way. A prover holds every leaf and hashes the tree top-down. An auditor holds none: its
whole view of the log tree is the head values of the current tree's full subtrees —
`popcount(size)` hashes, under 64 for any log that can exist — and it grows them one entry
at a time, folding them bottom-up when it needs a root. The two computations meet only at
§11.8's `hashContent` rule.

That is exactly the shape of bug the reverse direction caught in §12.1: agreement at every
size someone tested, divergence at the next. So the file sweeps 64 sizes and checks three
things at each — the heads after the append, the root they fold to, and the same root
computed from every leaf instead. The head count is asserted against the population count
of the size in the generator, since each merge is a carry and getting that wrong is how the
shape drifts. The two implementations arrive differently: katie indexes a chain by level
and propagates a carry, `kt-tree::log` keeps subtree lengths beside their heads and merges
the rightmost pair while the lengths match.

### §4.2 can leave a user checking nothing at all

Implementing §4.2's update-view procedure turned up a hole, and `update-view.json`
records the Go peer reproducing it, which is what makes it the procedure's behaviour
rather than either implementation's.

The procedure starts from "the direct path of the log entry with index `size-1`, where
`size` is the tree size advertised by the user", and keeps the entries at or beyond
`size`. When the user's previous rightmost entry is still on the *new* tree's
frontier, every one of its ancestors is smaller than it — a frontier node is only ever
reached by turning left from above — so the filter removes the entire direct path.
There is then nothing to start the frontier walk from, and the user is sent **no
timestamps at all**, despite the log having grown.

For a log of 1000 entries, the advertised sizes affected are 512, 768, 896, 960, and
992: the frontier shifted by one. Those are not obscure values — a user's advertised
size is one they were handed by an earlier response, and the frontier is exactly where
retained rightmost entries sit.

What the user then fails to check is everything §4.2 exists for: the timestamps of the
entries added since, the monotonic series they are meant to form, and the `max_ahead` /
`max_behind` clock bounds, which are checked against the rightmost entry's timestamp —
the one they are never given. `katie`'s `UpdateView(12, 8)` is empty too.

`kt-tree::ibst::leaves_right_edge_unchecked` reports the condition so a client can
refuse rather than read an empty response as "nothing to verify". Worth an upstream
issue: either the procedure needs to fall back to the frontier when the direct path
filters away, or §4.2 needs to say why the rightmost timestamp does not have to be
checked in that case.

### The two Go implementations disagree about §11.2

The most consequential finding so far, and the one that needed both peers to see.
§11.2 writes `Configuration`'s mode-dependent part as grouped cases:

```tls-presentation
select (Configuration.mode) {
  case contactMonitoring:
  case thirdPartyManagement:
    opaque leaf_public_key<0..2^16-1>;
```

On the C-derived reading the presentation language inherits, `leaf_public_key` is
present in **both** modes. `katie` emits it only under `thirdPartyManagement`.
`keytrans-verification`'s `Configuration` annotates the field "Only for Contact
monitoring or ThirdParty" — the other reading. So the two independent Go
implementations have taken opposite positions.

It is not a detail. A `TreeHeadTBS` begins with the entire `Configuration`, so in
contact-monitoring mode the two readings produce inputs differing by 34 bytes (a
two-byte length prefix and a 32-byte key), measured from the generated vectors: 96
bytes against 130, and a TBS of 136 against 170. **No signature produced by one
verifies for the other**, in one of the three deployment modes, for every tree head
the log has ever signed.

The draft's own prose resolves it in katie's favour: `leaf_public_key` verifies "the
Service Operator's signature on modifications", and §11.5 gives `UpdateSuffix` a
signature only under `thirdPartyManagement` — so under contact monitoring the key
would have nothing to verify. The `case contactMonitoring:` label reads like an
editing slip. This implementation follows the prose, and `tampered.json` carries a
signature that is valid under the other reading and must be rejected, so the
resolution is pinned by a test rather than by a paragraph.

This is exactly the case this document predicted: "where katie and
keytrans-verification disagree, the draft is ambiguous and that is worth an upstream
issue."

### Asking a verifier to say no

Until `tampered.json` existed, the Go → Rust direction had **one** must-reject case
across 162. Everything else compared computed values, which a verifier that accepted
every proof would pass — nothing in those files asks it to reject anything. The
security-relevant property for a client is the other one: a client receives proofs
from a server, so what matters is that it refuses what the peer refuses.

`tampered.json` closes that. Each case is a proof katie built, corrupted in a
described way, and confirmed rejected by katie's own verifier before being written
out — so the peer is asserting invalidity and a Rust verifier that accepts is wrong,
not merely different. 18 cases across the commitment, the VRF, and both trees:
flipped elements, dropped and duplicated elements, reordered elements, a wrong leaf
value, a corrupted retained subtree head (the §12.1 `MUST`), a proof checked against
the wrong key, and openings for the wrong label, version, and value.

Combined with `from-kt.json`, which runs the same idea with the roles swapped, the
two implementations now have to agree about what is invalid. The evidence page marks
areas whose only evidence is a file of values as "values only", because that is a
weaker claim than a green tick suggests.

### A third kind of oracle: the specification itself

The VRF is the first primitive where the *spec* ships test vectors. RFC 9381
Appendix B gives three ECVRF-EDWARDS25519-SHA512-TAI examples, and
`kt-crypto::vrf` runs them directly, so the ECVRF core is pinned against the
standard rather than against another implementation. That is strictly better than a
differential test: passing means this is ECVRF, not merely that two programs agree.

`vrf.json` then covers what RFC 9381 does not, which is the whole KT wrapping:
`alpha_string` is the presentation-language encoding of a `VrfInput` (§11.7), and
the 64-byte `beta_string` is truncated to `VRF.Nh = 32` (§17.1). Two implementations
can both pass Appendix B and still not interoperate if they disagree about either.
Worth remembering when the next primitive with an RFC behind it comes along: use the
RFC's vectors for the primitive and the peer's for the protocol's use of it.

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

**§12.2's `depth` field cannot describe the deepest possible prefix tree.** `depth`
is a `uint8`, so it tops out at 255. Two search keys that agree on their first 255
bits put their leaves at depth 256, which no `PrefixSearchResult` can express — the
tree is well formed and its root is computable, but no proof about it can be encoded.
`kt-tree::prefix` reports `DepthOverflow` rather than saturating the field, since a
saturated `depth` would describe a different tree than the one being proven and a
verifier could only catch it by failing on the root. Not reachable in practice: for
VRF outputs this is a `2^-255` coincidence, and a log cannot grind for it because it
must produce a valid VRF proof for whatever label-version pair it uses. Worth a
sentence in the draft rather than a fix.

**§15.2 makes some removals unauditable, and both implementations guess.** An
auditor is sent an `AuditorUpdate` — leaves added, leaves removed, and one batch
proof in the *previous* entry's prefix tree — and has to reconstruct the root the new
entry claims (step 7). Applying a removal is not just clearing a node: §3.3's shape
is canonical, so a parent left holding one leaf and one empty child collapses back
into that leaf. Deciding whether to collapse requires knowing whether the removed
leaf's sibling *is* a leaf. It usually cannot be known: §15.2 says `proof.results`
holds one result per element of `added` then `removed`, so the proof describes
exactly the keys being changed and nothing else — never the sibling of a removed
leaf. Measured at pin `00da5254`, over a tree of three leaves with one removed,
katie's `EvaluateBeforeAfter` returns `dfff45ee…` where its own `Tree.Mutate`
produces `06f44480…`. Give the same removal a sibling that happens to be a *parent*
and katie's answer is right — because assuming no collapse is the correct guess
there — which is what makes this hard to notice. An auditor that signs a guessed
root publishes an `AuditorTreeHead` over a root no user can reproduce from their own
proofs, so every `FullTreeHead` carrying it fails. `kt-tree::prefix` returns the same
root katie does, so the two interoperate, but reports it through
`Mutation::assumed_no_collapse`, and `kt-tree::audit` surfaces that as
`Accepted::root_determined` — which an auditor must check before signing. Pinned by
`prefix-mutation.json`, whose `after` column is katie's own tree rather than its
verifier's opinion. The fix belongs in the draft: the update needs to be able to name
the sibling, or `removed` needs to carry it.

**katie treats §11.9's all-zero copath element as an opaque node.** The same
reconstruction, different cause, and here the two implementations differ. When a
removal empties the last leaf under a parent whose other slot was supplied as an
element equal to the all-zero stand-in, that element *does* identify the subtree as
empty — a real node hash cannot be zero — so the parent collapses and, if it was the
last one, the tree is empty. katie blocks the collapse on any element and returns a
root its own tree does not have: for a two-leaf tree with both leaves removed, it
gives `dc48a742…` where `Tree.Mutate` gives the all-zero root. `kt-tree::prefix`
resolves the stand-in and reaches the tree's root. Pinned as a divergence in
`prefix-mutation.json`.

**katie cannot evaluate the replacement §15.2 explicitly permits.** Step 2 says "a
VRF output in `added` is also allowed to be in `removed`", and step 3 exempts exactly
those keys from the non-inclusion requirement — that pair of sentences is how a
label's value is replaced in one entry. katie's `EvaluateBeforeAfter` concatenates
`added` and `removed` and runs the combined list through the duplicate check a plain
batch search needs, so it fails with "same vrf output present multiple times". Two
consequences for anyone implementing this. The proof carries *two* results for the
repeated key, one per request position, so a prover must answer repeats rather than
reject them. And the "before" root has to be reconstructed with the commitment from
`removed`, not `added`: the previous tree held the old value. The draft says so, in a
way that is easy to miss — step 6 computes the previous root "with `proof` and the
`PrefixLeaf` structures in `removed`". Pinned by `prefix-mutation.json`'s
`replace-in-place` case, where the vector records katie's refusal.

**§15.2 cannot audit a log entry that changes nothing.** Neither `added` nor
`removed` has a lower bound, so an entry that adds and removes no prefix tree leaves
is well formed — a log publishing on a fixed schedule with no updates to make would
produce one. But then the proof has no results and no copath, and step 6 has no
material to reconstruct the previous root from, so the auditor cannot confirm the
update starts where it is. Both implementations reject it, independently and for the
same underlying reason; `auditor-update.json`'s `change-nothing` case pins that.
Whether the draft intends to forbid such an entry or to exempt it from step 6 is
worth asking.

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

Nothing has been filed yet — the disclosure email about the ladder hang went to katie's
maintainer first, and the rest are held pending a decision on what to file where. The
queue, in the order they seem worth raising:

*Draft issues.* §15.2 step 7 cannot determine the root when a removal's sibling is
uncovered — the substantive one, since it makes some updates unauditable as specified.
§15.2 has no way to audit an entry that changes nothing. The `2^32-1` greatest version is
unprovable. §12.2's `depth` cannot express 256, and leaves two things implicit about what
it counts. §11.2's grouped `select` reads two ways, and the two Go implementations took
one each.

*katie issues.* The binary ladder hang at versions at or above `2^31-1` (already
disclosed). `EvaluateBeforeAfter` treating §11.9's all-zero copath element as an opaque
node. `EvaluateBeforeAfter` refusing the replacement §15.2 permits.

Each is pinned by a committed vector, so a filing can point at reproducible bytes rather
than at prose.
