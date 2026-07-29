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
pinned at `a2c77bff`) is a second Go client whose `pkg/` covers some of the same
primitives. It is **not** a second oracle, and the reasons come from its
maintainer rather than from us — see
[issue 32](https://github.com/felixlinker/keytrans-verification/issues/32):

- It is not independent of katie. It uses katie for the VRF, so agreement there
  is one implementation agreeing with itself, and the licence question has no
  permissive answer for the same reason: a repository that depends on AGPL code
  cannot be released under MIT even where its author would like to.
- Its Gobra proofs are for **memory safety only**. The maintainer's words: they
  "certainly don't prove anything about corresponding to the spec correctly". So
  they are not evidence about which implementation is right when two disagree,
  which is what this document previously claimed they were.

What it remains useful for is reading: a second author's reading of an ambiguous
passage is evidence that the passage is ambiguous, which is exactly how `DRAFT-07`
below was found. That is an observation about what its source says, not a value to
test against, and it needs no licence.

katie is therefore the single oracle. Where that is a weakness it is stated as
one: a finding that rests on katie alone cannot distinguish "the draft means this"
from "katie does this", and the register marks those.

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
| 7 | Combined tree + full head (§3.4, §11.4) | full `FullTreeHead` verification | First point where signatures enter. | **agrees**: signatures, `FullTreeHead` bytes in all three modes, and §3.4's log entries |
| 8 | Algorithms (§6-§10, §13) | search / monitor / update transcripts | Composite; only meaningful once 1–7 agree. | §6.1 and the §12.3/§13.1 response structures **agree**; the algorithms that consume them are todo |
| 9 | Auditing (§15.2) | `AuditorUpdate` bytes; before/after prefix roots; accept-or-reject; the log root signed | Sits on the prefix tree, and the auditor is the one role whose whole job is a verdict. | **agrees** on all 14 verdicts across steps 1–7, every encoding, and every log root; three divergences recorded, see below |

Steps 1 through 6 are done, step 7 apart from the combined tree, step 9, and §6.1 out of
step 8.
Eighteen vector files pass from the Rust side — 6696 checks across 787 cases — and
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

### Replaying an algorithm is how the ordering gets verified

§12.3's elements are ordered by the algorithm consuming them, so implementing §6.3 is what
turns that ordering from an assumption into a test. §12.3 requires the proof to hold exactly
the elements the algorithm asks for — "no more and no less" — so replaying §6.3 over a
recorded response either consumes every timestamp and every prefix proof or it does not. There
is no partial credit and no need for extra vector data: `Reader::finish` reports what was left
over.

Getting there corrected three readings of the draft, each caught by a case that would not
consume:

- The per-entry ladders are prefixes, not recomputations (`NOTE-04` above). This was the first
  failure: the verifier expected 6 lookups at the first entry and the proof carried 5.
- **The distinguished-entry walk consumes timestamps of its own.** §12.3.2 says the search
  needs no additional timestamps because the frontier's are "either already provided as part of
  updating the user's view of the tree, or are expected to have been retained". That is false
  when §4.2's list comes out empty — `DRAFT-06` — and it comes out empty in exactly the case a
  user hits by advertising a size whose rightmost entry is still on the new frontier. The log
  sends the frontier timestamps anyway, and the first thing that asks for them is the walk that
  finds where §6.3 starts. So its request order is part of the wire order.
- **The response's own ladder can be truncated too**, for the same reason as the per-entry
  ones, which is how a label with no versions gets a single-step ladder (`DRAFT-08`).

All five greatest-version cases now consume exactly, including the advertised-size one whose
view update supplies nothing. §7.2's fixed-version search followed, and its five cases found two
more places where the ordering is not what it looks like:

- **The omission rule is directional, and a binary search moves both ways.** §6.2 licenses
  dropping an inclusion already proven "for a log entry to the left" and a non-inclusion proven
  "to the right". §6.3 walks strictly left to right, so a flat accumulated set happens to work
  there; §7.2 descends left and right, and a flat set makes the verifier expect a ladder with no
  lookups at all where the log sent two. The direction is the whole content of the rule.
- **The rightmost entry's timestamp comes first, before the walk.** §7.1 defines expiry by
  subtracting an entry's timestamp "from the timestamp of the rightmost log entry", so no expiry
  question can be answered until that one is known — which makes it the first element of a
  fixed-version search's `timestamps`, ahead of the root's. A verifier that takes it from
  anywhere else reads every subsequent element one position out.

§7.1's expiry needed the log's clock to be part of the fixture. Expiry is relative to the
rightmost entry's timestamp, so producing an expired entry means spacing the mutations out in
real time — a hundred milliseconds apart against a 250ms lifetime, which leaves four of seven
entries expired and 50ms of slack on either side of every boundary. In those cases §7.2 step 1
skips the expired entries without a ladder at all, so the response carries one proof and two
prefix roots where the unexpired equivalent carries three proofs; the replay consumes both
shapes exactly. A third case is refused by the log outright — asking for a version whose every
proving entry has expired gets §7.2's "expired" answer from the server rather than a proof the
client must reject.

And one place where §7.2 turns out to be implementable only because of a property §6.1 does not
state outright: steps 5.2 and 6.2 ask whether an entry is distinguished, and a verifier cannot
enumerate the distinguished set, because that needs timestamps for entries the search never
visits. It does not have to. §6.1 brackets a node by the timestamps of the entries either side
of it in the search tree, and a descent maintains exactly those bounds as it goes — so
distinguishedness along a search path is decidable from the path itself.

### Monitoring mostly does nothing, which is the part to get right

§8.2 moves a user's map up the tree as new intermediate nodes are built over the versions they
have been shown. Implementing it turned up something that is not a finding but is worth writing
down, because it decides whether a test exercises the algorithm at all: for most map entries the
algorithm inspects **nothing**.

Two shapes are degenerate, for different reasons. An entry on the log's frontier has no ancestors
to its right, so §8.2 step 2.2 removes every candidate. And a left descendant keeps a left
bracket of zero — §6.1's initial value — so its gap to the right bracket is the whole age of the
log and it is always distinguished, which step 1 leaves alone. The shape that does work is an
entry with an ancestor to its right that is not itself distinguished, and in a seven-entry log
there are few of them.

That mattered twice. The first recorded case used a frontier entry and consumed a proof with no
prefix proofs in it, so it passed while testing nothing; adding a case with an ancestor to inspect
then caught a real bug in the descent — §6.1's brackets depend on the *direction* of each step,
and descending to a left child lowers the right bracket rather than raising the left one. The
first implementation only ever raised the left, which made every left descendant look
non-distinguished. That is the same mistake in the same place as §7.2's, where the descent got it
right, and it took a non-degenerate case to expose it here.

Both shapes are now recorded, deliberately: the degenerate one is the common case, and a verifier
that only ever meets it never runs the algorithm.

### Bytes that do not say what they are for

§12.3's `CombinedTreeProof` is the only structure in the draft whose contents cannot be
interpreted from the bytes. It carries `timestamps`, `prefix_proofs` and `prefix_roots` with
nothing saying which log entry each element belongs to — they arrive "in the order that the
algorithm the user is executing would request them". So the same bytes mean different things
depending on which algorithm is running, whether the user advertised a previous tree size,
and which timestamps they are expected to have retained already.

That makes it the one structure a hand-built vector cannot pin. `search.json` therefore builds
a real katie log in memory, mutates it seven times, and records the `SearchResponse` bytes it
serves — and the cases vary exactly what changes the ordering: a first-time search against one
that advertises an earlier size (2 timestamps and 1 inclusion element instead of 3 and 3,
because §12.3 omits what the user retained); a greatest-version search, which carries a
`version` field, against a fixed-version one, which does not; a label with seven versions
against one with a single version against one that does not exist at all.

What is pinned is the wire layer: 10 responses that decode with the request's context and
re-encode byte-for-byte, with the ladder, the three proof vectors and the inclusion elements
checked individually so a mismatch says which field drifted. What is *not* pinned is the
meaning of the ordering, and the coverage table says so in its own row — reading the structure
is not the same as verifying it, and one should not be allowed to stand in for the other.

Two things measured along the way, both against expectations that turned out to be wrong. A
search for a label that has no versions does not fail: katie answers with a one-step ladder
for version 0, proving nothing exists. Nor does a fixed-version search above the greatest
version — it answers with a fourteen-step ladder. Both had been written as expected errors
before the generator was run.

### The one check that is about the log's past

§15.2 step 5 is unlike every other check an auditor performs: it is not about the update in
front of it. A removed leaf must have "been published in at least one distinguished log entry
before removal", which is a claim about history — and it is the rule that makes removals safe
at all, because without it a log could insert a value and take it away again before the label
owner it belongs to had any chance to see it.

Deriving it needs nothing but §6.1. A leaf inserted at entry `p` sits in the prefix tree of
every entry from `p` until it is removed, so it has been published in a distinguished entry
exactly when one exists at or after `p`; "before removal" restricts that to entries strictly
left of the one doing the removing, which is `previous_rightmost`. The auditor therefore
carries two things more: the timestamps along its log tree frontier, without which it cannot
tell which entries are distinguished, and the positions of insertions that no distinguished
entry has covered yet. That second list stays short for a reason worth noticing — §6.1's
distinguished entries are *stable*, so once an insertion is covered it is covered forever and
can be forgotten. An untracked leaf is eligible by construction.

This is also where the frontier walks come in. §6.1's recursion visits every distinguished
entry and needs a timestamp for each; an auditor has only the frontier. The walks derive the
same answers from the frontier alone, out of the same ancestor-closure property, and a test
asserts they agree with the recursion across every size to 256 and seven windows — plus that
they never read a position outside what an auditor retained.

`auditor-update.json` exercises the rule by priming katie's own auditor with a chain of three
entries a minute apart. With a week-long window the third is not distinguished, so a leaf
inserted there may not be removed and both implementations refuse; remove the leaf inserted
first, which a distinguished entry did publish, and both accept. The cases record the peer
auditor's state — heads, frontier timestamps, and the step 5 record — so this side resumes
from katie's bookkeeping rather than from a reconstruction of it. In those cases katie's own
record has pruned all but one insertion, which is the one the refusal is about.

### A shortcut that turns out to be the specification

§6.1 defines distinguished log entries — the reference points every user checks against —
with a recursion over the implicit binary search tree: an entry is distinguished when the
gap between the timestamps bracketing it reaches the Reasonable Monitoring Window, and then
both halves are examined the same way.

katie does not run that recursion. `RightmostDistinguished` descends the frontier while the
current node's right child is still distinguished, which is `O(log n)` rather than
`O(|D|)`. `PreviousRightmost` is stranger: it special-cases the rightmost entry being
distinguished, then hunts for the rightmost edge of a subtree of distinguished entries.
Neither is obviously the same function as the definition, and the set they describe decides
which entries every user in the deployment is obliged to inspect — so this is a good place
for two implementations to differ quietly.

`distinguished.json` therefore records katie's answers, and `kt-tree::distinguished` answers
from §6.1 directly: [`enumerate`] runs the recursion, and the rightmost is the greatest
element of the set it returns. They agree across 42 shapes — sizes from 0 to 1000, windows
from zero (everything is distinguished) to `2^40` (nothing is), evenly spaced timestamps, a
log that stalls and then bursts, and fifty entries sharing a single millisecond. The
shortcut is the definition; that is now a result rather than an assumption.

Two things worth writing down from this. The window-of-zero cases exist because §6.1 goes
out of its way to say the comparison is "less than" and not "less than or equal to" — with
the comparison the other way, a window of zero would distinguish *nothing* instead of
everything, and a deployment that misconfigured it would silently have no reference points
at all. And when the tree size is a power of two the root *is* the rightmost entry, so its
own timestamp is the right bracket and its left child inherits the identical pair: the whole
left spine comes out distinguished. That looks like a misconfigured window if you meet it
without expecting it.

An adjacent thing measured and *not* found: katie's auditor builds its data provider with a
nil proof handle, so any timestamp request outside the retained frontier would be a nil
dereference. Swept across 120,000 combinations — sizes to 4096, ten windows, three timestamp
patterns — `PreviousRightmost` never asked for one. The retained frontier is exactly enough.
Recorded here because the reasoning that says it *should* be reachable is wrong, and the next
reader deserves to know that was checked rather than assumed.

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

### DRAFT-06: §4.2 can leave a user checking nothing at all

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

### DRAFT-07: the two Go implementations disagree about §11.2

The one finding that needed a second implementation to see — and, given what
`keytrans-verification` turned out to be, the only thing that second implementation
was ever going to give us. §11.2 writes `Configuration`'s mode-dependent part as
grouped cases:

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

### Findings

Recorded here rather than rediscovered. Each carries a stable identifier so code comments
and vector notes can point at one without restating it; the register at the end of this
file lists them all with their status. `KT-` is an implementation bug in the Go peer,
`DRAFT-` a gap or ambiguity in the specification, and `NOTE-` a difference that is not a
bug in either but would silently break a third implementation that guessed differently.

**[KT-01] katie's binary ladder does not terminate for versions at or above `2^31-1`.**
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

**[DRAFT-01] A greatest version of `2^32-1` cannot be proven at all.** Appendix B is Python,
so the ladder for `n = 2^32-1` contains `2^33-1`; on the wire a version is a
`uint32` (§11.7), so that lookup does not exist. Establishing `2^32-1` as the
greatest version requires a non-inclusion proof for version `2^32`, which is
unrepresentable. `kt-tree::ladder` reports this rather than truncating. This is a
draft-level gap: either the version space needs to exclude its own maximum, or
Appendix B needs to say what happens there.

**[NOTE-01] katie's search ladder is indexed on the target, Appendix B's on the greatest
version — and they agree anyway.** draft-05's `search_binary_ladder` iterates
`base_binary_ladder(n)`; katie iterates `baseBinaryLadder(t)`. The outputs are
identical, because the two base ladders agree rung by rung until the first rung
where a comparison against `n` differs from one against `t` — i.e. the first rung
in `(min(t,n), max(t,n)]` — and that is exactly Appendix B's `would_end`
condition, which both variants include before stopping. The generator checks this
over a 131×131 grid at generation time and refuses to emit vectors if it ever
fails, and `kt-tree` asserts it again from the Rust side. So katie-generated
ladder vectors are a valid oracle for a draft-shaped implementation.

**[DRAFT-09] nothing says when a monitoring ladder deduplicates, and the two readings do not
interoperate.** §8.1's prose defines a monitoring binary ladder as §5's series "omitting any
lookup for a version greater than the target version" and mentions no deduplication. Appendix B
defines `monitoring_binary_ladder(t, left_inclusion = [])`, which also filters
`v not in left_inclusion`. §8.2 step 3.2 says to obtain one and verify "all expected lookups are
present", without saying what `left_inclusion` should be — and step 3.1 already handles
cross-entry duplication by a different mechanism, which makes the parameter's purpose harder to
guess rather than easier.

Because the check is on an exact count, the two readings fail against each other: a verifier
that deduplicates expects fewer lookups than a log that does not sends, on every monitoring
response where a version was already proven to the left. katie cannot settle it —
`MonitoringBinaryLadder(t)` takes only the target, so it always uses the default — and that is an
implementation choice rather than evidence about intent.

This one **is filed**, because it is the first finding that could not be resolved either by
reading the specification or by measuring the peer:
[draft-protocol#48](https://github.com/ietf-wg-keytrans/draft-protocol/issues/48). This
implementation uses the empty-set reading, which is what interoperates today, and §8.2's three
recorded cases consume their proofs exactly under it.

**[DRAFT-02] §12.2 leaves two things implicit about prefix proofs.** First, what `depth`
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

**[DRAFT-03] §12.2's `depth` field cannot describe the deepest possible prefix tree.** `depth`
is a `uint8`, so it tops out at 255. Two search keys that agree on their first 255
bits put their leaves at depth 256, which no `PrefixSearchResult` can express — the
tree is well formed and its root is computable, but no proof about it can be encoded.
`kt-tree::prefix` reports `DepthOverflow` rather than saturating the field, since a
saturated `depth` would describe a different tree than the one being proven and a
verifier could only catch it by failing on the root. Not reachable in practice: for
VRF outputs this is a `2^-255` coincidence, and a log cannot grind for it because it
must produce a valid VRF proof for whatever label-version pair it uses. Worth a
sentence in the draft rather than a fix.

**[DRAFT-04] §15.2 makes some removals unauditable, and both implementations guess.** An
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

**[KT-02] katie treats §11.9's all-zero copath element as an opaque node.** The same
reconstruction, different cause, and here the two implementations differ. When a
removal empties the last leaf under a parent whose other slot was supplied as an
element equal to the all-zero stand-in, that element *does* identify the subtree as
empty — a real node hash cannot be zero — so the parent collapses and, if it was the
last one, the tree is empty. katie blocks the collapse on any element and returns a
root its own tree does not have: for a two-leaf tree with both leaves removed, it
gives `dc48a742…` where `Tree.Mutate` gives the all-zero root. `kt-tree::prefix`
resolves the stand-in and reaches the tree's root. Pinned as a divergence in
`prefix-mutation.json`.

**[KT-03] katie cannot evaluate the replacement §15.2 explicitly permits.** Step 2 says "a
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

**[DRAFT-05] §15.2 cannot audit a log entry that changes nothing.** Neither `added` nor
`removed` has a lower bound, so an entry that adds and removes no prefix tree leaves
is well formed — a log publishing on a fixed schedule with no updates to make would
produce one. But then the proof has no results and no copath, and step 6 has no
material to reconstruct the previous root from, so the auditor cannot confirm the
update starts where it is. Both implementations reject it, independently and for the
same underlying reason; `auditor-update.json`'s `change-nothing` case pins that.
Whether the draft intends to forbid such an entry or to exempt it from step 6 is
worth asking.

**[DRAFT-08] §6.3 cannot verify the response that means "this label does not exist".** A log
still has to answer a search for a label with no versions, and the only answer available is a
claimed greatest version of 0 whose single ladder lookup proves version 0 absent. §6.3 step 2
read literally rejects it: it requires the rightmost entry to show every version at or below
the target as *included*, which nothing can do for a label that has never existed. There is no
branch in §6.3 for the case and no field in `SearchResponse` that distinguishes it — on the
wire it is a `version` of 0 and a one-step ladder, which is also what a label whose only
version is 0 would produce, minus the inclusion. katie invents the handling its client needs
(`if ver == 0 && res == -1 { ErrLabelNotFound }`); this implementation reports it as
`Outcome::NoVersions` rather than as a dishonest log. Pinned by `search.json`'s
`label-does-not-exist` case. The draft needs either a branch in §6.3 or a way to say it in the
response.

**[NOTE-04] a per-entry binary ladder is a prefix of the target's, not a recomputation of
it.** §6.2 says a search ladder "ends after the first inclusion proof for a version greater
than the target, or the first non-inclusion proof for a version less than or equal to it", and
the log indexes that stopping rule on the greatest version present *at that entry* — which the
verifier does not know, because learning it is the point of the search. So the proof for an
entry left of the terminal one carries **fewer** results than the ladder the verifier computes,
and they pair with a prefix of it: the sequence of versions is the same, only the stopping
point differs. A verifier that requires the lengths to match rejects every honest multi-entry
search, and one that recomputes the ladder from a guessed local greatest gets different
versions. Measured against katie: for a seven-entry log with greatest version 6, the ladder is
`[0, 1, 3, 7, 5, 6]` and the three inspected entries carry 5, 3 and 2 results. Not a bug in
either implementation — but the draft never says the results are a prefix, and it is the first
thing an implementer gets wrong.

**[NOTE-03] `opening` sits in a different place in the two implementations.** The draft puts
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

## Findings register

Findings are tracked here rather than filed, with one exception. The rule is that a finding gets
filed when it is a **blocker** — something that cannot be resolved either by reading the
specification or by measuring the peer, so that no amount of further work here will settle it.
`DRAFT-09` is the first to meet that bar and is filed as
[draft-protocol#48](https://github.com/ietf-wg-keytrans/draft-protocol/issues/48). Everything
else is resolved: the behaviour is known, a committed vector pins it, and a filing would be a
courtesy rather than a necessity.

| ID | What | Belongs to | Pinned by | Status |
|---|---|---|---|---|
| `KT-01` | Binary ladder does not terminate for greatest versions at or above `2^31-1` | katie | `binary-ladder.json` capped at `2^31-2`; Rust tests above it | disclosed by email; not filed |
| `KT-02` | `EvaluateBeforeAfter` treats §11.9's all-zero copath element as an opaque node | katie | `prefix-mutation.json` `remove-every-leaf` | tracked locally |
| `KT-03` | `EvaluateBeforeAfter` refuses the replacement §15.2 permits | katie | `prefix-mutation.json` `replace-in-place` | tracked locally |
| `DRAFT-01` | A greatest version of `2^32-1` cannot be proven at all | draft | `kt-tree::ladder` refuses it | tracked locally |
| `DRAFT-02` | §12.2 leaves `nonInclusionParent`'s `depth` and its element accounting implicit | draft | `prefix-tree.json` | tracked locally |
| `DRAFT-03` | §12.2's `uint8 depth` cannot express depth 256 | draft | `kt-tree::prefix` `DepthOverflow` | tracked locally |
| `DRAFT-04` | §15.2 step 7 cannot determine the root when a removal's sibling is uncovered | draft | `prefix-mutation.json`, `auditor-update.json` | tracked locally |
| `DRAFT-05` | §15.2 cannot audit a log entry that changes nothing | draft | `auditor-update.json` `change-nothing` | tracked locally |
| `DRAFT-06` | §4.2 can send a user no timestamps at all while the log has grown | draft | `update-view.json`; `ibst::leaves_right_edge_unchecked` | tracked locally |
| `DRAFT-07` | §11.2's grouped `select` reads two ways; the two Go implementations took one each, and no signature cross-verifies in contactMonitoring | draft | `tree-head.json`, including a negative case carrying a signature valid under the other reading | tracked locally |
| `DRAFT-08` | §6.3 cannot verify the response that means "this label does not exist" | draft | `search.json` `label-does-not-exist` | tracked locally |
| `NOTE-01` | katie's search ladder is target-indexed, Appendix B's greatest-indexed — equivalent | neither | generator's 131×131 grid; Rust tests | no action |
| `NOTE-04` | a per-entry ladder's results are a *prefix* of the verifier's ladder, because the log stops on the local greatest version | neither | `search.json`, all five greatest-version cases | no action |
| `DRAFT-09` | Nothing says when a monitoring ladder deduplicates against `left_inclusion`; the two readings fail against each other | draft | `monitor.json`, three §8.2 replays under the empty-set reading | **filed**: [draft-protocol#48](https://github.com/ietf-wg-keytrans/draft-protocol/issues/48) |
| `NOTE-03` | `opening` sits inside `CommitmentValue` in the draft, outside it in katie | neither | `commitment.json` records both | no action |

Two ground rules for anything added here. A finding is only a finding once a committed
vector or test pins it — otherwise it is a hunch, and hunches do not survive contact with a
regenerated vector. And a `DRAFT-` entry has to say what an implementation is supposed to
do instead, because "the specification is unclear" is not actionable and this file is the
place the next reader looks.
