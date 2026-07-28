// Vectors for the third-party auditor's view of one log entry (draft §15.2).
//
// Two things are pinned here, and they are pinned separately on purpose.
//
// The first is the `AuditorUpdate` encoding. It is the only §15.2 structure that crosses
// a wire, and it is the one place where the draft's element-counted vectors carry
// something big: `PrefixLeaf added<0..2^16-1>` is 65535 *leaves*, not 65535 bytes, so a
// decoder that reads the §2.1.2 bound the way RFC 8446 does gets a different message off
// the same bytes. `encoding` is katie's marshalling of each update.
//
// The second is the verdict: whether katie's own stateful auditor accepts the update.
// That is a much stronger check than the encoding, because §15.2's eight steps are prose
// and every one of them is a chance to disagree — and the two implementations reach the
// same accept-or-reject on each case here. Verdicts are normalized to "accepted" or
// "rejected" rather than compared as error strings, since nothing requires two
// implementations to phrase a refusal the same way; `peer_detail` records katie's own
// wording so a disagreement can be read rather than guessed at.
//
// Two cases are worth reading before the rest.
//
// `change-nothing` is an entry that adds and removes no prefix tree leaves, which §15.2
// permits — neither list has a lower bound. Both implementations reject it, and neither
// can do otherwise: with nothing in `added` or `removed` the proof has no results and no
// copath, so step 6 has no way to reconstruct the previous root and therefore no way to
// confirm the update starts where the auditor is. So a log running on a fixed schedule
// cannot publish an entry that changes nothing and still have it audited. katie's
// rejection comes out of its copath accounting and this implementation's out of step 6;
// the verdict is the same either way, which is what the vector pins.
//
// The `remove-a-leaf-*-distinguished-entry-published` pair is what step 5 is for. Step 5
// requires that a removed leaf "was published in at least one distinguished log entry
// before removal", which is a statement about the log's past rather than about the update,
// so it cannot be exercised without a history: the cases prime the auditor with three
// entries a minute apart, and with a week-long window the third is not distinguished. A
// leaf inserted there has never been published in a distinguished entry, and both
// implementations refuse to let the log remove it. Remove the leaf inserted first instead,
// which a distinguished entry did publish, and both accept.
//
// That is also why each case records the peer auditor's own state — `log_size`,
// `log_full_subtrees`, `frontier_timestamps`, and `inserted` — rather than a
// reconstruction of it. `inserted` is the step 5 record, and it is short because katie
// prunes it: an insertion a distinguished entry has covered can never become ineligible
// again, so it is forgotten. In the three-entry cases only the leaf inserted at entry 2
// survives, which is the one the refusal is about.
//
// Note also that these removals uncover a sibling the proof does not identify, so the root
// both auditors would sign is one neither can derive: see prefix-mutation.json and the
// DRAFT-04 finding in docs/interop.md.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/crypto/vrf/edwards25519"
	"github.com/Bren2010/katie/db/memory"
	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/auditor"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// auditorVectors covers draft §15.2 steps 1 through 7.
func auditorVectors(sha string) (*File, error) {
	cs := suites.KTSha256Ed25519{}

	f := &File{
		Primitive:   "auditor-update",
		Draft:       draftRev + " §15.2",
		Generator:   Generator{Impl: "katie", SHA: sha},
		CipherSuite: 0x0002, // KT_128_SHA256_Ed25519
		Notes: "One `AuditorUpdate` per case, with the encoding katie marshals and the " +
			"verdict katie's own stateful auditor reaches. `entries` build the previous " +
			"log entry's prefix tree, whose root is `prefix_root` — an auditor's whole " +
			"state, along with `previous_timestamp`. `verdict` is \"accepted\" or " +
			"\"rejected\", normalized because nothing requires two implementations to word " +
			"a refusal alike; `peer_detail` is katie's wording. `peer_step_5` marks a " +
			"rejection that comes from §15.2 step 5, the check that a removed leaf was " +
			"published in a distinguished log entry, which this implementation does not " +
			"check because it needs auditor history rather than anything in the update.",
	}

	// A third-party auditing configuration, since katie's auditor refuses to exist
	// under any other mode. Fixed keys, so regeneration is a no-op diff.
	logKey, err := cs.ParseSigningPrivateKey(repeat(0x71, 32))
	if err != nil {
		return nil, fmt.Errorf("parsing the log signing key: %w", err)
	}
	auditorKey, err := cs.ParseSigningPrivateKey(repeat(0x72, 32))
	if err != nil {
		return nil, fmt.Errorf("parsing the auditor signing key: %w", err)
	}
	vrfKey, err := edwards25519.NewPrivateKey(repeat(0x74, 32))
	if err != nil {
		return nil, fmt.Errorf("parsing the VRF key: %w", err)
	}
	config := &structs.PublicConfig{
		SignatureKey: logKey.Public(),
		VrfKey:       vrfKey.PublicKey(),
		Config: structs.Config{
			Suite:                      cs,
			Mode:                       structs.ThirdPartyAuditing,
			MaxAhead:                   10000,
			MaxBehind:                  10000,
			ReasonableMonitoringWindow: 604800000,
			MaxAuditorLag:              60000,
			AuditorStartPos:            0,
			AuditorPublicKey:           auditorKey.Public(),
		},
	}

	for _, spec := range auditorCases() {
		before, tree, err := buildPrefixTree(cs, spec.entries)
		if err != nil {
			return nil, fmt.Errorf("case %q: building the tree: %w", spec.name, err)
		}
		if len(spec.entries) == 0 {
			// An empty tree still has to be mutated into existence before it will answer
			// a search; §11.9's all-zero root is what it answers with.
			if _, _, _, err := tree.Mutate(0, nil, nil); err != nil {
				return nil, fmt.Errorf("case %q: creating the empty tree: %w", spec.name, err)
			}
		}

		searches := make([][]byte, 0, len(spec.added)+len(spec.removed))
		for _, e := range spec.added {
			searches = append(searches, e.VrfOutput)
		}
		for _, e := range spec.removed {
			searches = append(searches, e.VrfOutput)
		}
		var proof prefix.PrefixProof
		if len(searches) > 0 {
			results, err := tree.Search([]prefix.PrefixSearch{{Version: 1, VrfOutputs: searches}})
			if err != nil {
				return nil, fmt.Errorf("case %q: searching: %w", spec.name, err)
			}
			proof = results[0].Proof
		}

		update := &structs.AuditorUpdate{
			Timestamp: spec.timestamp,
			Added:     spec.added,
			Removed:   spec.removed,
			Proof:     proof,
		}
		if spec.mangle != nil {
			spec.mangle(update)
		}

		var buf bytes.Buffer
		if err := update.Marshal(&buf); err != nil {
			return nil, fmt.Errorf("case %q: marshalling the update: %w", spec.name, err)
		}
		// A round trip through katie's own parser, so the vector cannot pin bytes that
		// katie would not itself read back.
		reread := bytes.NewBuffer(buf.Bytes())
		if _, err := structs.NewAuditorUpdate(cs, reread); err != nil {
			return nil, fmt.Errorf("case %q: katie cannot parse its own encoding: %w", spec.name, err)
		} else if reread.Len() != 0 {
			return nil, fmt.Errorf("case %q: katie left %d bytes unread", spec.name, reread.Len())
		}

		verdict, detail, accepted, primed, err := auditorVerdict(
			config, auditorKey, spec, before, update)
		if err != nil {
			return nil, fmt.Errorf("case %q: %w", spec.name, err)
		}

		input := map[string]any{
			"entries":            prefixEntriesJSON(spec.entries),
			"window":             config.ReasonableMonitoringWindow,
			"previous_timestamp": spec.previousTimestamp,
			"timestamp":          spec.timestamp,
			"added":              prefixEntriesJSON(update.Added),
			"removed":            prefixEntriesJSON(update.Removed),
			"prefix_root":        hex.EncodeToString(before),
		}
		if spec.firstEntry {
			input["first_entry"] = true
		}
		// The auditor's whole state as the peer built it, so the Rust side resumes from
		// the peer's own bookkeeping rather than from a reconstruction of it. `inserted` is
		// what §15.2 step 5 turns on — a removal is allowed only once a distinguished log
		// entry has published the leaf, and this is the record that decides it — and
		// `frontier_timestamps` is what decides which entries are distinguished at all.
		inserted := make([]map[string]any, 0)
		frontierTimestamps := make([]uint64, 0)
		fullSubtrees := make([]string, 0)
		var logSize uint64
		if primed != nil {
			logSize = primed.TreeHead.TreeSize
			for _, ins := range primed.Inserted {
				inserted = append(inserted, map[string]any{
					"position":   ins.Pos,
					"vrf_output": hex.EncodeToString(ins.VrfOutput),
				})
			}
			frontierTimestamps = append(frontierTimestamps, primed.Timestamps...)
			for _, head := range primed.FullSubtrees {
				fullSubtrees = append(fullSubtrees, hex.EncodeToString(head))
			}
		}
		input["inserted"] = inserted
		input["frontier_timestamps"] = frontierTimestamps
		input["log_full_subtrees"] = fullSubtrees
		input["log_size"] = logSize
		expect := map[string]any{
			"encoding": hex.EncodeToString(buf.Bytes()),
			"verdict":  verdict,
		}
		if detail != "" {
			expect["peer_detail"] = detail
		}
		if accepted != nil {
			// §15.2 step 7's second half, taken from the auditor's own committed state:
			// the log tree grew by one entry and this is the root an AuditorTreeHead for
			// `tree_size` is signed over (§11.3). The auditor holds no leaves, so this is
			// a fold over the full subtree heads it carries — a different computation from
			// hashing a tree, and worth pinning as such.
			expect["tree_size"] = accepted.TreeSize
			expect["log_root"] = hex.EncodeToString(accepted.LogRoot)
		}

		f.Cases = append(f.Cases, Case{Name: spec.name, Input: input, Expect: expect})
	}

	return f, nil
}

// acceptedState is what the auditor's state became, for the cases it accepted.
type acceptedState struct {
	TreeSize uint64
	LogRoot  []byte
}

// auditorVerdict runs katie's stateful auditor over the case, priming its state with the
// previous log entry so step 6 has something to match against.
func auditorVerdict(
	config *structs.PublicConfig,
	auditorKey suites.SigningPrivateKey,
	spec auditorCase,
	before []byte,
	update *structs.AuditorUpdate,
) (verdict string, detail string, accepted *acceptedState, primed *auditor.AuditorState, err error) {
	store := memory.NewAuditorStore()
	a, err := auditor.NewAuditor(config, auditorKey, store)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("constructing the auditor: %w", err)
	}

	// Every case but the first-entry one needs the auditor to already hold the tree the
	// update starts from. The only way in is to process updates that produce it, so the
	// auditor is primed by replaying the case's history — one update per log entry,
	// inserting into the tree as it stood at the time.
	if !spec.firstEntry {
		var held []prefix.Entry
		for i, step := range spec.priming() {
			sorted := sortedEntries(step.added)
			proof, err := treeProof(config.Suite, held, sorted)
			if err != nil {
				return "", "", nil, nil, fmt.Errorf("priming step %d: proving: %w", i, err)
			}
			priming := &structs.AuditorUpdate{
				Timestamp: step.timestamp,
				Added:     sorted,
				Proof:     *proof,
			}
			if err := a.Process(priming); err != nil {
				return "", "", nil, nil, fmt.Errorf("priming step %d: %w", i, err)
			}
			if _, err := a.Commit(); err != nil {
				return "", "", nil, nil, fmt.Errorf("priming step %d: committing: %w", i, err)
			}
			held = append(held, sorted...)
		}

		// Read the committed state back out to confirm the auditor now holds the tree
		// the case's update is supposed to start from. Without this the step 6 cases
		// would be checking nothing.
		state, err := committedState(config, store)
		if err != nil {
			return "", "", nil, nil, fmt.Errorf("reading the primed state: %w", err)
		}
		if !bytes.Equal(state.PrefixTree, before) {
			return "", "", nil, nil, fmt.Errorf(
				"priming produced prefix root %x, the case expects %x", state.PrefixTree, before)
		}
		primed = state
	}

	if err := a.Process(update); err != nil {
		return "rejected", err.Error(), nil, primed, nil
	}
	if _, err := a.Commit(); err != nil {
		return "", "", nil, nil, fmt.Errorf("committing the accepted update: %w", err)
	}
	state, err := committedState(config, store)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("reading the accepted state: %w", err)
	}
	root, err := log.Root(config.Suite, state.TreeHead.TreeSize, state.FullSubtrees)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("rooting the log tree: %w", err)
	}
	return "accepted", "", &acceptedState{
		TreeSize: state.TreeHead.TreeSize,
		LogRoot:  root,
	}, primed, nil
}

// priming returns the chain of updates that brings the auditor to the case's starting
// state: the case's own history, or a single update inserting every entry if it has none.
func (c auditorCase) priming() []historyStep {
	if len(c.history) > 0 {
		return c.history
	}
	return []historyStep{{timestamp: c.previousTimestamp, added: c.entries}}
}

// committedState reads back what the auditor persisted, which is the only way to see the
// full subtree heads it is carrying.
func committedState(config *structs.PublicConfig, store *memory.AuditorStore) (*auditor.AuditorState, error) {
	raw, err := store.GetState()
	if err != nil {
		return nil, err
	}
	return auditor.NewAuditorState(config.Suite, bytes.NewBuffer(raw))
}

// historyStep is one update used to bring the auditor to the state a case starts from.
type historyStep struct {
	timestamp uint64
	added     []prefix.Entry
}

type auditorCase struct {
	name    string
	entries []prefix.Entry
	added   []prefix.Entry
	removed []prefix.Entry

	// history primes the auditor with a chain of updates rather than one. §15.2 step 5
	// cannot be exercised without it: a leaf is only ineligible for removal when it was
	// inserted after the last distinguished log entry, which takes at least three entries
	// to arrange. When empty, the priming is a single update inserting `entries`.
	history []historyStep

	previousTimestamp uint64
	timestamp         uint64

	// firstEntry runs the update against an auditor with no state at all, where there is
	// no timestamp to be after and no root to match.
	firstEntry bool
	// mangle breaks the update after it is built, for the structural checks.
	mangle func(*structs.AuditorUpdate)
}

func auditorCases() []auditorCase {
	entry := func(first, tag, commitment byte) prefix.Entry {
		key := make([]byte, 32)
		key[0], key[31] = first, tag
		return prefix.Entry{VrfOutput: key, Commitment: repeat(commitment, 32)}
	}

	a := entry(0x00, 1, 0xa1)
	b := entry(0x40, 2, 0xb2)
	c := entry(0x80, 3, 0xc3)
	d := entry(0xc0, 4, 0xd4)

	const (
		previous = 1_700_000_000_000
		now      = 1_700_000_060_000
	)

	return []auditorCase{
		{
			name:              "add-one-leaf",
			entries:           []prefix.Entry{a, c},
			added:             []prefix.Entry{b},
			previousTimestamp: previous,
			timestamp:         now,
		},
		{
			name:              "add-two-leaves",
			entries:           []prefix.Entry{a},
			added:             []prefix.Entry{b, c},
			previousTimestamp: previous,
			timestamp:         now,
		},
		{
			// §15.2 puts no lower bound on either list: an entry may change nothing.
			name:              "change-nothing",
			entries:           []prefix.Entry{a, c},
			previousTimestamp: previous,
			timestamp:         now,
		},
		{
			name:              "same-timestamp-is-allowed",
			entries:           []prefix.Entry{a, c},
			added:             []prefix.Entry{b},
			previousTimestamp: previous,
			timestamp:         previous,
		},
		{
			name:              "timestamp-goes-backwards",
			entries:           []prefix.Entry{a, c},
			added:             []prefix.Entry{b},
			previousTimestamp: now,
			timestamp:         previous,
		},
		{
			name:              "added-out-of-order",
			entries:           []prefix.Entry{a},
			added:             []prefix.Entry{c, b},
			previousTimestamp: previous,
			timestamp:         now,
		},
		{
			name:              "added-repeats-a-key",
			entries:           []prefix.Entry{a},
			added:             []prefix.Entry{b, b},
			previousTimestamp: previous,
			timestamp:         now,
		},
		{
			// The proof shows inclusion for a key `added` claims is new.
			name:              "added-is-already-present",
			entries:           []prefix.Entry{a, c},
			added:             []prefix.Entry{a},
			previousTimestamp: previous,
			timestamp:         now,
		},
		{
			// And the proof shows non-inclusion for a key `removed` claims is there.
			name:              "removed-is-absent",
			entries:           []prefix.Entry{a, c},
			removed:           []prefix.Entry{b},
			previousTimestamp: previous,
			timestamp:         now,
		},
		{
			name:              "results-do-not-cover-the-keys",
			entries:           []prefix.Entry{a, c},
			added:             []prefix.Entry{b},
			previousTimestamp: previous,
			timestamp:         now,
			mangle: func(u *structs.AuditorUpdate) {
				u.Proof.Results = nil
			},
		},
		{
			name:              "first-entry-adds-two-leaves",
			added:             []prefix.Entry{a, b},
			previousTimestamp: previous,
			timestamp:         now,
			firstEntry:        true,
		},
		{
			// §15.2 step 5's refusal. Three priming entries a minute apart: with a
			// week-long window, entry 2 is not distinguished, so a leaf inserted there has
			// never been published in a distinguished entry and may not be removed. This is
			// the case the rule exists for — without it a log could insert a value and take
			// it away again before any label owner had a chance to see it.
			name:    "remove-a-leaf-no-distinguished-entry-published",
			entries: []prefix.Entry{a, b, c},
			history: []historyStep{
				{timestamp: previous, added: []prefix.Entry{a}},
				{timestamp: previous + 60_000, added: []prefix.Entry{b}},
				{timestamp: previous + 120_000, added: []prefix.Entry{c}},
			},
			removed:           []prefix.Entry{c},
			previousTimestamp: previous + 120_000,
			timestamp:         previous + 180_000,
		},
		{
			// The same history, removing the leaf inserted first — which a distinguished
			// entry has published, so it may go.
			name:    "remove-a-leaf-a-distinguished-entry-published",
			entries: []prefix.Entry{a, b, c},
			history: []historyStep{
				{timestamp: previous, added: []prefix.Entry{a}},
				{timestamp: previous + 60_000, added: []prefix.Entry{b}},
				{timestamp: previous + 120_000, added: []prefix.Entry{c}},
			},
			removed:           []prefix.Entry{a},
			previousTimestamp: previous + 120_000,
			timestamp:         previous + 180_000,
		},
		{
			// Accepted by both. Its single priming entry leaves nothing tracked for step
			// 5 — a distinguished entry covered every insertion — so eligibility is
			// decided by the pruning rule rather than by a lookup.
			name:              "remove-one-leaf",
			entries:           []prefix.Entry{a, b, c, d},
			removed:           []prefix.Entry{a},
			previousTimestamp: previous,
			timestamp:         now,
		},
	}
}

// sortedEntries returns the entries in the ascending vrf_output order §15.2 step 2 wants.
func sortedEntries(entries []prefix.Entry) []prefix.Entry {
	out := make([]prefix.Entry, len(entries))
	copy(out, entries)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && bytes.Compare(out[j-1].VrfOutput, out[j].VrfOutput) > 0; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// treeProof is the batch proof a tree holding `held` gives for the keys of `searched`,
// which is what the log sends alongside an update that inserts them.
func treeProof(
	cs suites.CipherSuite, held, searched []prefix.Entry,
) (*prefix.PrefixProof, error) {
	if len(held) == 0 {
		return emptyTreeProof(cs, searched)
	}
	tree := prefix.NewTree(cs, memory.NewPrefixStore())
	if _, _, _, err := tree.Mutate(0, held, nil); err != nil {
		return nil, err
	}
	keys := make([][]byte, 0, len(searched))
	for _, e := range searched {
		keys = append(keys, e.VrfOutput)
	}
	if len(keys) == 0 {
		return &prefix.PrefixProof{}, nil
	}
	results, err := tree.Search([]prefix.PrefixSearch{{Version: 1, VrfOutputs: keys}})
	if err != nil {
		return nil, err
	}
	return &results[0].Proof, nil
}

// emptyTreeProof is the batch proof an empty prefix tree gives for `entries`, which is
// what the log sends with its very first update. Built by searching a real empty tree
// rather than assembled by hand: katie's result types are unexported, and going through
// its own prover is the only way to be sure the shape is one it would produce.
func emptyTreeProof(cs suites.CipherSuite, entries []prefix.Entry) (*prefix.PrefixProof, error) {
	if len(entries) == 0 {
		return &prefix.PrefixProof{}, nil
	}
	tree := prefix.NewTree(cs, memory.NewPrefixStore())
	// A tree has to be mutated into existence before it can be searched, even to say
	// that it is empty. Mutating with nothing gives version 1 of an empty tree, whose
	// root is §11.9's all-zero stand-in.
	if _, _, _, err := tree.Mutate(0, nil, nil); err != nil {
		return nil, err
	}
	keys := make([][]byte, 0, len(entries))
	for _, e := range entries {
		keys = append(keys, e.VrfOutput)
	}
	results, err := tree.Search([]prefix.PrefixSearch{{Version: 1, VrfOutputs: keys}})
	if err != nil {
		return nil, err
	}
	return &results[0].Proof, nil
}
