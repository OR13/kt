// Vectors for the prefix tree mutation an auditor has to replay (draft §15.2).
//
// §15.2 hands an auditor an `AuditorUpdate` — leaves added, leaves removed, and one
// batch proof covering their search keys in the *previous* entry's tree — and asks it to
// reconstruct two roots: the one it should already have (step 6) and the one the new
// entry claims (step 7). The auditor never holds the tree, so both come out of the
// proof alone.
//
// Step 7 is the interesting half, because applying a change to a prefix tree is not
// just replacing nodes. §3.3's shape is canonical: intermediate nodes exist only as far
// down as two keys share a prefix. A leaf that gains a neighbour is pushed down until
// the keys diverge, and a parent left holding one leaf and one empty child collapses
// back into that leaf. Every case here is a different way of hitting or missing that
// rule.
//
// Each case records four things katie computed:
//
//   - `before` and `after`: the roots of the trees katie's own `Tree.Mutate` builds from
//     the entries before and after the update. These are the ground truth — not a
//     verifier's opinion of what the roots should be, but what the log's own tree code
//     produces — which is what makes them worth checking against.
//   - `peer_before` / `peer_after`: what katie's `prefix.EvaluateBeforeAfter` reconstructs
//     from the proof, or `peer_error` if it declines.
//
// Recording both is the point. They come apart in three ways, all measured rather than
// argued, and all written up in ../../../docs/interop.md:
//
//  1. `remove-every-leaf`: the sibling slot is supplied as a copath element equal to
//     §11.9's all-zero stand-in, which identifies it as an empty subtree, so the parent
//     collapses and the tree ends up empty. katie treats every copath element as an
//     opaque node that blocks the collapse, and returns a root its own tree does not
//     have.
//  2. `remove-beside-a-leaf`: the removed leaf's sibling is a leaf that should now be
//     promoted, but it is a bare copath hash. Nothing in the proof says what it is, and
//     nothing can: `proof.results` corresponds exactly to `added` then `removed`, so a
//     node that is neither can never appear in it. Both implementations return the same
//     root, and it is not the tree's. A draft problem, not a katie bug, which is why the
//     two cases whose sibling is uncovered are marked `sibling_uncovered` — and note
//     that `remove-beside-a-parent` has the same shape and comes out *right*, because
//     assuming no collapse is the correct guess there. Agreement in that case is luck,
//     and the mark says so.
//  3. `replace-in-place`: §15.2 says "a VRF output in `added` is also allowed to be in
//     `removed`", which is how a value is replaced. katie cannot evaluate it — it runs
//     the combined list through the duplicate check a plain batch search needs — so the
//     case records the refusal and checks against the tree instead.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db/memory"
	"github.com/Bren2010/katie/tree/prefix"
)

// mutationVectors covers draft §15.2 steps 6 and 7.
func mutationVectors(sha string) (*File, error) {
	cs := suites.KTSha256Ed25519{}

	f := &File{
		Primitive:   "prefix-mutation",
		Draft:       draftRev + " §15.2",
		Generator:   Generator{Impl: "katie", SHA: sha},
		CipherSuite: 0x0002, // KT_128_SHA256_Ed25519
		Notes: "Prefix tree mutations replayed from a proof, as a §15.2 auditor must. " +
			"`entries` build the tree, `add` and `remove` are the update, and `proof` is " +
			"the batch proof for their keys in that order. `before` and `after` are the " +
			"roots of the trees katie's own Tree.Mutate builds, so they are the log's " +
			"values rather than a verifier's. `peer_before` and `peer_after` are what " +
			"katie's EvaluateBeforeAfter reconstructs from the proof alone, or " +
			"`peer_error` where it declines: they differ from `after` in three shapes, " +
			"noted in the file's source comment and in docs/interop.md. `sibling_uncovered` " +
			"marks a case where a removal empties a slot whose sibling is a bare copath " +
			"hash: §3.3's collapse depends on that node's type, the hash does not reveal " +
			"it, and §15.2 gives no way to ask, so the root is not a function of the proof. " +
			"For those cases `peer_after` is the value both implementations reach by " +
			"assuming no collapse, and `after` shows whether the assumption held.",
	}

	for _, spec := range mutationCases() {
		before, beforeTree, err := buildPrefixTree(cs, spec.entries)
		if err != nil {
			return nil, fmt.Errorf("case %q: building the tree: %w", spec.name, err)
		}

		// The batch an auditor would have been sent: additions first, then removals.
		searches := make([][]byte, 0, len(spec.add)+len(spec.remove))
		for _, e := range spec.add {
			searches = append(searches, e.VrfOutput)
		}
		for _, e := range spec.remove {
			searches = append(searches, e.VrfOutput)
		}
		results, err := beforeTree.Search([]prefix.PrefixSearch{{Version: 1, VrfOutputs: searches}})
		if err != nil {
			return nil, fmt.Errorf("case %q: searching: %w", spec.name, err)
		}
		if len(results) != 1 {
			return nil, fmt.Errorf("case %q: expected one search result set", spec.name)
		}
		proof := results[0].Proof

		var buf bytes.Buffer
		if err := proof.Marshal(&buf); err != nil {
			return nil, fmt.Errorf("case %q: marshalling proof: %w", spec.name, err)
		}

		// The tree the update actually produces, built the same way the log builds it.
		after, err := afterRoot(cs, spec)
		if err != nil {
			return nil, fmt.Errorf("case %q: building the updated tree: %w", spec.name, err)
		}

		expect := map[string]any{
			"before":   hex.EncodeToString(before),
			"after":    hex.EncodeToString(after),
			"proof":    hex.EncodeToString(buf.Bytes()),
			"results":  searchResultJSON(proof.Results),
			"elements": hexAll(proof.Elements),
		}

		peerBefore, peerAfter, err := prefix.EvaluateBeforeAfter(cs, spec.add, spec.remove, &proof)
		if err != nil {
			expect["peer_error"] = err.Error()
		} else {
			if !bytes.Equal(peerBefore, before) {
				// Step 6 is unambiguous, so a mismatch here is not a finding — it means
				// the case is built wrong and the vector would be meaningless.
				return nil, fmt.Errorf(
					"case %q: katie's step 6 root does not match its own tree", spec.name)
			}
			expect["peer_before"] = hex.EncodeToString(peerBefore)
			expect["peer_after"] = hex.EncodeToString(peerAfter)
		}

		// A marked case claims both implementations reach the same assumed root, so the
		// peer has to have produced one.
		if spec.siblingUncovered && peerAfter == nil {
			return nil, fmt.Errorf(
				"case %q is marked sibling_uncovered but the peer produced no root", spec.name)
		}

		input := map[string]any{
			"entries": prefixEntriesJSON(spec.entries),
			"add":     prefixEntriesJSON(spec.add),
			"remove":  prefixEntriesJSON(spec.remove),
		}
		if spec.siblingUncovered {
			input["sibling_uncovered"] = true
		}

		f.Cases = append(f.Cases, Case{Name: spec.name, Input: input, Expect: expect})
	}

	return f, nil
}

type mutationCase struct {
	name    string
	entries []prefix.Entry
	add     []prefix.Entry
	remove  []prefix.Entry
	// Set where a removal empties a slot whose sibling is a bare copath hash, so §3.3's
	// collapse decision rests on a node type the proof does not reveal. A structural
	// property of the case, not a claim about who gets the right answer: one of the two
	// marked cases comes out right anyway.
	siblingUncovered bool
}

func mutationCases() []mutationCase {
	entry := func(first, second, tag, commitment byte) prefix.Entry {
		key := make([]byte, 32)
		key[0], key[1], key[31] = first, second, tag
		return prefix.Entry{VrfOutput: key, Commitment: repeat(commitment, 32)}
	}

	// Keys chosen for their first two bits, which is where every shape below is
	// decided: 0x00 and 0x20 agree on two bits, 0x00 and 0x40 on one, 0x80 on none.
	a := entry(0x00, 0, 1, 0xa1)
	b := entry(0x40, 0, 2, 0xb2)
	c := entry(0x60, 0, 3, 0xc3)
	d := entry(0x80, 0, 4, 0xd4)
	refill := entry(0x20, 0, 5, 0xe5)

	replacement := prefix.Entry{VrfOutput: a.VrfOutput, Commitment: repeat(0xff, 32)}

	return []mutationCase{
		{
			name:    "add-two-leaves",
			entries: []prefix.Entry{a, d},
			add:     []prefix.Entry{b, entry(0xc0, 0, 6, 0xf6)},
		},
		{
			// The addition lands beside a leaf they share two bits with, so §3.3 has to
			// grow intermediate nodes rather than place it at the parent's free slot.
			name:    "add-pushing-a-leaf-down",
			entries: []prefix.Entry{a, d},
			add:     []prefix.Entry{refill},
		},
		{
			name:    "remove-the-only-leaf",
			entries: []prefix.Entry{a},
			remove:  []prefix.Entry{a},
		},
		{
			name:    "remove-every-leaf",
			entries: []prefix.Entry{a, b},
			remove:  []prefix.Entry{a, b},
		},
		{
			name:             "remove-beside-a-leaf",
			entries:          []prefix.Entry{a, b, d},
			remove:           []prefix.Entry{a},
			siblingUncovered: true,
		},
		{
			// Same shape as far as the proof shows, but the sibling is a parent, so
			// assuming no collapse happens to be right. Still not determined.
			name:             "remove-beside-a-parent",
			entries:          []prefix.Entry{a, b, c, d},
			remove:           []prefix.Entry{a},
			siblingUncovered: true,
		},
		{
			name:    "remove-refilled-by-an-add",
			entries: []prefix.Entry{a, b, d},
			add:     []prefix.Entry{refill},
			remove:  []prefix.Entry{a},
		},
		{
			name:    "replace-in-place",
			entries: []prefix.Entry{a, b, d},
			add:     []prefix.Entry{replacement},
			remove:  []prefix.Entry{a},
		},
	}
}

// buildPrefixTree inserts `entries` into a fresh tree and returns its root.
func buildPrefixTree(cs suites.CipherSuite, entries []prefix.Entry) ([]byte, *prefix.Tree, error) {
	tree := prefix.NewTree(cs, memory.NewPrefixStore())
	if len(entries) == 0 {
		// §11.9: an empty prefix tree is the all-zero stand-in.
		return repeat(0, cs.HashSize()), tree, nil
	}
	root, _, _, err := tree.Mutate(0, entries, nil)
	if err != nil {
		return nil, nil, err
	}
	return root, tree, nil
}

// afterRoot builds the tree the update produces, from scratch, so the expected root is
// the log's own value rather than anything a verifier derived.
func afterRoot(cs suites.CipherSuite, spec mutationCase) ([]byte, error) {
	kept := make([]prefix.Entry, 0, len(spec.entries)+len(spec.add))
	for _, e := range spec.entries {
		removed := false
		for _, r := range spec.remove {
			if bytes.Equal(e.VrfOutput, r.VrfOutput) {
				removed = true
			}
		}
		if !removed {
			kept = append(kept, e)
		}
	}
	kept = append(kept, spec.add...)
	root, _, err := buildPrefixTree(cs, kept)
	return root, err
}

func prefixEntriesJSON(entries []prefix.Entry) []map[string]any {
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{
			"vrf_output": hex.EncodeToString(e.VrfOutput),
			"commitment": hex.EncodeToString(e.Commitment),
		})
	}
	return out
}
