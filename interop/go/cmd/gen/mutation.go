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
			"the batch proof Tree.Mutate returns: one result per key of `add`, then " +
			"`remove`, then `leaves`. `leaves` are the leaves the mutation moved closer to " +
			"the root because a sibling was removed (§3.3), which the draft added so " +
			"an auditor can see that a leaf's position changes. `before` and `after` are " +
			"the roots of the trees katie builds, and `after` is checked against a tree " +
			"built from scratch, since §3.3 makes the prefix tree history independent. " +
			"`peer_before` and `peer_after` are what katie's EvaluateBeforeAfter " +
			"reconstructs from the proof alone. A case marked `omit_leaves` is the same " +
			"update from a log that did not name the moved leaves: the proof covers " +
			"only `add` and `remove`, the sibling arrives as a bare hash, and the " +
			"auditor reaches a root that is not the log's.",
	}

	for _, spec := range mutationCases() {
		before, beforeTree, err := buildPrefixTree(cs, spec.entries)
		if err != nil {
			return nil, fmt.Errorf("case %q: building the tree: %w", spec.name, err)
		}

		// Apply the update to the tree the way the log does. The proof Mutate returns is the
		// batch proof from just before the mutation, for the keys of `add`, `remove` and the
		// leaves the mutation moved — the three lists §15.2 now has an auditor read.
		sortedAdd, sortedRemove := sortedEntries(spec.add), sortedEntries(spec.remove)
		removeKeys := make([][]byte, 0, len(sortedRemove))
		for _, e := range sortedRemove {
			removeKeys = append(removeKeys, e.VrfOutput)
		}
		res, err := beforeTree.Mutate(1, sortedAdd, removeKeys)
		if err != nil {
			return nil, fmt.Errorf("case %q: mutating: %w", spec.name, err)
		}
		proof := res.Proof
		leaves := res.Leaves
		if spec.omitLeaves {
			if len(res.Leaves) == 0 {
				return nil, fmt.Errorf("case %q: omit_leaves, but the update moves nothing", spec.name)
			}
			keys := make([][]byte, 0, len(sortedAdd)+len(sortedRemove))
			for _, e := range sortedAdd {
				keys = append(keys, e.VrfOutput)
			}
			for _, e := range sortedRemove {
				keys = append(keys, e.VrfOutput)
			}
			searched, err := beforeTree.Search([]prefix.PrefixSearch{{Version: 1, VrfOutputs: keys}})
			if err != nil {
				return nil, fmt.Errorf("case %q: searching: %w", spec.name, err)
			}
			proof = searched[0].Proof
			leaves = nil
		}

		var buf bytes.Buffer
		if err := proof.Marshal(&buf); err != nil {
			return nil, fmt.Errorf("case %q: marshalling proof: %w", spec.name, err)
		}

		// The tree the update should produce, built from scratch. §3.3 says the prefix tree
		// is history independent, so Mutate's root and this one must agree.
		after, err := afterRoot(cs, spec)
		if err != nil {
			return nil, fmt.Errorf("case %q: building the updated tree: %w", spec.name, err)
		}
		if !bytes.Equal(after, res.Root) {
			return nil, fmt.Errorf(
				"case %q: Mutate's root is not the from-scratch root: tree is not history independent",
				spec.name)
		}

		expect := map[string]any{
			"before":   hex.EncodeToString(before),
			"after":    hex.EncodeToString(after),
			"proof":    hex.EncodeToString(buf.Bytes()),
			"results":  searchResultJSON(proof.Results),
			"elements": hexAll(proof.Elements),
			"leaves":   prefixEntriesJSON(leaves),
		}

		peerBefore, peerAfter, err := prefix.EvaluateBeforeAfter(cs, sortedAdd, sortedRemove, leaves, &proof)
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

		// A marked case claims the peer reaches a root, and that it is the wrong one.
		if spec.omitLeaves {
			if peerAfter == nil {
				return nil, fmt.Errorf(
					"case %q is marked omit_leaves but the peer produced no root", spec.name)
			} else if bytes.Equal(peerAfter, after) {
				return nil, fmt.Errorf(
					"case %q is marked omit_leaves but the peer reached the right root anyway", spec.name)
			}
		} else if peerAfter != nil && !bytes.Equal(peerAfter, after) {
			return nil, fmt.Errorf(
				"case %q: katie's verifier reconstructs a root its own tree does not have", spec.name)
		}

		input := map[string]any{
			"entries": prefixEntriesJSON(spec.entries),
			"add":     prefixEntriesJSON(spec.add),
			"remove":  prefixEntriesJSON(spec.remove),
		}
		if spec.omitLeaves {
			input["omit_leaves"] = true
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
	// Set where the update moves a leaf but the log does not name it, so the proof
	// carries its sibling only as a hash.
	omitLeaves bool
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
			// The sibling is a leaf, so it takes its parent's place and is named in `leaves`.
			name:    "remove-beside-a-leaf",
			entries: []prefix.Entry{a, b, d},
			remove:  []prefix.Entry{a},
		},
		{
			// The same update from a log that leaves `leaves` empty. The auditor cannot tell
			// the sibling is a leaf, assumes it is a parent, and signs a root nobody has.
			name:       "remove-beside-a-leaf-leaves-omitted",
			entries:    []prefix.Entry{a, b, d},
			remove:     []prefix.Entry{a},
			omitLeaves: true,
		},
		{
			// The sibling is a parent: nothing moves and `leaves` is empty.
			name:    "remove-beside-a-parent",
			entries: []prefix.Entry{a, b, c, d},
			remove:  []prefix.Entry{a},
		},
		{
			// The survivor rises two levels, not one: §3.3 repeats the replacement until it
			// has a sibling or is the root.
			name:    "remove-collapsing-a-chain",
			entries: []prefix.Entry{a, refill, d},
			remove:  []prefix.Entry{a},
		},
		{
			// Two removals each orphan a leaf, so two leaves move and `leaves` has to be sorted.
			name:    "remove-two-siblings-apart",
			entries: []prefix.Entry{a, b, d, entry(0xc0, 0, 6, 0xf6)},
			remove:  []prefix.Entry{a, d},
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
	tree := prefix.NewTree(cs, newPrefixStore())
	if len(entries) == 0 {
		// §11.9: an empty prefix tree is the all-zero stand-in.
		return repeat(0, cs.HashSize()), tree, nil
	}
	res, err := tree.Mutate(0, sortedEntries(entries), nil)
	if err != nil {
		return nil, nil, err
	}
	return res.Root, tree, nil
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
