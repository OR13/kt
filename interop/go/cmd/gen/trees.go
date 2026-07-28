// Vectors for the two hash trees: the log tree (draft §3.2, §11.8, §12.1) and
// the prefix tree (§3.3, §11.9, §12.2).
//
// Both are generated from katie's real tree implementations backed by its
// in-memory stores, so the roots and proofs here are the ones a running Go log
// would serve, not a re-derivation of the hashing rules.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/db/memory"
	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/prefix"
	ktmath "github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// logTreeVectors covers draft §3.2, §11.8, and §12.1.
//
// Each case is one log size: the leaf values (the hash of each LogEntry), the
// root, the full subtree heads a verifier retains, and a batch proof for each
// requested combination of proven leaves and retained view.
//
// The proofs come from katie's log.Tree.GetBatch, which is the same code path a
// running log serves from. `proof` is the wire-encoded structs.InclusionProof so
// the Rust side checks its §12.1 encoding and not only the element values.
func logTreeVectors(sha string) (*File, error) {
	cs := suites.KTSha256Ed25519{}

	f := &File{
		Primitive: "log-tree",
		Draft:     draftRev + " §3.2, §11.8, §12.1",
		Generator: Generator{Impl: "katie", SHA: sha},
		Notes: "Left-balanced log tree. `leaf_values` are Hash(LogEntry) for each entry; " +
			"`root` is the tree root; `full_subtrees` are the heads a verifier retains for " +
			"a tree of that size, left to right. Each request is a batch proof: " +
			"`proven_leaves` are the leaf indices being shown, `retained_size` is a smaller " +
			"tree the verifier already saw (its full subtree heads are the ones listed for " +
			"that size), and `proof` is the wire-encoded InclusionProof. A request with no " +
			"proven leaves and a retained size is a pure consistency proof; one with proven " +
			"leaves and no retained size is a pure inclusion proof; one with both is the " +
			"batched form, including the §12.1 case where a proven leaf sits inside a " +
			"retained subtree.",
	}

	// Sizes at and around the powers of two, where the left-balanced structure
	// changes shape, plus a few larger ones.
	sizes := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 15, 16, 17, 31, 32, 33, 50, 64, 100}

	for _, size := range sizes {
		entries := logEntries(size)

		// Build the tree, collecting each leaf value and the full subtree heads.
		store := memory.NewLogStore()
		tree := log.NewTree(cs, store)
		leafValues := make([]string, 0, size)
		var fullSubtrees [][]byte
		for i, entry := range entries {
			value, err := entry.Hash(cs)
			if err != nil {
				return nil, fmt.Errorf("size %d: hashing entry %d: %w", size, i, err)
			}
			leafValues = append(leafValues, hex.EncodeToString(value))
			fullSubtrees, err = tree.Append(uint64(i), value)
			if err != nil {
				return nil, fmt.Errorf("size %d: appending entry %d: %w", size, i, err)
			}
		}
		root, err := log.Root(cs, size, fullSubtrees)
		if err != nil {
			return nil, fmt.Errorf("size %d: computing root: %w", size, err)
		}

		asked := make([]map[string]any, 0)
		answered := make([]map[string]any, 0)
		for _, req := range logProofRequests(size) {
			var retained *uint64
			if req.retainedSize != 0 {
				value := req.retainedSize
				retained = &value
			}
			// GetBatch's `m` argument is the verifier's previously observed size,
			// which is exactly the retained view.
			elements, err := tree.GetBatch(req.leaves, size, nil, retained)
			if err != nil {
				return nil, fmt.Errorf(
					"size %d: batch proof for %v with retained %v: %w",
					size, req.leaves, req.retainedSize, err)
			}
			wire, err := structs.Marshal(&structs.InclusionProof{Elements: elements})
			if err != nil {
				return nil, fmt.Errorf("size %d: marshalling proof: %w", size, err)
			}

			// The request parameters go in `input`, the proof they produce in
			// `expect`, positionally paired. Repeating either side would make the
			// file twice the size for no extra assertion.
			request := map[string]any{"proven_leaves": req.leaves}
			if retained != nil {
				request["retained_size"] = *retained
			}
			asked = append(asked, request)
			answered = append(answered, map[string]any{
				"proof":    hex.EncodeToString(wire),
				"elements": hexAll(elements),
			})
		}

		f.Cases = append(f.Cases, Case{
			Name: fmt.Sprintf("size-%d", size),
			Input: map[string]any{
				"entries":  entryJSON(entries),
				"requests": asked,
			},
			Expect: map[string]any{
				"leaf_values":   leafValues,
				"root":          hex.EncodeToString(root),
				"full_subtrees": hexAll(fullSubtrees),
				"proofs":        answered,
			},
		})
	}

	return f, nil
}

// logProofRequest is one batch proof to generate.
type logProofRequest struct {
	leaves       []uint64
	retainedSize uint64 // 0 means the verifier advertised nothing.
}

// logProofRequests picks the proofs worth recording for a tree of this size:
// each single leaf (for small trees), the ends and middle (for larger ones),
// every consistency step, and the §12.1 overlap where a proven leaf is inside a
// retained subtree.
func logProofRequests(size uint64) []logProofRequest {
	out := make([]logProofRequest, 0)

	singles := make([]uint64, 0)
	if size <= 17 {
		for i := uint64(0); i < size; i++ {
			singles = append(singles, i)
		}
	} else {
		singles = append(singles, 0, size/2, size-1)
	}
	for _, i := range singles {
		out = append(out, logProofRequest{leaves: []uint64{i}})
	}

	// A batch of several leaves, and the degenerate batch of all of them.
	if size >= 4 {
		out = append(out, logProofRequest{leaves: []uint64{0, size / 2, size - 1}})
	}
	if size <= 8 {
		all := make([]uint64, 0, size)
		for i := uint64(0); i < size; i++ {
			all = append(all, i)
		}
		out = append(out, logProofRequest{leaves: all})
	}

	// Consistency from every earlier size, or a sample for larger trees.
	for old := uint64(1); old <= size; old++ {
		if size > 17 && old != 1 && old != size/2 && old != size-1 && old != size {
			continue
		}
		out = append(out, logProofRequest{leaves: []uint64{}, retainedSize: old})

		// And the batched form: a leaf inside the retained portion, which is the
		// §12.1 edge case, plus one outside it.
		if old >= 2 {
			out = append(out, logProofRequest{leaves: []uint64{old / 2}, retainedSize: old})
		}
		if old < size {
			out = append(out, logProofRequest{leaves: []uint64{size - 1}, retainedSize: old})
		}
	}

	return out
}

// logEntries builds a deterministic run of LogEntry structures.
func logEntries(size uint64) []*structs.LogEntry {
	out := make([]*structs.LogEntry, 0, size)
	for i := uint64(0); i < size; i++ {
		prefixTree := make([]byte, 32)
		for j := range prefixTree {
			prefixTree[j] = byte(i) ^ byte(j)
		}
		out = append(out, &structs.LogEntry{
			// A fixed base so regeneration is a no-op diff, incrementing so the
			// timestamps are monotonic as §4.1 requires of a real log.
			Timestamp:  1_700_000_000_000 + i*1_000,
			PrefixTree: prefixTree,
		})
	}
	return out
}

func entryJSON(entries []*structs.LogEntry) []map[string]any {
	out := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		out = append(out, map[string]any{
			"timestamp":   entry.Timestamp,
			"prefix_tree": hex.EncodeToString(entry.PrefixTree),
		})
	}
	return out
}

// prefixTreeVectors covers draft §3.3, §11.9, and §12.2.
//
// Each case builds a prefix tree from a set of entries and records the root, then
// a batch search proof for a chosen set of search keys. The searches deliberately
// mix all three §12.2 result types, including keys that leave the tree
// immediately and keys that collide deep into the tree.
//
// `proof` is the wire-encoded PrefixProof, which is what pins the two readings of
// §12.2 that the draft leaves implicit: what `depth` counts for a
// `nonInclusionParent` result, and whether the child slot that terminates such a
// search consumes an element.
func prefixTreeVectors(sha string) (*File, error) {
	cs := suites.KTSha256Ed25519{}

	f := &File{
		Primitive: "prefix-tree",
		Draft:     draftRev + " §3.3, §11.9, §12.2",
		Generator: Generator{Impl: "katie", SHA: sha},
		Notes: "Prefix tree over VRF outputs. `entries` are inserted in the order given; " +
			"`root` is the resulting root hash. `searches` are looked up as one batch and " +
			"`proof` is the wire-encoded PrefixProof, with `results` and `elements` broken " +
			"out. Result types are 1 = inclusion, 2 = nonInclusionLeaf, 3 = " +
			"nonInclusionParent. `depth` counts the bits consumed to reach the terminal " +
			"node, so for nonInclusionParent it is the depth of the absent child slot, one " +
			"below the parent that lacks it.",
	}

	for _, spec := range prefixCases() {
		store := memory.NewPrefixStore()
		tree := prefix.NewTree(cs, store)

		add := make([]prefix.Entry, 0, len(spec.entries))
		for _, entry := range spec.entries {
			add = append(add, prefix.Entry{
				VrfOutput:  entry.vrfOutput,
				Commitment: entry.commitment,
			})
		}
		root, _, _, err := tree.Mutate(0, add, nil)
		if err != nil {
			return nil, fmt.Errorf("case %q: building the tree: %w", spec.name, err)
		}

		results, err := tree.Search([]prefix.PrefixSearch{{Version: 1, VrfOutputs: spec.searches}})
		if err != nil {
			return nil, fmt.Errorf("case %q: searching: %w", spec.name, err)
		}
		if len(results) != 1 {
			return nil, fmt.Errorf("case %q: expected one search result set", spec.name)
		}
		proof := results[0].Proof

		// Sanity: katie must verify its own proof against its own root, or the
		// vector is worthless.
		entries := make([]prefix.Entry, 0, len(spec.searches))
		for i, key := range spec.searches {
			entry := prefix.Entry{VrfOutput: key}
			if i < len(results[0].Commitments) {
				entry.Commitment = results[0].Commitments[i]
			}
			entries = append(entries, entry)
		}
		if err := prefix.Verify(cs, entries, &proof, root); err != nil {
			return nil, fmt.Errorf("case %q: katie rejects its own proof: %w", spec.name, err)
		}

		var buf bytes.Buffer
		if err := proof.Marshal(&buf); err != nil {
			return nil, fmt.Errorf("case %q: marshalling proof: %w", spec.name, err)
		}

		f.Cases = append(f.Cases, Case{
			Name: spec.name,
			Input: map[string]any{
				"entries":  prefixEntryJSON(spec.entries),
				"searches": hexAll(spec.searches),
			},
			Expect: map[string]any{
				"root":     hex.EncodeToString(root),
				"proof":    hex.EncodeToString(buf.Bytes()),
				"results":  searchResultJSON(proof.Results),
				"elements": hexAll(proof.Elements),
				// The commitments katie returns for the searches it found, in
				// request order, empty where the search was not an inclusion.
				"commitments": hexAll(results[0].Commitments),
			},
		})
	}

	return f, nil
}

type prefixEntry struct {
	vrfOutput, commitment []byte
}

type prefixCase struct {
	name     string
	entries  []prefixEntry
	searches [][]byte
}

// prefixKey builds a 32-byte search key whose leading bits are `bits` and whose
// last byte is `tag`, so keys can be written to collide for a chosen depth while
// staying distinct.
func prefixKey(bits []byte, tag byte) []byte {
	out := make([]byte, 32)
	for i, b := range bits {
		if b == 1 {
			out[i/8] |= 1 << (7 - (i % 8))
		}
	}
	out[31] = tag
	return out
}

func prefixCases() []prefixCase {
	entry := func(bits []byte, tag byte, commitment byte) prefixEntry {
		return prefixEntry{
			vrfOutput:  prefixKey(bits, tag),
			commitment: repeat(commitment, 32),
		}
	}

	// The tree drawn in draft §3.3: 00010, 00101, 10001, 10111, 11011.
	figure := []prefixEntry{
		entry([]byte{0, 0, 0, 1, 0}, 0x01, 0xa1),
		entry([]byte{0, 0, 1, 0, 1}, 0x02, 0xb2),
		entry([]byte{1, 0, 0, 0, 1}, 0x03, 0xc3),
		entry([]byte{1, 0, 1, 1, 1}, 0x04, 0xd4),
		entry([]byte{1, 1, 0, 1, 1}, 0x05, 0xe5),
	}
	figureKeys := make([][]byte, 0, len(figure))
	for _, e := range figure {
		figureKeys = append(figureKeys, e.vrfOutput)
	}

	// Keys that agree for many bits, so the tree grows a long thin spine.
	deep := []prefixEntry{
		entry(repeatBits(0, 40), 0x10, 0x11),
		entry(append(repeatBits(0, 40), 1), 0x11, 0x22),
		entry(append(repeatBits(0, 20), 1), 0x12, 0x33),
	}
	deepKeys := make([][]byte, 0, len(deep))
	for _, e := range deep {
		deepKeys = append(deepKeys, e.vrfOutput)
	}

	// A wide tree: 64 keys spread across the first byte.
	wide := make([]prefixEntry, 0, 64)
	for i := 0; i < 64; i++ {
		key := make([]byte, 32)
		key[0] = byte(i * 4)
		key[31] = byte(i)
		wide = append(wide, prefixEntry{vrfOutput: key, commitment: repeat(byte(i), 32)})
	}

	return []prefixCase{
		{
			name:     "single-entry-inclusion",
			entries:  figure[:1],
			searches: [][]byte{figure[0].vrfOutput},
		},
		{
			// A one-entry tree searched for a different key: the root leaf is the
			// terminal, so this is a nonInclusionLeaf at depth 0.
			name:     "single-entry-non-inclusion-leaf",
			entries:  figure[:1],
			searches: [][]byte{prefixKey([]byte{1, 1, 1, 1, 1}, 0x7f)},
		},
		{
			name:     "figure-each-key-included",
			entries:  figure,
			searches: figureKeys,
		},
		{
			name:     "figure-inclusion-one-key",
			entries:  figure,
			searches: [][]byte{figure[2].vrfOutput},
		},
		{
			// 00011 shares three bits with 00010, whose leaf is the terminal.
			name:     "figure-non-inclusion-leaf",
			entries:  figure,
			searches: [][]byte{prefixKey([]byte{0, 0, 0, 1, 1}, 0x20)},
		},
		{
			// Nothing begins 01, so the search leaves the tree after two bits.
			name:     "figure-non-inclusion-parent",
			entries:  figure,
			searches: [][]byte{prefixKey([]byte{0, 1, 0, 0, 0}, 0x21)},
		},
		{
			name:    "figure-mixed-result-types",
			entries: figure,
			searches: [][]byte{
				figure[0].vrfOutput,
				prefixKey([]byte{0, 1, 0, 0, 0}, 0x22),
				prefixKey([]byte{0, 0, 0, 1, 1}, 0x23),
				figure[4].vrfOutput,
				prefixKey([]byte{1, 1, 1, 1, 1}, 0x24),
			},
		},
		{
			name:     "deep-spine-inclusion",
			entries:  deep,
			searches: deepKeys,
		},
		{
			name:    "deep-spine-non-inclusion",
			entries: deep,
			searches: [][]byte{
				prefixKey(append(repeatBits(0, 30), 1), 0x30),
				prefixKey([]byte{1}, 0x31),
			},
		},
		{
			name:     "wide-single",
			entries:  wide,
			searches: [][]byte{wide[17].vrfOutput},
		},
		{
			name:    "wide-batch",
			entries: wide,
			searches: [][]byte{
				wide[0].vrfOutput,
				wide[1].vrfOutput,
				wide[31].vrfOutput,
				wide[32].vrfOutput,
				wide[63].vrfOutput,
			},
		},
	}
}

// repeatBits returns `n` copies of `b` as a bit slice.
func repeatBits(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func prefixEntryJSON(entries []prefixEntry) []map[string]any {
	out := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		out = append(out, map[string]any{
			"vrf_output": hex.EncodeToString(entry.vrfOutput),
			"commitment": hex.EncodeToString(entry.commitment),
		})
	}
	return out
}

func searchResultJSON(results []prefix.PrefixSearchResult) []map[string]any {
	out := make([]map[string]any, 0, len(results))
	for _, res := range results {
		var buf bytes.Buffer
		res.Marshal(&buf)
		raw := buf.Bytes()
		entry := map[string]any{
			"result_type": raw[0],
			"depth":       res.Depth(),
		}
		// A nonInclusionLeaf result carries the leaf it found, between the type
		// and the depth on the wire.
		if raw[0] == 2 && len(raw) == 1+64+1 {
			entry["leaf"] = map[string]any{
				"vrf_output": hex.EncodeToString(raw[1:33]),
				"commitment": hex.EncodeToString(raw[33:65]),
			}
		}
		out = append(out, entry)
	}
	return out
}

func hexAll(values [][]byte) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, hex.EncodeToString(value))
	}
	return out
}

// updateViewVectors covers draft §4.2: the log entries whose timestamps a user
// needs in order to advance their view of the tree.
//
// katie exports UpdateView, so this is a direct oracle for the whole procedure —
// including the cases where it returns nothing at all. Those are recorded rather
// than skipped: a user whose previous rightmost entry is still on the new frontier
// is sent no timestamps, so the entries added since go unchecked, and the peer
// agreeing with us about that is the evidence it is the procedure's behaviour and
// not ours. See docs/interop.md.
func updateViewVectors(sha string) (*File, error) {
	f := &File{
		Primitive: "update-view",
		Draft:     draftRev + " §4.2",
		Generator: Generator{Impl: "katie", SHA: sha},
		Notes: "Log entry indices whose timestamps must be provided for a user to " +
			"advance their view, in the order the user checks them. `advertised` is the " +
			"tree size the user last observed, absent if they have none. An empty " +
			"`entries` is a real result and appears twice over: once when the user is " +
			"already up to date, and once — noted as `right_edge_unchecked` — when the " +
			"procedure yields nothing despite the log having grown, which happens when " +
			"the user's previous rightmost entry is still on the new frontier.",
	}

	sizes := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 16, 17, 31, 32, 50, 64, 100, 1000}
	for _, size := range sizes {
		// No previous view.
		f.Cases = append(f.Cases, Case{
			Name:  fmt.Sprintf("size-%d-no-previous-view", size),
			Input: map[string]any{"size": size},
			Expect: map[string]any{
				"entries":  indices(ktmath.UpdateView(size, nil)),
				"frontier": indices(ktmath.Frontier(size)),
			},
		})

		// Every advertised size for small trees, a sample for large ones.
		for advertised := uint64(1); advertised <= size; advertised++ {
			if size > 32 && advertised != 1 && advertised != size/2 &&
				advertised != size-1 && advertised != size &&
				advertised != 1<<log2Floor(size) {
				continue
			}
			m := advertised
			entries := ktmath.UpdateView(size, &m)
			rightEdgeUnchecked := advertised != size &&
				(len(entries) == 0 || entries[len(entries)-1] != size-1)

			f.Cases = append(f.Cases, Case{
				Name: fmt.Sprintf("size-%d-advertised-%d", size, advertised),
				Input: map[string]any{
					"size":       size,
					"advertised": advertised,
				},
				Expect: map[string]any{
					"entries":              indices(entries),
					"right_edge_unchecked": rightEdgeUnchecked,
				},
			})
		}
	}

	return f, nil
}

// indices normalizes a nil slice to an empty one, so an absent result encodes as
// `[]` rather than `null`. UpdateView returns nil when the user is already up to
// date, and a decoder should not have to treat that as a third case.
func indices(in []uint64) []uint64 {
	if in == nil {
		return []uint64{}
	}
	return in
}

// log2Floor is the exponent of the largest power of two not greater than x.
func log2Floor(x uint64) uint64 {
	k := uint64(0)
	for x>>(k+1) > 0 {
		k++
	}
	return k
}

// ladderInterpretationVectors covers draft §6.2: what a search binary ladder's
// outcomes tell a searcher about the greatest version of a label.
//
// katie exports InterpretSearchLadder, so the inference itself has an oracle — the
// verdict, not just the ladder. That matters because the ladder and the inference
// have to agree about the same stopping rules: a ladder that ends one rung early and
// an interpretation that expects one more would each look correct alone.
//
// The proofs are built as wire bytes and parsed back with katie's own
// NewPrefixProof, since its result types are unexported. That has the side benefit of
// putting the §12.2 result encoding under test again from a different direction.
func ladderInterpretationVectors(sha string) (*File, error) {
	cs := suites.KTSha256Ed25519{}

	f := &File{
		Primitive:   "ladder-interpretation",
		Draft:       draftRev + " §6.2",
		Generator:   Generator{Impl: "katie", SHA: sha},
		CipherSuite: 0x0002,
		Notes: "What a search binary ladder's outcomes say about the greatest version " +
			"of a label: -1 if it is below the target, 0 if equal, 1 if above. `results` " +
			"lists whether each lookup was an inclusion, in ladder order, as an honest " +
			"log would answer them. `verdict` is katie's InterpretSearchLadder. The " +
			"ladder and the inference share §6.2's stopping rules, so a vector that pins " +
			"only one of them would miss a disagreement about where a ladder ends.",
	}

	for target := uint32(0); target <= 40; target++ {
		for greatest := uint32(0); greatest <= 40; greatest++ {
			// Keep the file to a readable size: the interesting pairs are near the
			// diagonal, plus a spread of far-apart ones.
			near := target >= greatest && target-greatest <= 2
			if greatest > target {
				near = greatest-target <= 2
			}
			if !near && !(target%13 == 0 && greatest%13 == 0) {
				continue
			}

			ladder := ktmath.SearchBinaryLadder(target, greatest, nil, nil)

			// An honest log's outcomes, stopping where §6.2 says to stop.
			results := make([]bool, 0, len(ladder))
			for _, version := range ladder {
				included := version <= greatest
				results = append(results, included)
				ends := (included && version > target) || (!included && version <= target)
				if ends {
					break
				}
			}

			proof, err := prefixProofFromOutcomes(cs, results)
			if err != nil {
				return nil, fmt.Errorf("target %d greatest %d: %w", target, greatest, err)
			}
			verdict, err := ktmath.InterpretSearchLadder(ladder, target, proof)
			if err != nil {
				return nil, fmt.Errorf(
					"target %d greatest %d: katie rejects its own ladder: %w",
					target, greatest, err)
			}
			// Sanity: the verdict must be the comparison it claims to recover.
			want := 0
			if greatest < target {
				want = -1
			} else if greatest > target {
				want = 1
			}
			if verdict != want {
				return nil, fmt.Errorf(
					"target %d greatest %d: katie says %d, expected %d",
					target, greatest, verdict, want)
			}

			f.Cases = append(f.Cases, Case{
				Name: fmt.Sprintf("target-%d-greatest-%d", target, greatest),
				Input: map[string]any{
					"target":   target,
					"greatest": greatest,
					"ladder":   ladder,
					"results":  results,
				},
				Expect: map[string]any{"verdict": verdict},
			})
		}
	}

	return f, nil
}

// prefixProofFromOutcomes builds a PrefixProof with one result per outcome —
// inclusion where true, nonInclusionParent where false — by writing the §12.2 wire
// encoding and parsing it with katie's own reader, since its result types are
// unexported.
func prefixProofFromOutcomes(cs suites.CipherSuite, outcomes []bool) (*prefix.PrefixProof, error) {
	buf := &bytes.Buffer{}
	buf.WriteByte(byte(len(outcomes)))
	for _, included := range outcomes {
		if included {
			buf.WriteByte(1) // inclusion
		} else {
			buf.WriteByte(3) // nonInclusionParent
		}
		buf.WriteByte(0) // depth
	}
	buf.WriteByte(0) // elements: two-byte count of zero
	buf.WriteByte(0)
	return prefix.NewPrefixProof(cs, buf)
}
