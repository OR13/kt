// Vectors for growing a log tree one leaf at a time (draft §3.2, §11.8).
//
// Everything else in this directory treats the log tree as a thing that already exists:
// a prover holds every leaf, and both sides hash them into a root. A §15.2 auditor cannot
// do that. It never holds the log, only the head values of the current tree's full
// subtrees — `popcount(size)` hashes, so under 64 for any log that can exist — and it has
// to carry them forward one entry at a time, because the root each `AuditorTreeHead`
// signature covers is the root after that entry.
//
// Which makes this worth pinning separately: a root computed by folding retained heads
// bottom-up and a root computed by walking every leaf top-down share only the
// `hashContent` rule of §11.8. They can agree at one size and diverge at the next, and the
// only place the difference shows up is a signature nobody can verify.
//
// The two implementations get there differently, which is the point of comparing them.
// katie indexes a chain by level and propagates a carry through it; this implementation
// keeps subtree lengths beside their heads and merges the rightmost pair while the lengths
// match. Both are binary counting, written down twice.
//
// Each case records the state after appending leaf `size-1`: the heads left to right, and
// the root they fold to. `leaves` gives the leaf values so a reader can rebuild the tree
// the other way and confirm the root independently.
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// appendVectors covers draft §3.2 and §11.8, incrementally.
func appendVectors(sha string) (*File, error) {
	cs := suites.KTSha256Ed25519{}

	f := &File{
		Primitive:   "log-append",
		Draft:       draftRev + " §3.2, §11.8",
		Generator:   Generator{Impl: "katie", SHA: sha},
		CipherSuite: 0x0002, // KT_128_SHA256_Ed25519
		Notes: "A log tree grown one leaf at a time, as a §15.2 auditor must grow it: it " +
			"holds no leaves, only the head values of the current tree's full subtrees. " +
			"Each case is the state after appending leaf `size-1` — `full_subtrees` left " +
			"to right, and the `root` they fold to. The head count is the population " +
			"count of the size, because each merge is a carry. `leaves` are the leaf " +
			"values, so the root can be rebuilt from every leaf instead and compared.",
	}

	// Deterministic entries, matching the shape the log-tree vectors use so the two files
	// describe the same trees.
	leaves := make([][]byte, 0, 64)
	entries := make([]structs.LogEntry, 0, 64)
	for i := range 64 {
		prefixTree := make([]byte, cs.HashSize())
		for j := range prefixTree {
			prefixTree[j] = byte(i) ^ byte(j)
		}
		entry := structs.LogEntry{
			Timestamp:  1700000000000 + uint64(i)*1000,
			PrefixTree: prefixTree,
		}
		leaf, err := entry.Hash(cs)
		if err != nil {
			return nil, fmt.Errorf("hashing entry %d: %w", i, err)
		}
		entries = append(entries, entry)
		leaves = append(leaves, leaf)
	}

	var fullSubtrees [][]byte
	for i := range leaves {
		size := uint64(i) + 1

		var err error
		fullSubtrees, err = log.Append(cs, uint64(i), fullSubtrees, leaves[i])
		if err != nil {
			return nil, fmt.Errorf("appending leaf %d: %w", i, err)
		}
		root, err := log.Root(cs, size, fullSubtrees)
		if err != nil {
			return nil, fmt.Errorf("rooting at size %d: %w", size, err)
		}

		// The head count has to be the population count of the size, or the incremental
		// path has drifted from the shape §3.2 defines and the vector is worthless.
		if want := popcount(size); len(fullSubtrees) != want {
			return nil, fmt.Errorf(
				"size %d: katie kept %d heads, the shape calls for %d",
				size, len(fullSubtrees), want)
		}

		f.Cases = append(f.Cases, Case{
			Name: fmt.Sprintf("size-%d", size),
			Input: map[string]any{
				"size": size,
				"entries": []map[string]any{{
					"timestamp":   entries[i].Timestamp,
					"prefix_tree": hex.EncodeToString(entries[i].PrefixTree),
				}},
				"leaves": hexAll(leaves[:size]),
			},
			Expect: map[string]any{
				"full_subtrees": hexAll(fullSubtrees),
				"root":          hex.EncodeToString(root),
			},
		})
	}

	return f, nil
}

func popcount(n uint64) int {
	count := 0
	for n > 0 {
		count += int(n & 1)
		n >>= 1
	}
	return count
}
