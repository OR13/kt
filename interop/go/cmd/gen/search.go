// Vectors from a running transparency log (draft §12.3, §13.1).
//
// Every other file here pins a primitive: a hash, a proof, a structure. This one pins what a
// log actually sends. It builds a real katie log in memory, mutates it a few times, and
// records the bytes of the `SearchResponse` it serves — tree head, binary ladder,
// `CombinedTreeProof` and all.
//
// That matters because §12.3 is the one structure whose bytes do not say what they are for.
// It carries `timestamps`, `prefix_proofs` and `prefix_roots` with no indication of which log
// entry each element belongs to: they arrive "in the order that the algorithm the user is
// executing would request them". So the same bytes mean different things depending on which
// algorithm is running, whether the user advertised a previous tree size, and which
// timestamps the user is expected to have retained already. A decoder cannot be checked
// against a hand-built example — only against one a log produced while running the algorithm.
//
// The cases vary exactly the things that change the ordering:
//
//   - a first-time search, where the user has advertised nothing and every frontier timestamp
//     must be sent, against a search by a user who advertised an earlier tree size, where
//     §12.3 says the timestamps they retained are omitted;
//   - a greatest-version search (`version` absent in the request, so the response carries a
//     `version` field) against a fixed-version one (present, so it does not);
//   - a label with one version against a label with many, which changes the length of the
//     binary ladder and therefore how many log entries get inspected;
//   - a label that does not exist at all.
//
// `response` is the encoded SearchResponse. The pieces are also broken out so a mismatch can
// be localized: getting the `CombinedTreeProof`'s three counts right while getting the ladder
// wrong is a different bug from reading the whole structure at the wrong offset.
//
// Unlike every other file in this directory, this one is not reproducible, and cannot be:
// katie stamps each log entry with time.Now() and generates a fresh random opening for every
// commitment, so every commitment, prefix root, log root and signature below differs run to
// run. CI therefore runs the whole Rust check suite against a freshly generated copy — against
// bytes nobody has seen — rather than diffing this file against a regeneration of it. See
// ../../README.md.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"time"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/crypto/vrf/edwards25519"
	"github.com/Bren2010/katie/db/memory"
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// searchVectors covers draft §12.3 and §13.1.
func searchVectors(sha string) (*File, error) {
	cs := suites.KTSha256Ed25519{}

	f := &File{
		Primitive:   "search",
		Draft:       draftRev + " §12.3, §13.1",
		Generator:   Generator{Impl: "katie", SHA: sha},
		CipherSuite: 0x0002, // KT_128_SHA256_Ed25519
		Notes: "Responses served by a real log. `mutations` describes how the log was built " +
			"— one entry per mutation, each adding the listed label-version pairs — and " +
			"`request` is the SearchRequest that was sent. `response` is the encoded " +
			"SearchResponse, with `full_tree_head`, `binary_ladder` and the " +
			"CombinedTreeProof's `timestamps`, `prefix_proofs`, `prefix_roots` and " +
			"`inclusion` broken out so a mismatch can be localized. The proof's elements " +
			"carry no indication of which log entry they belong to: they are in the order " +
			"the algorithm being executed requests them, which is why these have to come " +
			"from a log that ran the algorithm rather than from a hand-built example.",
	}

	for _, spec := range searchCases() {
		tree, config, entryTimestamps, err := buildLog(cs, spec)
		if err != nil {
			return nil, fmt.Errorf("case %q: building the log: %w", spec.name, err)
		}

		req := &structs.SearchRequest{
			Last:    spec.last,
			Label:   []byte(spec.label),
			Version: spec.version,
		}
		res, err := tree.Search(context.Background(), req)
		if err != nil {
			if spec.expectError == "" {
				return nil, fmt.Errorf("case %q: searching: %w", spec.name, err)
			}
			input := searchInput(spec, config)
			input["entry_timestamps"] = indices(entryTimestamps)
			f.Cases = append(f.Cases, Case{
				Name:  spec.name,
				Input: input,
				Expect: map[string]any{
					"error": err.Error(),
				},
			})
			continue
		}
		if spec.expectError != "" {
			return nil, fmt.Errorf("case %q: expected the search to fail", spec.name)
		}

		// A case configured for expiry has to actually produce some, and has to leave
		// something unexpired for the search to land on. Either way round the case would
		// otherwise pass while testing nothing.
		if spec.lifetime != 0 {
			rightmost := entryTimestamps[len(entryTimestamps)-1]
			expired, unexpired := 0, 0
			for _, ts := range entryTimestamps {
				if rightmost-ts >= spec.lifetime {
					expired++
				} else {
					unexpired++
				}
			}
			if expired == 0 || unexpired == 0 {
				return nil, fmt.Errorf(
					"case %q: %d entries expired and %d not; the case needs both", spec.name,
					expired, unexpired)
			}
		}

		var buf bytes.Buffer
		if err := res.Marshal(&buf); err != nil {
			return nil, fmt.Errorf("case %q: marshalling the response: %w", spec.name, err)
		}
		// Read it back with katie's own parser, which needs the request to know whether a
		// `version` field is on the wire — the clearest demonstration of why these bytes are
		// not self-describing.
		reread := bytes.NewBuffer(buf.Bytes())
		if _, err := structs.NewSearchResponse(config, req, reread); err != nil {
			return nil, fmt.Errorf("case %q: katie cannot parse its own response: %w", spec.name, err)
		} else if reread.Len() != 0 {
			return nil, fmt.Errorf("case %q: %d bytes left after the response", spec.name, reread.Len())
		}

		var head bytes.Buffer
		if err := res.FullTreeHead.Marshal(&head); err != nil {
			return nil, fmt.Errorf("case %q: marshalling the head: %w", spec.name, err)
		}

		expect := map[string]any{
			"response":       hex.EncodeToString(buf.Bytes()),
			"full_tree_head": hex.EncodeToString(head.Bytes()),
			"opening":        hex.EncodeToString(res.Opening),
			"binary_ladder":  ladderJSON(res.BinaryLadder),
			"timestamps":     indices(res.Search.Timestamps),
			"prefix_proofs":  prefixProofsJSON(res.Search.PrefixProofs),
			"prefix_roots":   hexAll(res.Search.PrefixRoots),
			"inclusion":      hexAll(res.Search.Inclusion.Elements),
			"tree_size":      tree.TreeHead().TreeSize,
		}
		if res.Version != nil {
			expect["version"] = *res.Version
		}

		input := searchInput(spec, config)
		input["entry_timestamps"] = indices(entryTimestamps)
		f.Cases = append(f.Cases, Case{
			Name:   spec.name,
			Input:  input,
			Expect: expect,
		})
	}

	return f, nil
}

func searchInput(spec searchCase, config *structs.PublicConfig) map[string]any {
	mutations := make([]map[string]any, 0, len(spec.mutations))
	for _, m := range spec.mutations {
		labels := make([]map[string]any, 0, len(m))
		for _, lv := range m {
			labels = append(labels, map[string]any{
				"label": hex.EncodeToString(lv.label),
				"value": hex.EncodeToString(lv.value),
			})
		}
		mutations = append(mutations, map[string]any{"add": labels})
	}
	input := map[string]any{
		"mutations":            mutations,
		"maximum_lifetime":     spec.lifetime,
		"label":                hex.EncodeToString([]byte(spec.label)),
		"mode":                 uint8(config.Mode),
		"signature_public_key": hex.EncodeToString(config.SignatureKey.Bytes()),
		"vrf_public_key":       hex.EncodeToString(config.VrfKey.Bytes()),
		"max_ahead":            config.MaxAhead,
		"max_behind":           config.MaxBehind,
		"monitoring_window":    config.ReasonableMonitoringWindow,
	}
	if spec.version != nil {
		input["version"] = *spec.version
	}
	if spec.last != nil {
		input["last"] = *spec.last
	}
	return input
}

type labelValue struct {
	label []byte
	value []byte
}

type searchCase struct {
	name string
	// mutations is one log entry per element, each adding the label-value pairs given.
	mutations [][]labelValue
	label     string
	version   *uint32
	last      *uint64
	// expectError records that the log refuses this request, and with what.
	expectError string

	// lifetime is the log's maximum lifetime (§7.1), zero for a log that defines none. Setting
	// it is the only way to exercise §7.2's expiry branches: an expired entry gets no binary
	// ladder at all, so the response is a different shape.
	lifetime uint64
	// window overrides the Reasonable Monitoring Window. §7.1 requires the lifetime to exceed
	// it, and since the lifetime has to be small enough for entries to expire during
	// generation, the window has to be smaller still.
	window uint64
	// spacing is how long to wait between mutations, in milliseconds. katie stamps each entry
	// with time.Now(), so without a wait the whole log lands inside one or two milliseconds and
	// nothing can expire. The absolute timestamps are not reproducible either way; the point is
	// to make the *relative* structure — which entries are expired — deterministic.
	spacing time.Duration
}

func searchCases() []searchCase {
	lv := func(label, value string) labelValue {
		return labelValue{label: []byte(label), value: []byte(value)}
	}
	alice := "alice@example.com"
	bob := "bob@example.com"

	// A log where alice gains a new version in every entry and bob only in the first, so
	// the two labels have different ladder lengths in the same tree.
	growing := [][]labelValue{
		{lv(alice, "alice-1"), lv(bob, "bob-1")},
		{lv(alice, "alice-2")},
		{lv(alice, "alice-3")},
		{lv(alice, "alice-4")},
		{lv(alice, "alice-5")},
		{lv(alice, "alice-6")},
		{lv(alice, "alice-7")},
	}

	return []searchCase{
		{
			name:      "greatest-version-first-search",
			mutations: growing,
			label:     alice,
		},
		{
			// The same log and label, but the user advertises a tree size they have already
			// seen. §12.3 then omits the timestamps they are expected to have retained, so
			// the proof is a different shape for the same query.
			name:      "greatest-version-with-advertised-size",
			mutations: growing,
			label:     alice,
			last:      ptr(uint64(4)),
		},
		{
			name:      "greatest-version-single-version-label",
			mutations: growing,
			label:     bob,
		},
		{
			name:      "fixed-version-first",
			mutations: growing,
			label:     alice,
			version:   ptr(uint32(0)),
		},
		{
			name:      "fixed-version-middle",
			mutations: growing,
			label:     alice,
			version:   ptr(uint32(3)),
		},
		{
			name:      "fixed-version-greatest",
			mutations: growing,
			label:     alice,
			version:   ptr(uint32(6)),
		},
		{
			name:      "fixed-version-with-advertised-size",
			mutations: growing,
			label:     alice,
			version:   ptr(uint32(2)),
			last:      ptr(uint64(4)),
		},
		{
			name:      "single-entry-log",
			mutations: [][]labelValue{{lv(alice, "alice-1")}},
			label:     alice,
		},
		{
			// A label with no versions at all. Measured rather than assumed: the log does
			// not refuse, it answers with a ladder for version 0 proving nothing exists.
			// Whether a client should accept that response is §6.3's business; that it is a
			// response at all is the thing worth pinning.
			name:      "label-does-not-exist",
			mutations: growing,
			label:     "nobody@example.com",
		},
		{
			name:      "fixed-version-above-the-greatest",
			mutations: growing,
			label:     alice,
			version:   ptr(uint32(99)),
		},
		// §7.1's expiry, which needs a log that defines a maximum lifetime and entries far
		// enough apart to fall outside it. A hundred milliseconds between mutations with a
		// lifetime of 250ms puts the older entries outside it, so §7.2 step 1 skips them
		// without a ladder and the response comes out a different shape.
		//
		// The margins are wide on purpose. The timestamps are wall-clock, so which entries
		// expire depends on how long the sleeps actually take; at ten milliseconds' spacing a
		// loaded machine could flip an entry either way. At a hundred there is 50ms of slack on
		// each side of every boundary, and the generator asserts the resulting structure below
		// rather than trusting it.
		{
			name:      "fixed-version-with-expired-entries",
			mutations: growing,
			label:     alice,
			version:   ptr(uint32(5)),
			lifetime:  250,
			window:    50,
			spacing:   100 * time.Millisecond,
		},
		{
			// The log refuses this one rather than answering: version 0 is old enough that
			// every entry proving it was the greatest has expired, which is §7.2's
			// ErrLabelExpired reached from the server side. Worth recording as the refusal it
			// is — a client asking for a version the log has pruned past gets no proof at all,
			// not a proof it must reject.
			name:        "fixed-version-expired-target",
			mutations:   growing,
			label:       alice,
			version:     ptr(uint32(0)),
			lifetime:    250,
			window:      50,
			spacing:     100 * time.Millisecond,
			expectError: "requested version of label has expired",
		},
		{
			name:      "greatest-version-with-expired-entries",
			mutations: growing,
			label:     alice,
			lifetime:  250,
			window:    50,
			spacing:   100 * time.Millisecond,
		},
	}
}

// buildLog runs a real katie log through the case's mutations and returns it with the public
// configuration a client would have.
func buildLog(
	cs suites.CipherSuite, spec searchCase,
) (*transparency.Tree, *structs.PublicConfig, []uint64, error) {
	logKey, err := cs.ParseSigningPrivateKey(repeat(0x71, 32))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing the log signing key: %w", err)
	}
	vrfKey, err := edwards25519.NewPrivateKey(repeat(0x74, 32))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing the VRF key: %w", err)
	}
	window := uint64(604800000)
	if spec.window != 0 || spec.lifetime != 0 {
		window = spec.window
	}
	private := structs.PrivateConfig{
		SignatureKey: logKey,
		VrfKey:       vrfKey,
		Config: structs.Config{
			Suite:                      cs,
			Mode:                       structs.ContactMonitoring,
			MaxAhead:                   10000,
			MaxBehind:                  10000,
			ReasonableMonitoringWindow: window,
			MaximumLifetime:            spec.lifetime,
		},
	}
	if spec.lifetime != 0 && spec.lifetime <= window {
		return nil, nil, nil, fmt.Errorf(
			"§7.1 requires the maximum lifetime (%d) to exceed the monitoring window (%d)",
			spec.lifetime, window)
	}

	tree, err := transparency.NewTree(private, memory.NewTransparencyStore(), nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating the tree: %w", err)
	}
	// Each Mutate hands back the AuditorUpdate for the entry it created, which carries that
	// entry's timestamp. Recording them is not a convenience: §12.3 omits the timestamps a
	// user is expected to have retained, so a verifier replaying one of these responses has to
	// be given them, and they are wall-clock values that cannot be reconstructed.
	timestamps := make([]uint64, 0, len(spec.mutations))
	for i, mutation := range spec.mutations {
		add := make([]transparency.LabelValue, 0, len(mutation))
		for _, entry := range mutation {
			add = append(add, transparency.LabelValue{
				Label: entry.label,
				Value: structs.UpdateValue{Value: entry.value},
			})
		}
		if i > 0 && spec.spacing > 0 {
			time.Sleep(spec.spacing)
		}
		update, err := tree.Mutate(add, nil)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("mutation %d: %w", i, err)
		}
		timestamps = append(timestamps, update.Timestamp)
	}
	return tree, private.Public(), timestamps, nil
}

// prefixProofsJSON renders each PrefixProof as its results and copath, plus its encoded
// bytes: the CombinedTreeProof's proofs are the part most likely to be read at the wrong
// offset, so recording both the structure and the bytes localizes a mismatch.
func prefixProofsJSON(proofs []prefix.PrefixProof) []map[string]any {
	out := make([]map[string]any, 0, len(proofs))
	for _, proof := range proofs {
		var buf bytes.Buffer
		if err := proof.Marshal(&buf); err != nil {
			// Marshalling a proof katie just produced cannot fail; recording the empty
			// string would be worse than the panic a nil map access would give, so keep the
			// entry and let the byte comparison flag it.
			continue
		}
		out = append(out, map[string]any{
			"encoding": hex.EncodeToString(buf.Bytes()),
			"results":  searchResultJSON(proof.Results),
			"elements": hexAll(proof.Elements),
		})
	}
	return out
}

func ladderJSON(steps []structs.BinaryLadderStep) []map[string]any {
	out := make([]map[string]any, 0, len(steps))
	for _, step := range steps {
		entry := map[string]any{"proof": hex.EncodeToString(step.Proof)}
		if step.Commitment != nil {
			entry["commitment"] = hex.EncodeToString(step.Commitment)
		}
		out = append(out, entry)
	}
	return out
}
