// Vectors for the monitoring operations, served by a running log (draft §13.2, §13.3, §13.4).
//
// Monitoring is the other half of what makes key transparency work, and it is the half that
// asks a different question. A searcher wants to know what a label's value is, so its response
// carries commitments and an opening. A monitor already knows, and is asking only whether the
// log has kept it where it was — so a `ContactMonitorResponse` is a tree head and a proof, and
// nothing else. Everything is in the ordering.
//
// Which is why these are recorded from a real log rather than built by hand. §12.3.4 through
// §12.3.6 give three more element orderings, and they differ from the search orderings in a way
// that matters: monitoring iterates the user's map "from rightmost to leftmost log entry", so
// the timestamps arrive in descending position order and §12.3's monotonicity requirement — that
// each timestamp be at least every timestamp to its *left* — is checked against entries that
// have not been read yet.
//
// Like search.json, this file is not reproducible and cannot be: the log stamps each entry with
// time.Now() and draws a fresh random opening per commitment. CI runs the whole check suite
// against a freshly generated copy rather than diffing this one against a regeneration; see
// ../../README.md.
//
// The monitoring map in each request is the state a user would hold after a search: a position
// mapped to the version proven to exist there. katie validates that each position is the entry
// that first contained the version or on its right direct path, so these are the maps a real
// client would arrive at, not arbitrary pairs.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/Bren2010/katie/crypto/commitments"
	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/crypto/vrf"
	"github.com/Bren2010/katie/crypto/vrf/edwards25519"
	"github.com/Bren2010/katie/tree/transparency"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// monitorVectors covers draft §13.2, §13.3, and §13.4.
func monitorVectors(sha string) (*File, error) {
	cs := suites.KTSha256Ed25519{}

	f := &File{
		Primitive:   "monitor",
		Draft:       draftRev + " §13.2, §13.3, §13.4",
		Generator:   Generator{Impl: "katie", SHA: sha},
		CipherSuite: 0x0002, // KT_128_SHA256_Ed25519
		Notes: "Monitoring responses served by a real log. `operation` selects which: " +
			"`contact` for §13.2, `owner-init` for §13.3, `owner-monitor` for §13.4. " +
			"`entries` is the user's monitoring map — a position mapped to the version proven " +
			"to exist there, which is the state a search leaves behind — and `start` is the " +
			"rightmost distinguished entry an owner has verified. `response` is the encoded " +
			"response, with the CombinedTreeProof's parts broken out. The proofs' element " +
			"order comes from §12.3.4 through §12.3.6, which iterate the map from rightmost " +
			"to leftmost rather than descending, so the timestamps arrive in descending " +
			"position order.",
	}

	for _, spec := range monitorCases() {
		tree, config, entryTimestamps, err := buildLog(cs, spec.log)
		if err != nil {
			return nil, fmt.Errorf("case %q: building the log: %w", spec.name, err)
		}

		entries := make([]structs.MonitorMapEntry, 0, len(spec.entries))
		for _, e := range spec.entries {
			entries = append(entries, structs.MonitorMapEntry{Position: e.position, Version: e.version})
		}

		var (
			raw       bytes.Buffer
			head      structs.FullTreeHead
			proof     structs.CombinedTreeProof
			versions  []uint32
			ladder    []structs.BinaryLadderStep
			operation = spec.operation
		)
		switch operation {
		case "contact":
			res, err := tree.ContactMonitor(context.Background(), &structs.ContactMonitorRequest{
				Last:    spec.last,
				Label:   []byte(spec.label),
				Entries: entries,
			})
			if err != nil {
				return nil, fmt.Errorf("case %q: contact monitor: %w", spec.name, err)
			}
			if err := res.Marshal(&raw); err != nil {
				return nil, fmt.Errorf("case %q: marshalling: %w", spec.name, err)
			}
			head, proof = res.FullTreeHead, res.Monitor
		case "owner-init":
			res, err := tree.OwnerInit(context.Background(), &structs.OwnerInitRequest{
				Last:  spec.last,
				Label: []byte(spec.label),
				Start: spec.start,
			})
			if err != nil {
				return nil, fmt.Errorf("case %q: owner init: %w", spec.name, err)
			}
			if err := res.Marshal(&raw); err != nil {
				return nil, fmt.Errorf("case %q: marshalling: %w", spec.name, err)
			}
			head, proof = res.FullTreeHead, res.Init
			versions, ladder = res.GreatestVersions, res.BinaryLadder
		case "owner-monitor":
			res, err := tree.OwnerMonitor(context.Background(), &structs.OwnerMonitorRequest{
				Last:            spec.last,
				Label:           []byte(spec.label),
				Entries:         entries,
				Start:           spec.start,
				GreatestVersion: spec.greatestVersion,
			})
			if err != nil {
				return nil, fmt.Errorf("case %q: owner monitor: %w", spec.name, err)
			}
			if err := res.Marshal(&raw); err != nil {
				return nil, fmt.Errorf("case %q: marshalling: %w", spec.name, err)
			}
			head, proof = res.FullTreeHead, res.Monitor
		default:
			return nil, fmt.Errorf("case %q: unknown operation %q", spec.name, operation)
		}

		var headBytes bytes.Buffer
		if err := head.Marshal(&headBytes); err != nil {
			return nil, fmt.Errorf("case %q: marshalling the head: %w", spec.name, err)
		}

		// What a monitoring client already holds. §8.2 says the map is populated from a search,
		// so by the time a user monitors they have the VRF output and the commitment for every
		// version they are tracking — a monitoring response carries neither, because there would
		// be no point in sending them again. Recording them here is what lets a verifier replay
		// the algorithm; deriving them is not possible from the public key alone, which is the
		// whole reason a monitoring response is as small as it is.
		vrfPrivate, err := edwards25519.NewPrivateKey(repeat(0x74, 32))
		if err != nil {
			return nil, fmt.Errorf("case %q: parsing the VRF key: %w", spec.name, err)
		}
		known, kerr := knownVersions(
			cs, tree, vrfPrivate, []byte(spec.label), spec.entries, spec.greatestVersion)
		if kerr != nil {
			return nil, fmt.Errorf("case %q: %w", spec.name, kerr)
		}
		input := map[string]any{
			"known_versions":       known,
			"operation":            operation,
			"mutations":            mutationsJSON(spec.log.mutations),
			"label":                hex.EncodeToString([]byte(spec.label)),
			"entries":              monitorEntriesJSON(entries),
			"mode":                 uint8(config.Mode),
			"signature_public_key": hex.EncodeToString(config.SignatureKey.Bytes()),
			"vrf_public_key":       hex.EncodeToString(config.VrfKey.Bytes()),
			"monitoring_window":    config.ReasonableMonitoringWindow,
			"maximum_lifetime":     config.MaximumLifetime,
			"entry_timestamps":     indices(entryTimestamps),
			"start":                spec.start,
		}
		if spec.last != nil {
			input["last"] = *spec.last
		}
		if spec.greatestVersion != nil {
			input["greatest_version"] = *spec.greatestVersion
		}

		expect := map[string]any{
			"response":       hex.EncodeToString(raw.Bytes()),
			"full_tree_head": hex.EncodeToString(headBytes.Bytes()),
			"timestamps":     indices(proof.Timestamps),
			"prefix_proofs":  prefixProofsJSON(proof.PrefixProofs),
			"prefix_roots":   hexAll(proof.PrefixRoots),
			"inclusion":      hexAll(proof.Inclusion.Elements),
			"tree_size":      tree.TreeHead().TreeSize,
		}
		if versions != nil {
			expect["greatest_versions"] = indices32(versions)
		}
		if ladder != nil {
			expect["binary_ladder"] = ladderJSON(ladder)
		}

		f.Cases = append(f.Cases, Case{Name: spec.name, Input: input, Expect: expect})
	}

	return f, nil
}

type mapEntry struct {
	position uint64
	version  uint32
}

type monitorCase struct {
	name            string
	operation       string
	log             searchCase
	label           string
	entries         []mapEntry
	start           uint64
	greatestVersion *uint32
	last            *uint64
}

func monitorCases() []monitorCase {
	lv := func(label, value string) labelValue {
		return labelValue{label: []byte(label), value: []byte(value)}
	}
	alice := "alice@example.com"

	// A log where alice gains one version per entry, so version v first appears at entry v and
	// `{position: v, version: v}` is a monitoring map entry a real client would hold.
	growing := searchCase{
		mutations: [][]labelValue{
			{lv(alice, "alice-1")},
			{lv(alice, "alice-2")},
			{lv(alice, "alice-3")},
			{lv(alice, "alice-4")},
			{lv(alice, "alice-5")},
			{lv(alice, "alice-6")},
			{lv(alice, "alice-7")},
		},
	}

	// The same log, with the entries spaced out in real time and a window small enough that most
	// of them are distinguished. §7.1 requires a maximum lifetime to exceed the window; there is
	// none here, so only the window matters.
	spaced := growing
	spaced.window = 50
	spaced.spacing = 100 * time.Millisecond

	return []monitorCase{
		{
			name:      "contact-one-version",
			operation: "contact",
			log:       growing,
			label:     alice,
			entries:   []mapEntry{{position: 5, version: 5}},
		},
		{
			// The shape §8.2 actually does work for: entry 2 has an ancestor to its right and is
			// not itself distinguished. Two nearby shapes do nothing at all — an entry on the
			// frontier has no ancestors to its right, and a left descendant like entry 1 keeps a
			// left bracket of zero and so is always distinguished — which is why
			// `contact-one-version` above carries no prefix proofs. Having both recorded is the
			// point: the degenerate case is the common one, and a verifier that only ever sees it
			// never exercises the algorithm.
			name:      "contact-inspects-an-ancestor",
			operation: "contact",
			log:       growing,
			label:     alice,
			entries:   []mapEntry{{position: 2, version: 2}},
		},
		{
			// The same spaced log the owner-monitor case uses, so a pure contact monitor over a
			// map entry that §6.1 makes distinguished can be compared against the composed
			// operation. §8.2 step 1 says a distinguished map entry is left alone with no ladder;
			// this records what the peer actually sends.
			name:      "contact-distinguished-map-entry",
			operation: "contact",
			log:       spaced,
			label:     alice,
			entries:   []mapEntry{{position: 5, version: 5}},
		},
		{
			name:      "contact-two-versions",
			operation: "contact",
			log:       growing,
			label:     alice,
			entries:   []mapEntry{{position: 4, version: 4}, {position: 6, version: 6}},
		},
		{
			name:      "contact-with-advertised-size",
			operation: "contact",
			log:       growing,
			label:     alice,
			entries:   []mapEntry{{position: 5, version: 5}},
			last:      ptr(uint64(6)),
		},
		{
			name:      "owner-init",
			operation: "owner-init",
			log:       growing,
			label:     alice,
			start:     3,
		},
		{
			name:            "owner-monitor",
			operation:       "owner-monitor",
			log:             growing,
			label:           alice,
			entries:         []mapEntry{{position: 5, version: 5}},
			start:           3,
			greatestVersion: ptr(uint32(6)),
		},
		{
			// The shape where §8.3's second algorithm reaches step 5 at all. With a week-long
			// window only the root of a seven-entry log is distinguished, so a walk starting at
			// the root goes right, finds nothing distinguished, and stops having checked no
			// ladders — which is what `owner-monitor` above does. Spacing the entries out and
			// shrinking the window makes several entries distinguished, so there are reference
			// points to the right of the owner's start for the walk to actually check.
			name:            "owner-monitor-reaches-step-5",
			operation:       "owner-monitor",
			log:             spaced,
			label:           alice,
			entries:         []mapEntry{{position: 5, version: 5}},
			start:           1,
			greatestVersion: ptr(uint32(6)),
		},
	}
}

// knownVersions returns, for every version up to the greatest in the monitoring map, the VRF
// output and the commitment a client would hold from having searched for it.
//
// The VRF output comes from the log's own key. The commitment comes from a fixed-version search,
// which is how a client gets it: the response carries the opening and the value, and the client
// recomputes the commitment from them. Going through the search rather than reaching into the
// tree keeps this to exported API and to the path a real client takes.
func knownVersions(
	cs suites.CipherSuite,
	tree *transparency.Tree,
	vrfKey vrf.PrivateKey,
	label []byte,
	entries []mapEntry,
	advertised *uint32,
) ([]map[string]any, error) {
	// The greatest version the owner knows of: the largest in its monitoring map, or the one it
	// advertises, whichever is larger. An owner monitor targets the advertised version, which can
	// be ahead of anything still in the map.
	greatest := uint32(0)
	for _, entry := range entries {
		if entry.version > greatest {
			greatest = entry.version
		}
	}
	if advertised != nil && *advertised > greatest {
		greatest = *advertised
	}

	// Every version the owner would hold after initialization: the ones it created, plus every
	// version that appears in a search binary ladder for any of them. §8.3 step 3 makes the log
	// supply VRF proofs for exactly that set during owner init, and a client retains them — which
	// is why an owner monitoring later can check a ladder lookup for a version that has never
	// existed, such as the 7 that a ladder for version 3 reaches for.
	wanted := make(map[uint32]struct{})
	for version := uint32(0); version <= greatest; version++ {
		wanted[version] = struct{}{}
		for _, rung := range math.SearchBinaryLadder(version, version, nil, nil) {
			wanted[rung] = struct{}{}
		}
	}
	versions := make([]uint32, 0, len(wanted))
	for version := range wanted {
		versions = append(versions, version)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })

	out := make([]map[string]any, 0, len(versions))
	for _, version := range versions {
		alpha, err := structs.Marshal(&structs.VrfInput{Label: label, Version: version})
		if err != nil {
			return nil, fmt.Errorf("marshalling the VRF input for version %d: %w", version, err)
		}
		output, _ := vrfKey.Prove(alpha)

		entry := map[string]any{
			"version":    version,
			"vrf_output": hex.EncodeToString(output),
		}
		// A commitment only where the version exists. §13.3 step 2 makes the same point about
		// owner initialization: a VRF proof is provided for versions that do not exist, so that
		// their absence can be checked, and there is nothing to commit to.
		if version <= greatest {
			target := version
			res, err := tree.Search(context.Background(), &structs.SearchRequest{
				Label:   label,
				Version: &target,
			})
			if err != nil {
				return nil, fmt.Errorf("searching for version %d: %w", version, err)
			}
			commitmentValue, err := structs.Marshal(&structs.CommitmentValue{
				Label:   label,
				Version: version,
				Update:  res.Value,
			})
			if err != nil {
				return nil, fmt.Errorf(
					"marshalling the commitment value for version %d: %w", version, err)
			}
			entry["commitment"] = hex.EncodeToString(
				commitments.Commit(cs, res.Opening, commitmentValue))
		}
		out = append(out, entry)
	}
	return out, nil
}

func mutationsJSON(mutations [][]labelValue) []map[string]any {
	out := make([]map[string]any, 0, len(mutations))
	for _, m := range mutations {
		labels := make([]map[string]any, 0, len(m))
		for _, lv := range m {
			labels = append(labels, map[string]any{
				"label": hex.EncodeToString(lv.label),
				"value": hex.EncodeToString(lv.value),
			})
		}
		out = append(out, map[string]any{"add": labels})
	}
	return out
}

func indices32(in []uint32) []uint32 {
	if in == nil {
		return []uint32{}
	}
	return in
}
