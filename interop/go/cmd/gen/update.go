// Vectors for a label owner verifying an update (draft §9.1, §13.5).
//
// §9.1 is the protocol's only two-tree algorithm: it checks a claim about the boundary between
// the log as it was before the new versions were added and the log as it is now. That makes the
// element ordering inside its `CombinedTreeProof` unlike any other operation's — two descents
// for distinguished entries, a greatest-version search over the *previous* tree's frontier, then
// one or two proofs at the entry holding the new versions — and ordering is exactly what a
// hand-built example cannot pin.
//
// # What is missing here, and why
//
// Every other response in this directory comes from katie's public entry point: `tree.Search`,
// `tree.ContactMonitor`, `tree.OwnerMonitor`. The equivalent for §13.5 would be `tree.Update`,
// and it cannot be used: it fails for every request with "label owner state has not been
// initialized". Its `updater.next` builds a monitor with `algorithms.NewMonitor`, which leaves
// `Monitor.Owner` nil, and then calls `Monitor.Update`, which refuses when `Owner` is nil. No
// katie test exercises `tree.Update`, which is consistent with the path never having run.
// Measured at the pinned commit; recorded as `KT-04`, filed as Bren2010/katie#1.
//
// So these vectors drive the algorithm the way `updater.next` intends to — a
// `ProducedProofHandle` over the log's own store, `algorithms.UpdateView`, a monitor whose
// `Owner` this harness supplies, then `Monitor.Update` — and record the `CombinedTreeProof` that
// comes out. That is the part §12.3 makes hard and the part a verifier can get wrong. What it
// does not record is the `UpdateResponse` envelope around it: `position`, `info` and
// `binary_ladder` are assembled by the unreachable code path, and its `FullTreeHead`,
// `UpdateInfo` and `BinaryLadderStep` members are already pinned by tree-head.json and
// requests.json. Claiming an `UpdateResponse` was checked against the peer would be claiming
// more than was measured.
//
// # Not reproducible
//
// Like search.json and monitor.json: katie stamps each entry with time.Now() and draws a fresh
// random commitment opening per version, so every timestamp, commitment and prefix root below
// differs run to run. CI runs the Rust checks against a freshly generated copy rather than
// diffing this file. See ../../README.md.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/crypto/vrf/edwards25519"
	"github.com/Bren2010/katie/db"
	"github.com/Bren2010/katie/db/memory"
	"github.com/Bren2010/katie/tree/transparency"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
	ktmath "github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// updateCase is one owner checking one update.
type updateCase struct {
	name string
	// mutations is one log entry per element, each adding the label-value pairs given.
	mutations [][]labelValue
	label     string
	// window overrides the Reasonable Monitoring Window. A week leaves only the root
	// distinguished, which is what puts §9.1 on its step 4 branch; zero makes every entry
	// distinguished, which is the step 3 branch.
	window uint64
	// position is the log entry the new versions were added to, and versions how many.
	position uint64
	versions int
	// The owner's state before the update: the reference point it verified, the greatest version
	// that existed there — nil for a label that did not exist yet — and where each version it
	// already knows about was inserted.
	starting      uint64
	verAtStarting *uint32
	upcoming      []uint64
	// last is the tree size the owner advertised, if any. §12.3 then omits the timestamps it is
	// expected to have retained, so the same query produces a differently shaped proof.
	last *uint64
	// note explains what the case is for, and rides along into the vector file.
	note string
}

func updateCases() []updateCase {
	lv := func(label, value string) labelValue {
		return labelValue{label: []byte(label), value: []byte(value)}
	}
	alice := "alice@example.com"
	bob := "bob@example.com"
	carol := "carol@example.com"
	dave := "dave@example.com"
	erin := "erin@example.com"

	// Seven entries. alice gains a version in every one; bob gains version 0 in the first and
	// version 1 in the last, so nothing happens to it in between; carol gains three versions at
	// once in the last; dave appears for the first time in the last. Four labels, four different
	// shapes of the same algorithm over one tree.
	log := [][]labelValue{
		{lv(alice, "alice-1"), lv(bob, "bob-1"), lv(erin, "erin-1")},
		{lv(alice, "alice-2")},
		{lv(alice, "alice-3")},
		{lv(alice, "alice-4")},
		{lv(alice, "alice-5")},
		{lv(alice, "alice-6")},
		{
			lv(alice, "alice-7"), lv(bob, "bob-2"),
			lv(carol, "carol-1"), lv(carol, "carol-2"), lv(carol, "carol-3"),
			lv(dave, "dave-1"),
			lv(erin, "erin-2"), lv(erin, "erin-3"), lv(erin, "erin-4"),
		},
	}
	week := uint64(604800000)

	return []updateCase{
		{
			// The owner's last known version is in entry 5, which is the previous tree's
			// rightmost entry, so step 2.1 skips it and phase one reads nothing. Step 4 runs at
			// entry 6, with the omissions phase one's seeding produced.
			name:          "single-version-previous-frontier-skipped",
			mutations:     log,
			label:         alice,
			window:        week,
			position:      6,
			versions:      1,
			starting:      3,
			verAtStarting: ptr(uint32(3)),
			upcoming:      []uint64{4, 5},
			note: "§9.1 step 2.1: the ladder for the previous tree's rightmost entry arrived " +
				"with the update that created the owner's last version, so this response " +
				"carries none.",
		},
		{
			// Nothing happened to bob between the owner's reference point and the update, so
			// step 2.2 has a real ladder to check: entry 5 must still show version 0 as the
			// greatest.
			name:          "single-version-previous-frontier-inspected",
			mutations:     log,
			label:         bob,
			window:        week,
			position:      6,
			versions:      1,
			starting:      3,
			verAtStarting: ptr(uint32(0)),
			upcoming:      nil,
			note: "§9.1 step 2.2: a greatest-version search over the previous tree's frontier, " +
				"which is the phase that stops a log from creating a version and hiding it.",
		},
		{
			// Three versions in one entry, and a search ladder for the new greatest version
			// happens to cover all three: versions 0, 1 and 2 are all rungs of the ladder for
			// version 2. So §9.1's additional proof is empty and no second proof is sent.
			name:          "multi-version-covered-by-the-ladder",
			mutations:     log,
			label:         carol,
			window:        week,
			position:      6,
			versions:      3,
			starting:      3,
			verAtStarting: nil,
			upcoming:      nil,
			note: "Three versions at once, all of them rungs of the ladder for the new greatest " +
				"version, so §9.1 asks for no additional inclusion proof.",
		},
		{
			// The same shape one version along, where it stops being free: versions 1, 2 and 3
			// on top of version 0, and the ladder for version 3 does not look up version 2. So
			// step 4 sends a second proof from the same log entry, which is where §12.3.4's rule
			// that two proofs for one entry must agree about its prefix tree root does work.
			name:          "multi-version-with-additional-proof",
			mutations:     log,
			label:         erin,
			window:        week,
			position:      6,
			versions:      3,
			starting:      3,
			verAtStarting: ptr(uint32(0)),
			upcoming:      nil,
			note: "Versions 1 to 3 created at once. A ladder for version 3 does not look up " +
				"version 2, so §9.1 sends a second prefix proof from the same log entry.",
		},
		{
			// A label the owner is creating for the first time. The previous greatest version is
			// absent rather than zero, and step 2.2's ladder proves version 0 *absent* in the
			// previous tree instead of proving a version present.
			name:          "first-version-of-a-new-label",
			mutations:     log,
			label:         dave,
			window:        week,
			position:      6,
			versions:      1,
			starting:      3,
			verAtStarting: nil,
			upcoming:      nil,
			note: "The label did not exist at the owner's reference point, so §9.1 step 2.3 " +
				"asks for a ladder consistent with no version existing at all.",
		},
		{
			// Every entry distinguished. Step 1 finds no non-distinguished entry, so phase one
			// is skipped entirely and step 3 asks only for the versions a ladder would miss.
			// Recorded deliberately as the degenerate shape: it exercises almost nothing.
			name:          "distinguished-entry-asks-for-nothing",
			mutations:     log,
			label:         carol,
			window:        0,
			position:      6,
			versions:      3,
			starting:      3,
			verAtStarting: nil,
			upcoming:      nil,
			note: "A window of zero makes every entry distinguished, so §9.1 takes its step 3 " +
				"branch — and with every new version covered by the ladder there is nothing " +
				"left to ask for. The whole proof is the view update.",
		},
		{
			// Distinguished, but with a version the ladder misses, so step 3 does have something
			// to ask for: an inclusion proof and nothing else.
			name:          "distinguished-entry-additional-proof",
			mutations:     log,
			label:         erin,
			window:        0,
			position:      6,
			versions:      3,
			starting:      3,
			verAtStarting: ptr(uint32(0)),
			upcoming:      nil,
			note: "§9.1 step 3 on its own: the entry is distinguished so no ladder is sent, but " +
				"version 2 is not a rung of the ladder for version 3 and still needs proving.",
		},
		{
			// The same query as the first case, but the owner advertises a tree size it has
			// already seen. §12.3 then omits the timestamps it retained, so the proof is a
			// different shape for the same algorithm.
			name:          "single-version-with-advertised-size",
			mutations:     log,
			label:         alice,
			window:        week,
			position:      6,
			versions:      1,
			starting:      3,
			verAtStarting: ptr(uint32(3)),
			upcoming:      []uint64{4, 5},
			last:          ptr(uint64(5)),
			note: "The owner advertises a tree size it has seen, so the view update sends §4.2's " +
				"list rather than the whole frontier and the retained timestamps are omitted.",
		},
	}
}

// updateVectors covers draft §9.1 and §13.5.
func updateVectors(sha string) (*File, error) {
	cs := suites.KTSha256Ed25519{}

	f := &File{
		Primitive:   "update",
		Draft:       draftRev + " §9.1, §13.5",
		Generator:   Generator{Impl: "katie", SHA: sha},
		CipherSuite: 0x0002, // KT_128_SHA256_Ed25519
		Notes: "CombinedTreeProof structures for §9.1, produced by katie's own algorithm " +
			"implementation. `mutations` describes how the log was built, `owner` is the label " +
			"owner's state before the update, and `ladder` gives every search key the proof's " +
			"lookups need — the union of what the owner already held and what the response " +
			"would add. These carry no UpdateResponse envelope: katie's tree.Update cannot " +
			"answer any request (see KT-04), so the envelope was never measured and is not " +
			"claimed. The proof's elements carry no indication of which log entry they belong " +
			"to; they are in the order §9.1 asks for them.",
	}

	for _, spec := range updateCases() {
		tree, store, config, timestamps, layout, err := buildUpdateLog(cs, spec)
		if err != nil {
			return nil, fmt.Errorf("case %q: building the log: %w", spec.name, err)
		}
		index, ok := layout[spec.label]
		if !ok {
			return nil, fmt.Errorf("case %q: label %q has no versions", spec.name, spec.label)
		}
		size := tree.TreeHead().TreeSize
		if spec.position >= size {
			return nil, fmt.Errorf(
				"case %q: position %d is outside a log of %d", spec.name, spec.position, size)
		}

		// The versions the case says were created must really be the ones in `position`, or the
		// case would be checking a claim the log does not make.
		created := 0
		for _, at := range index {
			if at == spec.position {
				created++
			}
		}
		if created != spec.versions {
			return nil, fmt.Errorf(
				"case %q: %d versions were created in entry %d, not %d",
				spec.name, created, spec.position, spec.versions)
		}

		handle := algorithms.NewProducedProofHandle(cs, store, index)
		provider := algorithms.NewDataProvider(cs, handle)
		if spec.last != nil {
			retained, err := retainedEntries(cs, store, *spec.last)
			if err != nil {
				return nil, fmt.Errorf("case %q: retained entries: %w", spec.name, err)
			}
			if err := provider.AddRetained(nil, retained); err != nil {
				return nil, fmt.Errorf("case %q: adding retained entries: %w", spec.name, err)
			}
		}
		if err := algorithms.UpdateView(config, size, spec.last, provider); err != nil {
			return nil, fmt.Errorf("case %q: updating the view: %w", spec.name, err)
		}
		monitor, err := algorithms.NewMonitor(config, size, provider)
		if err != nil {
			return nil, fmt.Errorf("case %q: creating the monitor: %w", spec.name, err)
		}
		// The state tree.Update would have loaded from the client's store, and the one thing its
		// own code path leaves nil.
		monitor.Owner = &algorithms.OwnerState{
			Starting:      spec.starting,
			VerAtStarting: verAtStarting(spec.verAtStarting),
			UpcomingVers:  slices.Clone(spec.upcoming),
		}
		if err := monitor.Update(spec.position, spec.versions); err != nil {
			return nil, fmt.Errorf("case %q: §9.1: %w", spec.name, err)
		}

		// Output needs a VRF output for every version the proof looks up, which is only known
		// once the algorithm has run. The commitments come back the same way, populated from the
		// prefix tree searches the output performs.
		required := maps(handle.RequiredVersions())
		slices.Sort(required)
		for _, ver := range required {
			input, err := structs.Marshal(&structs.VrfInput{
				Label:   []byte(spec.label),
				Version: ver,
			})
			if err != nil {
				return nil, fmt.Errorf("case %q: marshalling the VRF input: %w", spec.name, err)
			}
			output, _ := privateVrfKey().Prove(input)
			if err := handle.AddVersion(ver, output); err != nil {
				return nil, fmt.Errorf("case %q: version %d: %w", spec.name, ver, err)
			}
		}
		proof, err := provider.Output(size, nil, spec.last)
		if err != nil {
			return nil, fmt.Errorf("case %q: producing the proof: %w", spec.name, err)
		}

		var buf bytes.Buffer
		if err := proof.Marshal(&buf); err != nil {
			return nil, fmt.Errorf("case %q: marshalling the proof: %w", spec.name, err)
		}
		reread := bytes.NewBuffer(buf.Bytes())
		if _, err := structs.NewCombinedTreeProof(cs, reread); err != nil {
			return nil, fmt.Errorf("case %q: katie cannot parse its own proof: %w", spec.name, err)
		} else if reread.Len() != 0 {
			return nil, fmt.Errorf("case %q: %d bytes left after the proof", spec.name, reread.Len())
		}

		ladder := make([]map[string]any, 0, len(required))
		for _, ver := range required {
			input, err := structs.Marshal(&structs.VrfInput{
				Label:   []byte(spec.label),
				Version: ver,
			})
			if err != nil {
				return nil, fmt.Errorf("case %q: marshalling the VRF input: %w", spec.name, err)
			}
			output, _ := privateVrfKey().Prove(input)
			entry := map[string]any{
				"version":    ver,
				"vrf_output": hex.EncodeToString(output),
			}
			if commitment := handle.GetCommitment(ver); commitment != nil {
				entry["commitment"] = hex.EncodeToString(commitment)
			}
			ladder = append(ladder, entry)
		}

		owner := map[string]any{
			"starting": spec.starting,
			"upcoming": indices(spec.upcoming),
		}
		if spec.verAtStarting != nil {
			owner["version_at_starting"] = *spec.verAtStarting
		}

		input := map[string]any{
			"mutations":            updateMutationsJSON(spec.mutations),
			"label":                hex.EncodeToString([]byte(spec.label)),
			"mode":                 uint8(config.Mode),
			"vrf_public_key":       hex.EncodeToString(config.VrfKey.Bytes()),
			"monitoring_window":    spec.window,
			"tree_size":            size,
			"position":             spec.position,
			"versions":             spec.versions,
			"owner":                owner,
			"entry_timestamps":     indices(timestamps),
			"ladder":               ladder,
			"note":                 spec.note,
			"signature_public_key": hex.EncodeToString(config.SignatureKey.Bytes()),
		}
		if spec.last != nil {
			input["last"] = *spec.last
		}

		expect := map[string]any{
			"proof":         hex.EncodeToString(buf.Bytes()),
			"timestamps":    indices(proof.Timestamps),
			"prefix_proofs": prefixProofsJSON(proof.PrefixProofs),
			"prefix_roots":  hexAll(proof.PrefixRoots),
			"inclusion":     hexAll(proof.Inclusion.Elements),
			// Whether the entry holding the new versions is distinguished decides which branch
			// §9.1 takes, and katie reports it by whether it wrote a contact monitoring entry:
			// step 4 adds one, step 3 does not.
			"distinguished": monitor.Contact == nil || len(monitor.Contact.Ptrs) == 0,
		}
		if monitor.Contact != nil {
			if version, ok := monitor.Contact.Ptrs[spec.position]; ok {
				expect["contact"] = map[string]any{
					"position": spec.position,
					"version":  version,
				}
			}
		}

		f.Cases = append(f.Cases, Case{
			Name:   spec.name,
			Input:  input,
			Expect: expect,
		})
	}

	return f, nil
}

// verAtStarting converts the owner's greatest version at its reference point to katie's
// representation, where -1 means the label did not exist.
func verAtStarting(version *uint32) int {
	if version == nil {
		return -1
	}
	return int(*version)
}

// maps returns the keys of a set as a slice, since RequiredVersions hands back a map and Go
// randomizes map iteration — a vector file has to come out the same way every run.
func maps[K comparable](set map[K]struct{}) []K {
	out := make([]K, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	return out
}

func updateMutationsJSON(mutations [][]labelValue) []map[string]any {
	out := make([]map[string]any, 0, len(mutations))
	for _, mutation := range mutations {
		labels := make([]map[string]any, 0, len(mutation))
		for _, entry := range mutation {
			labels = append(labels, map[string]any{
				"label": hex.EncodeToString(entry.label),
				"value": hex.EncodeToString(entry.value),
			})
		}
		out = append(out, map[string]any{"add": labels})
	}
	return out
}

// privateVrfKey is the VRF key every generated log uses, so that a verifier can be handed the
// public half and check each search key against it.
func privateVrfKey() *edwards25519.PrivateKey {
	key, err := edwards25519.NewPrivateKey(repeat(0x74, 32))
	if err != nil {
		// The key material is a constant; failing to parse it is a programming error, not
		// something a caller could handle.
		panic(fmt.Sprintf("parsing the VRF key: %v", err))
	}
	return key
}

// retainedEntries loads the log entries a user who advertised tree size `last` would have kept:
// its frontier, with each entry's timestamp and prefix tree root.
func retainedEntries(
	cs suites.CipherSuite, store db.TransparencyStore, last uint64,
) (map[uint64]structs.LogEntry, error) {
	frontier := ktmath.Frontier(last)
	raw, err := store.BatchGet(frontier)
	if err != nil {
		return nil, err
	}
	out := make(map[uint64]structs.LogEntry, len(frontier))
	for _, position := range frontier {
		encoded, ok := raw[position]
		if !ok {
			return nil, fmt.Errorf("no log entry at %d", position)
		}
		buf := bytes.NewBuffer(encoded)
		entry, err := structs.NewLogEntry(cs, buf)
		if err != nil {
			return nil, fmt.Errorf("log entry %d: %w", position, err)
		} else if buf.Len() != 0 {
			return nil, fmt.Errorf("log entry %d has %d trailing bytes", position, buf.Len())
		}
		out[position] = *entry
	}
	return out, nil
}

// buildUpdateLog runs a log through the case's mutations, returning it along with the store the
// proof is produced from, the timestamp of each entry, and each label's index — the log entry
// where each of its versions was created.
//
// The index is recorded as the log is built rather than read back out of the store, because the
// stored form is a delta-encoded series of uvarints that only katie's unexported reader decodes.
// Building it here means this harness never has to reimplement a storage format.
func buildUpdateLog(
	cs suites.CipherSuite, spec updateCase,
) (
	*transparency.Tree,
	db.TransparencyStore,
	*structs.PublicConfig,
	[]uint64,
	map[string][]uint64,
	error,
) {
	logKey, err := cs.ParseSigningPrivateKey(repeat(0x71, 32))
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("parsing the log signing key: %w", err)
	}
	private := structs.PrivateConfig{
		SignatureKey: logKey,
		VrfKey:       privateVrfKey(),
		Config: structs.Config{
			Suite:                      cs,
			Mode:                       structs.ContactMonitoring,
			MaxAhead:                   10000,
			MaxBehind:                  10000,
			ReasonableMonitoringWindow: spec.window,
		},
	}
	store := memory.NewTransparencyStore()
	tree, err := transparency.NewTree(private, store, nil)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("creating the tree: %w", err)
	}

	timestamps := make([]uint64, 0, len(spec.mutations))
	layout := make(map[string][]uint64)
	for i, mutation := range spec.mutations {
		position := uint64(0)
		if head := tree.TreeHead(); head != nil {
			position = head.TreeSize
		}
		add := make([]transparency.LabelValue, 0, len(mutation))
		for _, entry := range mutation {
			add = append(add, transparency.LabelValue{
				Label: entry.label,
				Value: structs.UpdateValue{Value: entry.value},
			})
			layout[string(entry.label)] = append(layout[string(entry.label)], position)
		}
		update, err := tree.Mutate(add, nil)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("mutation %d: %w", i, err)
		}
		timestamps = append(timestamps, update.Timestamp)
	}
	return tree, store, private.Public(), timestamps, layout, nil
}
