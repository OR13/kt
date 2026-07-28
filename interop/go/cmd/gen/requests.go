// Vectors for the §13 request structures and the small pieces the responses are
// built from.
//
// These are the widest cheap interop surface left: every one is a pure
// structs.Marshal, so katie decides the bytes and the Rust side has to reproduce
// them. They matter more than their simplicity suggests, because almost all of them
// hinge on a presence octet or a length prefix whose meaning is not discoverable
// from the bytes:
//
//   - SearchRequest's `version` absent means "greatest version" (§6) and present
//     means "this exact version" (§7). One octet selects between two algorithms.
//   - BinaryLadderStep's `proof` is VRF.Np bytes with no length prefix, so a decoder
//     that guesses the suite wrong reads the presence octet out of the proof.
//   - UpdateRequest's empty `values` has a defined meaning of its own (§13.5: tell me
//     about later versions, create none), so it must encode as an empty vector
//     rather than be omitted.
//   - UpdateInfo needs both Nc from the suite and the deployment mode.
//
// The response structures are deliberately absent: they embed a CombinedTreeProof,
// whose contents §12.3 defines as the order the executing algorithm requests them in,
// so they cannot be pinned before those algorithms exist.
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/crypto/vrf/edwards25519"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// requestVectors covers draft §11.5 and §13.1 through §13.5.
func requestVectors(sha string) (*File, error) {
	cs := suites.KTSha256Ed25519{}

	f := &File{
		Primitive:   "requests",
		Draft:       draftRev + " §11.5, §13.1–§13.5",
		Generator:   Generator{Impl: "katie", SHA: sha},
		CipherSuite: 0x0002, // KT_128_SHA256_Ed25519
		Notes: "Request structures and response building blocks, each recorded as its " +
			"encoded bytes. `kind` selects the structure. Several depend on context the " +
			"bytes do not carry: a BinaryLadderStep's proof is VRF.Np = 80 bytes with no " +
			"length prefix, and an UpdateInfo needs both Nc and the deployment mode. The " +
			"response structures are not here because they embed a CombinedTreeProof, " +
			"whose shape depends on the algorithm being executed.",
	}

	// Fixed inputs, so regeneration is a no-op diff.
	label := []byte("alice@example.com")
	opening := fixed(0x10)
	commitment := repeat(0xc0, 32)

	vrfKey, err := edwards25519.NewPrivateKey(repeat(0x74, 32))
	if err != nil {
		return nil, fmt.Errorf("parsing the VRF key: %w", err)
	}
	alpha, err := structs.Marshal(&structs.VrfInput{Label: label, Version: 0})
	if err != nil {
		return nil, fmt.Errorf("marshalling VrfInput: %w", err)
	}
	_, vrfProof := vrfKey.Prove(alpha)

	add := func(name, kind string, input map[string]any, value structs.Marshaller) error {
		encoded, err := structs.Marshal(value)
		if err != nil {
			return fmt.Errorf("case %q: %w", name, err)
		}
		input["kind"] = kind
		f.Cases = append(f.Cases, Case{
			Name:   name,
			Input:  input,
			Expect: map[string]any{"encoding": hex.EncodeToString(encoded)},
		})
		return nil
	}

	// §13.1 SearchRequest: the presence of `version` picks the algorithm.
	for _, c := range []struct {
		name    string
		last    *uint64
		version *uint32
	}{
		{"search-greatest-version-with-last", ptr(uint64(50)), nil},
		{"search-greatest-version-first-time", nil, nil},
		{"search-fixed-version", ptr(uint64(50)), ptr(uint32(3))},
		{"search-fixed-version-zero", ptr(uint64(1)), ptr(uint32(0))},
		{"search-fixed-version-max", ptr(uint64(1)), ptr(^uint32(0))},
	} {
		input := map[string]any{"label": hex.EncodeToString(label)}
		if c.last != nil {
			input["last"] = *c.last
		}
		if c.version != nil {
			input["version"] = *c.version
		}
		if err := add(c.name, "search-request", input, &structs.SearchRequest{
			Last:    c.last,
			Label:   label,
			Version: c.version,
		}); err != nil {
			return nil, err
		}
	}

	// §13.1 BinaryLadderStep: present and absent commitment.
	for _, c := range []struct {
		name       string
		commitment []byte
	}{
		{"binary-ladder-step-with-commitment", commitment},
		{"binary-ladder-step-without-commitment", nil},
	} {
		input := map[string]any{"proof": hex.EncodeToString(vrfProof)}
		if c.commitment != nil {
			input["commitment"] = hex.EncodeToString(c.commitment)
		}
		if err := add(c.name, "binary-ladder-step", input, &structs.BinaryLadderStep{
			Proof:      vrfProof,
			Commitment: c.commitment,
		}); err != nil {
			return nil, err
		}
	}

	// §13.2 MonitorMapEntry and ContactMonitorRequest.
	if err := add("monitor-map-entry", "monitor-map-entry",
		map[string]any{"position": uint64(0x0102030405060708), "version": uint32(9)},
		&structs.MonitorMapEntry{Position: 0x0102030405060708, Version: 9}); err != nil {
		return nil, err
	}

	entries := []structs.MonitorMapEntry{
		{Position: 1, Version: 1},
		{Position: 5, Version: 2},
		{Position: 9, Version: 3},
	}
	for _, c := range []struct {
		name    string
		last    *uint64
		entries []structs.MonitorMapEntry
	}{
		{"contact-monitor-three-entries", ptr(uint64(10)), entries},
		{"contact-monitor-no-entries", ptr(uint64(10)), nil},
		{"contact-monitor-first-time", nil, entries},
	} {
		input := map[string]any{
			"label":   hex.EncodeToString(label),
			"entries": monitorEntriesJSON(c.entries),
		}
		if c.last != nil {
			input["last"] = *c.last
		}
		if err := add(c.name, "contact-monitor-request", input, &structs.ContactMonitorRequest{
			Last:    c.last,
			Label:   label,
			Entries: c.entries,
		}); err != nil {
			return nil, err
		}
	}

	// §13.3 OwnerInitRequest.
	for _, c := range []struct {
		name  string
		last  *uint64
		start uint64
	}{
		{"owner-init", ptr(uint64(64)), 31},
		{"owner-init-first-time", nil, 0},
	} {
		input := map[string]any{
			"label": hex.EncodeToString(label),
			"start": c.start,
		}
		if c.last != nil {
			input["last"] = *c.last
		}
		if err := add(c.name, "owner-init-request", input, &structs.OwnerInitRequest{
			Last:  c.last,
			Label: label,
			Start: c.start,
		}); err != nil {
			return nil, err
		}
	}

	// §13.4 OwnerMonitorRequest.
	for _, c := range []struct {
		name            string
		greatestVersion *uint32
	}{
		{"owner-monitor-with-greatest-version", ptr(uint32(5))},
		{"owner-monitor-without-greatest-version", nil},
	} {
		input := map[string]any{
			"label":   hex.EncodeToString(label),
			"entries": monitorEntriesJSON(entries[:1]),
			"start":   uint64(31),
			"last":    uint64(64),
		}
		if c.greatestVersion != nil {
			input["greatest_version"] = *c.greatestVersion
		}
		if err := add(c.name, "owner-monitor-request", input, &structs.OwnerMonitorRequest{
			Last:            ptr(uint64(64)),
			Label:           label,
			Entries:         entries[:1],
			Start:           31,
			GreatestVersion: c.greatestVersion,
		}); err != nil {
			return nil, err
		}
	}

	// §13.5 LabelValue, UpdateInfo, UpdateRequest.
	if err := add("label-value", "label-value",
		map[string]any{"value": hex.EncodeToString([]byte("key-material-1"))},
		&structs.LabelValue{Value: []byte("key-material-1")}); err != nil {
		return nil, err
	}
	if err := add("label-value-empty", "label-value",
		map[string]any{"value": ""},
		&structs.LabelValue{Value: []byte{}}); err != nil {
		return nil, err
	}

	if err := add("update-info-contact-monitoring", "update-info",
		map[string]any{
			"opening": hex.EncodeToString(opening),
			"mode":    uint8(structs.ContactMonitoring),
		},
		&structs.UpdateInfo{Opening: opening}); err != nil {
		return nil, err
	}

	values := []structs.LabelValue{
		{Value: []byte("key-material-1")},
		{Value: []byte("key-material-2")},
	}
	for _, c := range []struct {
		name            string
		greatestVersion *uint32
		values          []structs.LabelValue
	}{
		{"update-two-values", ptr(uint32(2)), values},
		{"update-no-values-asking-only", ptr(uint32(2)), nil},
		{"update-first-version", nil, values[:1]},
	} {
		input := map[string]any{
			"label":  hex.EncodeToString(label),
			"last":   uint64(8),
			"values": labelValuesJSON(c.values),
		}
		if c.greatestVersion != nil {
			input["greatest_version"] = *c.greatestVersion
		}
		if err := add(c.name, "update-request", input, &structs.UpdateRequest{
			Last:            ptr(uint64(8)),
			Label:           label,
			GreatestVersion: c.greatestVersion,
			Values:          c.values,
		}); err != nil {
			return nil, err
		}
	}

	// §11.5 UpdateTBS, which begins with the whole Configuration.
	logKey, err := cs.ParseSigningPrivateKey(repeat(0x71, 32))
	if err != nil {
		return nil, fmt.Errorf("parsing the log signing key: %w", err)
	}
	leafKey, err := cs.ParseSigningPrivateKey(repeat(0x73, 32))
	if err != nil {
		return nil, fmt.Errorf("parsing the leaf signing key: %w", err)
	}
	public := &structs.PublicConfig{
		SignatureKey: logKey.Public(),
		VrfKey:       vrfKey.PublicKey(),
		Config: structs.Config{
			Suite:                      cs,
			Mode:                       structs.ThirdPartyManagement,
			LeafPublicKey:              leafKey.Public(),
			MaxAhead:                   10000,
			MaxBehind:                  10000,
			ReasonableMonitoringWindow: 604800000,
		},
	}
	configBytes, err := structs.Marshal(public)
	if err != nil {
		return nil, fmt.Errorf("marshalling the configuration: %w", err)
	}
	if err := add("update-tbs", "update-tbs",
		map[string]any{
			"configuration": hex.EncodeToString(configBytes),
			"label":         hex.EncodeToString(label),
			"version":       uint32(4),
			"value":         hex.EncodeToString([]byte("key-material-1")),
		},
		&structs.UpdateTBS{
			Config:  public,
			Label:   label,
			Version: 4,
			Value:   []byte("key-material-1"),
		}); err != nil {
		return nil, err
	}

	return f, nil
}

func monitorEntriesJSON(entries []structs.MonitorMapEntry) []map[string]any {
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{"position": e.Position, "version": e.Version})
	}
	return out
}

func labelValuesJSON(values []structs.LabelValue) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, hex.EncodeToString(v.Value))
	}
	return out
}
