// Vectors for things that must be *rejected*.
//
// Every other file in interop/vectors/ asks the same question: the peer computed
// this value, do you compute it too? That question cannot be failed by a verifier
// that accepts everything, because it never asks a verifier to say no. Before this
// file there was exactly one must-reject case across 162 -- in commitment.json --
// so the Go -> Rust direction was almost entirely a test of arithmetic agreement.
//
// The cases here are proofs katie built and then corrupted, each one confirmed
// rejected by katie's own verifier before it is written out. That confirmation is
// what makes them usable as a shared oracle: the peer is asserting "this is
// invalid", so a Rust verifier that accepts one is not making a different
// judgement call, it is wrong. Together with interop/vectors/from-kt.json, which
// runs the same idea in the other direction, both implementations now have to agree
// about what is invalid and not merely about what is valid.
//
// Deliberately one file across all primitives rather than a *-tampered.json per
// primitive: the gap this closes was invisible precisely because rejection coverage
// was scattered, and one file makes "how many must-reject cases are there?" a
// question with an obvious answer.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/Bren2010/katie/crypto/commitments"
	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/crypto/vrf/edwards25519"
	"github.com/Bren2010/katie/db/memory"
	"github.com/Bren2010/katie/tree/log"
	"github.com/Bren2010/katie/tree/prefix"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// tamperedVectors emits proofs that must not verify.
func tamperedVectors(sha string) (*File, error) {
	f := &File{
		Primitive:   "tampered",
		Draft:       draftRev + " §11.2, §11.6, §11.7, §12.1, §12.2",
		Generator:   Generator{Impl: "katie", SHA: sha},
		CipherSuite: 0x0002, // KT_128_SHA256_Ed25519
		Notes: "Proofs and openings that must be rejected. Each was built by katie, " +
			"corrupted in the way `tamper` describes, and then confirmed rejected by " +
			"katie's own verifier before being written here -- so accepting one is not a " +
			"difference of opinion, it is a bug. `kind` selects the primitive. For the log " +
			"tree, 'rejected' means the verifier errors or arrives at a root other than " +
			"`root`; for the others it means the verify call fails. The mirror image of " +
			"this file is from-kt.json, where the Rust side builds the corrupted proofs " +
			"and katie has to reject them.",
	}

	logCases, err := tamperedLogCases()
	if err != nil {
		return nil, err
	}
	f.Cases = append(f.Cases, logCases...)

	prefixCases, err := tamperedPrefixCases()
	if err != nil {
		return nil, err
	}
	f.Cases = append(f.Cases, prefixCases...)

	vrfCases, err := tamperedVrfCases()
	if err != nil {
		return nil, err
	}
	f.Cases = append(f.Cases, vrfCases...)

	commitmentCases, err := tamperedCommitmentCases()
	if err != nil {
		return nil, err
	}
	f.Cases = append(f.Cases, commitmentCases...)

	headCases, err := tamperedHeadCases()
	if err != nil {
		return nil, err
	}
	f.Cases = append(f.Cases, headCases...)

	return f, nil
}

// logRejects reports whether katie refuses to derive `root` from this proof, which
// is what "invalid" means for a batch proof: the verifier either errors outright or
// lands somewhere else.
func logRejects(
	cs suites.CipherSuite,
	size uint64,
	entries []uint64,
	values [][]byte,
	retainedSize uint64,
	retained [][]byte,
	elements [][]byte,
	root []byte,
) bool {
	v := log.NewVerifier(cs)
	if retainedSize != 0 {
		if err := v.Retain(retainedSize, retained); err != nil {
			return true
		}
	}
	fullSubtrees, _, err := v.Evaluate(entries, size, nil, values, elements)
	if err != nil {
		return true
	}
	got, err := log.Root(cs, size, fullSubtrees)
	if err != nil {
		return true
	}
	return !bytes.Equal(got, root)
}

func tamperedLogCases() ([]Case, error) {
	cs := suites.KTSha256Ed25519{}
	out := make([]Case, 0)

	// A tree big enough that proofs have several elements and a retained view has
	// more than one subtree head.
	const size uint64 = 11
	entries := logEntries(size)
	store := memory.NewLogStore()
	tree := log.NewTree(cs, store)
	values := make([][]byte, 0, size)
	var fullSubtrees [][]byte
	for i, entry := range entries {
		value, err := entry.Hash(cs)
		if err != nil {
			return nil, fmt.Errorf("hashing entry %d: %w", i, err)
		}
		values = append(values, value)
		fullSubtrees, err = tree.Append(uint64(i), value)
		if err != nil {
			return nil, fmt.Errorf("appending entry %d: %w", i, err)
		}
	}
	root, err := log.Root(cs, size, fullSubtrees)
	if err != nil {
		return nil, fmt.Errorf("computing the root: %w", err)
	}

	// An inclusion proof for one leaf, and a batched proof over a retained view
	// where the proven leaf sits inside the retained subtree -- the §12.1 case the
	// draft marks MUST.
	proven := []uint64{4}
	elements, err := tree.GetBatch(proven, size, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("batch proof: %w", err)
	}
	const retainedSize uint64 = 8
	retained := make([][]byte, 0)
	for _, x := range mathFullSubtreeValues(cs, values, retainedSize) {
		retained = append(retained, x)
	}
	overlapping, err := tree.GetBatch([]uint64{2}, size, nil, ptr(retainedSize))
	if err != nil {
		return nil, fmt.Errorf("overlapping batch proof: %w", err)
	}

	type variant struct {
		name    string
		tamper  string
		entries []uint64
		values  [][]byte
		// zero means no retained view
		retainedSize uint64
		retained     [][]byte
		elements     [][]byte
	}

	variants := []variant{
		{
			name:     "log-flipped-element",
			tamper:   "one bit flipped in the first proof element",
			entries:  proven,
			values:   [][]byte{values[4]},
			elements: flipFirstByte(elements),
		},
		{
			name:     "log-dropped-element",
			tamper:   "the last proof element removed",
			entries:  proven,
			values:   [][]byte{values[4]},
			elements: elements[:len(elements)-1],
		},
		{
			name:     "log-extra-element",
			tamper:   "an extra all-zero proof element appended",
			entries:  proven,
			values:   [][]byte{values[4]},
			elements: append(dupAll(elements), make([]byte, cs.HashSize())),
		},
		{
			name:     "log-swapped-elements",
			tamper:   "the first two proof elements exchanged",
			entries:  proven,
			values:   [][]byte{values[4]},
			elements: swapFirstTwo(elements),
		},
		{
			name:     "log-wrong-leaf-value",
			tamper:   "a different leaf's value claimed for the proven index",
			entries:  proven,
			values:   [][]byte{values[5]},
			elements: dupAll(elements),
		},
		{
			// §12.1: proving a leaf inside a retained subtree makes that head
			// recomputable, and the recomputation is what must be believed. A
			// verifier that trusts the retained value instead accepts this.
			name:         "log-corrupted-retained-head",
			tamper:       "a retained full subtree head corrupted, with a proven leaf inside it",
			entries:      []uint64{2},
			values:       [][]byte{values[2]},
			retainedSize: retainedSize,
			retained:     flipFirstByte(retained),
			elements:     dupAll(overlapping),
		},
	}

	for _, v := range variants {
		if !logRejects(cs, size, v.entries, v.values, v.retainedSize, v.retained, v.elements, root) {
			return nil, fmt.Errorf("case %q: katie accepted it, so it is not a negative case", v.name)
		}
		input := map[string]any{
			"kind":     "log-tree",
			"size":     size,
			"entries":  v.entries,
			"values":   hexAll(v.values),
			"elements": hexAll(v.elements),
			"root":     hex.EncodeToString(root),
		}
		if v.retainedSize != 0 {
			input["retained_size"] = v.retainedSize
			input["retained"] = hexAll(v.retained)
		}
		out = append(out, Case{
			Name:   v.name,
			Input:  input,
			Expect: map[string]any{"error": true, "tamper": v.tamper},
		})
	}

	return out, nil
}

// mathFullSubtreeValues recomputes the full subtree heads of a tree of `size`
// leaves by building a second tree with just those leaves. Going through
// log.Tree.Append rather than reimplementing the decomposition keeps katie the
// source of truth for what a verifier would have retained.
func mathFullSubtreeValues(cs suites.CipherSuite, values [][]byte, size uint64) [][]byte {
	store := memory.NewLogStore()
	tree := log.NewTree(cs, store)
	var out [][]byte
	for i := uint64(0); i < size; i++ {
		var err error
		out, err = tree.Append(i, values[i])
		if err != nil {
			return nil
		}
	}
	return out
}

func tamperedPrefixCases() ([]Case, error) {
	cs := suites.KTSha256Ed25519{}
	out := make([]Case, 0)

	// The §3.3 figure's tree, which has all three terminal kinds reachable.
	spec := prefixCases()[6] // "figure-mixed-result-types"
	store := memory.NewPrefixStore()
	tree := prefix.NewTree(cs, store)
	add := make([]prefix.Entry, 0, len(spec.entries))
	for _, e := range spec.entries {
		add = append(add, prefix.Entry{VrfOutput: e.vrfOutput, Commitment: e.commitment})
	}
	root, _, _, err := tree.Mutate(0, add, nil)
	if err != nil {
		return nil, fmt.Errorf("building the prefix tree: %w", err)
	}
	results, err := tree.Search([]prefix.PrefixSearch{{Version: 1, VrfOutputs: spec.searches}})
	if err != nil {
		return nil, fmt.Errorf("searching: %w", err)
	}
	proof := results[0].Proof
	commitments := results[0].Commitments

	// The searches, as the verifier is given them.
	searches := make([]map[string]any, 0, len(spec.searches))
	entries := make([]prefix.Entry, 0, len(spec.searches))
	for i, key := range spec.searches {
		entry := prefix.Entry{VrfOutput: key}
		search := map[string]any{"vrf_output": hex.EncodeToString(key)}
		if i < len(commitments) && len(commitments[i]) > 0 {
			entry.Commitment = commitments[i]
			search["commitment"] = hex.EncodeToString(commitments[i])
		}
		entries = append(entries, entry)
		searches = append(searches, search)
	}

	emit := func(name, tamper string, mutate func(*prefix.PrefixProof)) error {
		broken := clonePrefixProof(&proof)
		mutate(broken)
		if err := prefix.Verify(cs, entries, broken, root); err == nil {
			return fmt.Errorf("case %q: katie accepted it, so it is not a negative case", name)
		}
		var buf bytes.Buffer
		if err := broken.Marshal(&buf); err != nil {
			return fmt.Errorf("case %q: marshalling: %w", name, err)
		}
		out = append(out, Case{
			Name: name,
			Input: map[string]any{
				"kind":     "prefix-tree",
				"searches": searches,
				"proof":    hex.EncodeToString(buf.Bytes()),
				"root":     hex.EncodeToString(root),
			},
			Expect: map[string]any{"error": true, "tamper": tamper},
		})
		return nil
	}

	if err := emit("prefix-flipped-element", "one bit flipped in the first copath element",
		func(p *prefix.PrefixProof) { p.Elements = flipFirstByte(p.Elements) }); err != nil {
		return nil, err
	}
	if err := emit("prefix-dropped-element", "the last copath element removed",
		func(p *prefix.PrefixProof) { p.Elements = p.Elements[:len(p.Elements)-1] }); err != nil {
		return nil, err
	}
	if err := emit("prefix-extra-element", "an extra all-zero copath element appended",
		func(p *prefix.PrefixProof) {
			p.Elements = append(dupAll(p.Elements), make([]byte, cs.HashSize()))
		}); err != nil {
		return nil, err
	}
	if err := emit("prefix-reordered-elements", "the first two copath elements exchanged",
		func(p *prefix.PrefixProof) { p.Elements = swapFirstTwo(p.Elements) }); err != nil {
		return nil, err
	}

	return out, nil
}

func tamperedVrfCases() ([]Case, error) {
	cs := suites.KTSha256Ed25519{}
	out := make([]Case, 0)

	seed := repeat(0x5a, 32)
	private, err := cs.ParseVRFPrivateKey(seed)
	if err != nil {
		return nil, fmt.Errorf("parsing the VRF private key: %w", err)
	}
	publicKey := private.PublicKey()

	label := []byte("alice@example.com")
	alpha, err := structs.Marshal(&structs.VrfInput{Label: label, Version: 0})
	if err != nil {
		return nil, fmt.Errorf("marshalling VrfInput: %w", err)
	}
	_, proof := private.Prove(alpha)

	// A different key, to check that proofs are bound to the key they were made
	// with and not merely to the input.
	otherPrivate, err := cs.ParseVRFPrivateKey(repeat(0x5b, 32))
	if err != nil {
		return nil, fmt.Errorf("parsing the second VRF private key: %w", err)
	}

	type variant struct {
		name      string
		tamper    string
		publicKey []byte
		proof     []byte
	}
	variants := []variant{
		{
			name:      "vrf-flipped-proof-byte",
			tamper:    "one bit flipped in the proof's Gamma",
			publicKey: publicKey.Bytes(),
			proof:     flipByte(proof, 0),
		},
		{
			name:      "vrf-flipped-challenge",
			tamper:    "one bit flipped in the proof's challenge",
			publicKey: publicKey.Bytes(),
			proof:     flipByte(proof, 32),
		},
		{
			name:      "vrf-flipped-scalar",
			tamper:    "one bit flipped in the proof's s",
			publicKey: publicKey.Bytes(),
			proof:     flipByte(proof, 48),
		},
		{
			name:      "vrf-wrong-public-key",
			tamper:    "a valid proof checked against a different public key",
			publicKey: otherPrivate.PublicKey().Bytes(),
			proof:     dup(proof),
		},
	}

	for _, v := range variants {
		parsed, err := cs.ParseVRFPublicKey(v.publicKey)
		if err != nil {
			return nil, fmt.Errorf("case %q: parsing the public key: %w", v.name, err)
		}
		if _, err := parsed.Verify(alpha, v.proof); err == nil {
			return nil, fmt.Errorf("case %q: katie accepted it, so it is not a negative case", v.name)
		}
		out = append(out, Case{
			Name: v.name,
			Input: map[string]any{
				"kind":       "vrf",
				"public_key": hex.EncodeToString(v.publicKey),
				"label":      hex.EncodeToString(label),
				"version":    uint32(0),
				"proof":      hex.EncodeToString(v.proof),
			},
			Expect: map[string]any{"error": true, "tamper": v.tamper},
		})
	}

	return out, nil
}

func tamperedCommitmentCases() ([]Case, error) {
	cs := suites.KTSha256Ed25519{}
	out := make([]Case, 0)

	opening := fixed(0x10)
	label := []byte("alice@example.com")
	value := []byte("key-material-1")
	body, err := structs.Marshal(&structs.CommitmentValue{
		Label:   label,
		Version: 0,
		Update:  structs.UpdateValue{Value: value},
	})
	if err != nil {
		return nil, fmt.Errorf("marshalling CommitmentValue: %w", err)
	}
	commitment := commitments.Commit(cs, opening, body)

	type variant struct {
		name       string
		tamper     string
		label      []byte
		version    uint32
		value      []byte
		commitment []byte
	}
	variants := []variant{
		{
			name:       "commitment-flipped-bit",
			tamper:     "one bit flipped in the commitment",
			label:      label,
			version:    0,
			value:      value,
			commitment: flipByte(commitment, 0),
		},
		{
			name:       "commitment-wrong-label",
			tamper:     "a different label opened against the same commitment",
			label:      []byte("bob@example.com"),
			version:    0,
			value:      value,
			commitment: dup(commitment),
		},
		{
			name:       "commitment-wrong-version",
			tamper:     "a different version opened against the same commitment",
			label:      label,
			version:    1,
			value:      value,
			commitment: dup(commitment),
		},
		{
			name:       "commitment-wrong-value",
			tamper:     "a different value opened against the same commitment",
			label:      label,
			version:    0,
			value:      []byte("key-material-2"),
			commitment: dup(commitment),
		},
	}

	for _, v := range variants {
		candidate, err := structs.Marshal(&structs.CommitmentValue{
			Label:   v.label,
			Version: v.version,
			Update:  structs.UpdateValue{Value: v.value},
		})
		if err != nil {
			return nil, fmt.Errorf("case %q: marshalling: %w", v.name, err)
		}
		if commitments.Verify(cs, opening, candidate, v.commitment) {
			return nil, fmt.Errorf("case %q: katie accepted it, so it is not a negative case", v.name)
		}
		out = append(out, Case{
			Name: v.name,
			Input: map[string]any{
				"kind":       "commitment",
				"opening":    hex.EncodeToString(opening),
				"label":      hex.EncodeToString(v.label),
				"version":    v.version,
				"update":     map[string]any{"value": hex.EncodeToString(v.value)},
				"commitment": hex.EncodeToString(v.commitment),
			},
			Expect: map[string]any{"error": true, "tamper": v.tamper},
		})
	}

	return out, nil
}

// --- small helpers, all of which copy rather than mutate their input ---

func dup(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func dupAll(in [][]byte) [][]byte {
	out := make([][]byte, 0, len(in))
	for _, v := range in {
		out = append(out, dup(v))
	}
	return out
}

func flipByte(in []byte, index int) []byte {
	out := dup(in)
	if index < len(out) {
		out[index] ^= 0x01
	}
	return out
}

func flipFirstByte(in [][]byte) [][]byte {
	out := dupAll(in)
	if len(out) > 0 && len(out[0]) > 0 {
		out[0][0] ^= 0x01
	}
	return out
}

func swapFirstTwo(in [][]byte) [][]byte {
	out := dupAll(in)
	if len(out) >= 2 {
		out[0], out[1] = out[1], out[0]
	}
	return out
}

func clonePrefixProof(p *prefix.PrefixProof) *prefix.PrefixProof {
	results := make([]prefix.PrefixSearchResult, len(p.Results))
	copy(results, p.Results)
	return &prefix.PrefixProof{Results: results, Elements: dupAll(p.Elements)}
}

func ptr[T any](v T) *T { return &v }

// tamperedHeadCases covers §11.2 and §11.4: signatures that must not verify.
//
// The last case is the interesting one. It is a signature that is perfectly valid
// over the *other* reading of §11.2 — the grouped-case reading, where a
// contactMonitoring Configuration carries leaf_public_key — presented to a verifier
// that uses katie's reading. If the working group resolves the ambiguity the other
// way, this case starts failing, which is exactly the signal you want: a vector that
// turns a documentation question into a test result.
func tamperedHeadCases() ([]Case, error) {
	cs := suites.KTSha256Ed25519{}
	out := make([]Case, 0)

	logKey, err := cs.ParseSigningPrivateKey(repeat(0x71, 32))
	if err != nil {
		return nil, fmt.Errorf("parsing the log signing key: %w", err)
	}
	otherKey, err := cs.ParseSigningPrivateKey(repeat(0x7f, 32))
	if err != nil {
		return nil, fmt.Errorf("parsing the second signing key: %w", err)
	}
	leafKey, err := cs.ParseSigningPrivateKey(repeat(0x73, 32))
	if err != nil {
		return nil, fmt.Errorf("parsing the leaf signing key: %w", err)
	}
	vrfKey, err := edwards25519.NewPrivateKey(repeat(0x74, 32))
	if err != nil {
		return nil, fmt.Errorf("parsing the VRF key: %w", err)
	}

	public := &structs.PublicConfig{
		SignatureKey: logKey.Public(),
		VrfKey:       vrfKey.PublicKey(),
		Config: structs.Config{
			Suite:                      cs,
			Mode:                       structs.ContactMonitoring,
			MaxAhead:                   10000,
			MaxBehind:                  10000,
			ReasonableMonitoringWindow: 604800000,
		},
	}
	configBytes, err := structs.Marshal(public)
	if err != nil {
		return nil, fmt.Errorf("marshalling the configuration: %w", err)
	}

	const size uint64 = 8
	root := repeat(byte(size), 32)
	tbs := &bytes.Buffer{}
	tbs.Write(configBytes)
	writeNumericTo(tbs, size)
	tbs.Write(root)
	honest, err := logKey.Sign(tbs.Bytes())
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	// A signature over a Configuration built the other way: the same fields, plus a
	// length-prefixed leaf_public_key after the VRF key, which is where §11.2's
	// grouped-case reading would put it.
	alternative := &bytes.Buffer{}
	alternative.Write(configBytes[:2])                      // cipher suite
	alternative.WriteByte(configBytes[2])                   // mode
	alternative.Write(configBytes[3 : 3+2+32])              // signature public key
	alternative.Write(configBytes[3+2+32 : 3+2+32+2+32])    // vrf public key
	writeUint16Bytes(alternative, leafKey.Public().Bytes()) // the disputed field
	alternative.Write(configBytes[3+2+32+2+32:])            // durations and optional
	altTbs := &bytes.Buffer{}
	altTbs.Write(alternative.Bytes())
	writeNumericTo(altTbs, size)
	altTbs.Write(root)
	altSignature, err := logKey.Sign(altTbs.Bytes())
	if err != nil {
		return nil, fmt.Errorf("signing the alternative reading: %w", err)
	}

	type variant struct {
		name      string
		tamper    string
		publicKey []byte
		signature []byte
	}
	variants := []variant{
		{
			name:      "tree-head-flipped-signature",
			tamper:    "one bit flipped in the tree head signature",
			publicKey: public.SignatureKey.Bytes(),
			signature: flipByte(honest, 0),
		},
		{
			name:      "tree-head-wrong-key",
			tamper:    "a valid signature checked against a different public key",
			publicKey: otherKey.Public().Bytes(),
			signature: dup(honest),
		},
		{
			name:      "tree-head-signature-from-another-key",
			tamper:    "the head signed by a key other than the one the configuration names",
			publicKey: public.SignatureKey.Bytes(),
			signature: mustSign(otherKey, tbs.Bytes()),
		},
		{
			name: "tree-head-signed-over-the-other-reading-of-11-2",
			tamper: "a signature valid over the grouped-case reading of §11.2, where a " +
				"contactMonitoring Configuration carries leaf_public_key; it must not " +
				"verify against the reading katie and the draft's prose use",
			publicKey: public.SignatureKey.Bytes(),
			signature: altSignature,
		},
	}

	for _, v := range variants {
		parsed, err := cs.ParseSigningPublicKey(v.publicKey)
		if err != nil {
			return nil, fmt.Errorf("case %q: parsing the public key: %w", v.name, err)
		}
		if parsed.Verify(tbs.Bytes(), v.signature) {
			return nil, fmt.Errorf("case %q: katie accepted it, so it is not a negative case", v.name)
		}
		out = append(out, Case{
			Name: v.name,
			Input: map[string]any{
				"kind":                         "tree-head",
				"mode":                         uint8(structs.ContactMonitoring),
				"signature_public_key":         hex.EncodeToString(v.publicKey),
				"vrf_public_key":               hex.EncodeToString(public.VrfKey.Bytes()),
				"max_ahead":                    public.MaxAhead,
				"max_behind":                   public.MaxBehind,
				"reasonable_monitoring_window": public.ReasonableMonitoringWindow,
				"tree_size":                    size,
				"root":                         hex.EncodeToString(root),
				"signature":                    hex.EncodeToString(v.signature),
			},
			Expect: map[string]any{"error": true, "tamper": v.tamper},
		})
	}

	return out, nil
}

func mustSign(key suites.SigningPrivateKey, message []byte) []byte {
	sig, err := key.Sign(message)
	if err != nil {
		return nil
	}
	return sig
}
