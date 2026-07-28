// Vectors for the VRF (draft §11.7), the search-key derivation that keeps labels
// private.
//
// RFC 9381's Appendix B already pins the ECVRF core, and the Rust side runs those
// vectors directly -- they are independent of every implementation, which makes
// them a better oracle than either of us. What this file adds is the part RFC 9381
// says nothing about: the KT wrapping. Specifically, that alpha_string is the
// presentation-language encoding of a VrfInput (§11.7), and that the 64-byte
// beta_string is truncated to VRF.Nh = 32 bytes (§17.1). Those two decisions are
// where two conforming ECVRF implementations can still fail to interoperate.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// vrfVectors covers draft §11.7 for KT_128_SHA256_Ed25519.
func vrfVectors(sha string) (*File, error) {
	cs := suites.KTSha256Ed25519{}

	// A fixed key, so regeneration is a no-op diff. Deliberately not the RFC 9381
	// key: those vectors are already run directly, and reusing one here would
	// leave the KT wrapping tested only against inputs the RFC also covers.
	seed := repeat(0x5a, 32)
	private, err := cs.ParseVRFPrivateKey(seed)
	if err != nil {
		return nil, fmt.Errorf("parsing the VRF private key: %w", err)
	}
	publicKey := private.PublicKey()

	inputs := []struct {
		name    string
		label   []byte
		version uint32
	}{
		{"empty-label-version-0", []byte{}, 0},
		{"simple", []byte("alice@example.com"), 0},
		{"version-1", []byte("alice@example.com"), 1},
		{"version-2", []byte("alice@example.com"), 2},
		{"version-max", []byte("alice@example.com"), ^uint32(0)},
		{"other-label-same-version", []byte("bob@example.com"), 0},
		// A label one byte longer than another, at a version whose bytes spell the
		// difference: the length prefix on `label` is what stops these colliding,
		// so a vector for each is worth having.
		{"label-a", []byte("a"), 0x62000000},
		{"label-ab", []byte("ab"), 0},
		{"label-max-len", repeat(0x61, 255), 7},
		{"label-with-nulls", []byte{0x00, 0x01, 0x00, 0xff}, 3},
	}

	f := &File{
		Primitive:   "vrf",
		Draft:       draftRev + " §11.7",
		Generator:   Generator{Impl: "katie", SHA: sha},
		CipherSuite: 0x0002, // KT_128_SHA256_Ed25519
		Notes: "ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) over the presentation-language " +
			"encoding of a VrfInput, with the output truncated to VRF.Nh = 32 bytes per " +
			"§17.1. `vrf_input` is that encoding, which is what alpha_string must be; " +
			"`output` is the prefix tree search key for the label-version pair; `proof` is " +
			"VRF.Np = 80 bytes. The RFC's own Appendix B vectors pin the ECVRF core and are " +
			"run directly by the Rust side; these pin the KT wrapping around it. The " +
			"negative case is a proof for one label-version pair checked against another, " +
			"which must not verify.",
	}

	for _, in := range inputs {
		alpha, err := structs.Marshal(&structs.VrfInput{Label: in.label, Version: in.version})
		if err != nil {
			return nil, fmt.Errorf("case %q: marshalling VrfInput: %w", in.name, err)
		}
		output, proof := private.Prove(alpha)
		if len(proof) != cs.VrfProofSize() {
			return nil, fmt.Errorf(
				"case %q: proof is %d bytes, suite says %d",
				in.name, len(proof), cs.VrfProofSize())
		}
		if len(output) != cs.HashSize() {
			return nil, fmt.Errorf(
				"case %q: output is %d bytes, expected %d",
				in.name, len(output), cs.HashSize())
		}

		// katie must verify its own proof, and recover the same output from it.
		verified, err := publicKey.Verify(alpha, proof)
		if err != nil {
			return nil, fmt.Errorf("case %q: katie rejects its own proof: %w", in.name, err)
		}
		if !bytes.Equal(verified, output) {
			return nil, fmt.Errorf("case %q: verifying gives a different output", in.name)
		}

		f.Cases = append(f.Cases, Case{
			Name: in.name,
			Input: map[string]any{
				"private_key": hex.EncodeToString(seed),
				"public_key":  hex.EncodeToString(publicKey.Bytes()),
				"label":       hex.EncodeToString(in.label),
				"version":     in.version,
			},
			Expect: map[string]any{
				"vrf_input": hex.EncodeToString(alpha),
				"output":    hex.EncodeToString(output),
				"proof":     hex.EncodeToString(proof),
			},
		})
	}

	// A negative case: a proof for one label-version pair must not verify against
	// another. This is the failure that matters in the protocol -- a log reusing a
	// proof across versions would let it serve one label's value for another.
	if len(f.Cases) < 3 {
		return nil, fmt.Errorf("not enough positive cases to build a negative one")
	}
	borrowed := f.Cases[1] // "simple": alice@example.com at version 0
	target := f.Cases[2]   // "version-1": the same label at version 1
	alpha, err := structs.Marshal(&structs.VrfInput{
		Label:   []byte("alice@example.com"),
		Version: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("negative case: marshalling VrfInput: %w", err)
	}
	proof, err := hex.DecodeString(borrowed.Expect["proof"].(string))
	if err != nil {
		return nil, fmt.Errorf("negative case: decoding the borrowed proof: %w", err)
	}
	if _, err := publicKey.Verify(alpha, proof); err == nil {
		return nil, fmt.Errorf("negative case: katie accepted a proof for the wrong version")
	}
	f.Cases = append(f.Cases, Case{
		Name: "proof-for-another-version-does-not-verify",
		Input: map[string]any{
			"private_key": hex.EncodeToString(seed),
			"public_key":  hex.EncodeToString(publicKey.Bytes()),
			"label":       target.Input["label"],
			"version":     target.Input["version"],
			"proof":       borrowed.Expect["proof"],
		},
		Expect: map[string]any{"error": true},
	})

	return f, nil
}
