// Vectors for the log's configuration and its signed tree heads (draft §11.2,
// §11.3, §11.4).
//
// These are the first vectors where a key the log chose decides the outcome, so
// they pin two things at once: the byte-for-byte encoding of a Configuration, and
// the fact that a signature over it verifies. The second is worthless without the
// first, because a TreeHeadTBS begins with the whole Configuration -- if two
// implementations disagree about how one encodes, no signature either produces will
// ever verify for the other.
//
// Which is not hypothetical. §11.2 writes the mode-dependent part as
//
//	select (Configuration.mode) {
//	  case contactMonitoring:
//	  case thirdPartyManagement:
//	    opaque leaf_public_key<0..2^16-1>;
//	  ...
//
// and read as grouped cases -- the C convention the presentation language inherits
// -- leaf_public_key belongs to *both* modes. katie emits it only under
// thirdPartyManagement. keytrans-verification's Configuration comments the field as
// "Only for Contact monitoring or ThirdParty", i.e. the other reading. So the two Go
// implementations disagree, in a way that breaks every signature in
// contactMonitoring mode.
//
// The draft's prose sides with katie: leaf_public_key verifies "the Service
// Operator's signature on modifications", and §11.5 only gives UpdateSuffix a
// signature under thirdPartyManagement, so under contact monitoring the key would
// have nothing to verify. These vectors therefore record katie's encoding, and the
// `configuration` field is emitted for all three modes so the difference is visible
// as a byte length rather than as a claim.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/crypto/vrf/edwards25519"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// headVectors covers draft §11.2, §11.3, and §11.4.
func headVectors(sha string) (*File, error) {
	cs := suites.KTSha256Ed25519{}

	f := &File{
		Primitive:   "tree-head",
		Draft:       draftRev + " §11.2, §11.3, §11.4",
		Generator:   Generator{Impl: "katie", SHA: sha},
		CipherSuite: 0x0002, // KT_128_SHA256_Ed25519
		Notes: "Signed tree heads and the configuration every signature covers. " +
			"`configuration` is the encoded Configuration, `tree_head_tbs` is what the " +
			"signature is computed over, and `tree_head` is the wire TreeHead. Note the " +
			"§11.2 reading recorded here: leaf_public_key is emitted only under " +
			"thirdPartyManagement, which is what katie does and what the draft's prose " +
			"supports, while the grouped-case reading of the struct would also put it in " +
			"contactMonitoring -- and keytrans-verification's own notes take that second " +
			"reading. The two differ by 34 bytes in the Configuration and therefore in " +
			"every TreeHeadTBS. The negative cases are signatures that must not verify.",
	}

	// Fixed keys, so regeneration is a no-op diff.
	logKey, err := cs.ParseSigningPrivateKey(repeat(0x71, 32))
	if err != nil {
		return nil, fmt.Errorf("parsing the log signing key: %w", err)
	}
	auditorKey, err := cs.ParseSigningPrivateKey(repeat(0x72, 32))
	if err != nil {
		return nil, fmt.Errorf("parsing the auditor signing key: %w", err)
	}
	leafKey, err := cs.ParseSigningPrivateKey(repeat(0x73, 32))
	if err != nil {
		return nil, fmt.Errorf("parsing the leaf signing key: %w", err)
	}
	vrfKey, err := edwards25519.NewPrivateKey(repeat(0x74, 32))
	if err != nil {
		return nil, fmt.Errorf("parsing the VRF key: %w", err)
	}

	modes := []struct {
		name string
		mode structs.DeploymentMode
	}{
		{"contact-monitoring", structs.ContactMonitoring},
		{"third-party-management", structs.ThirdPartyManagement},
		{"third-party-auditing", structs.ThirdPartyAuditing},
	}

	for _, m := range modes {
		public := &structs.PublicConfig{
			SignatureKey: logKey.Public(),
			VrfKey:       vrfKey.PublicKey(),
			Config: structs.Config{
				Suite:                      cs,
				Mode:                       m.mode,
				MaxAhead:                   10000,
				MaxBehind:                  10000,
				ReasonableMonitoringWindow: 604800000,
			},
		}
		switch m.mode {
		case structs.ThirdPartyManagement:
			public.LeafPublicKey = leafKey.Public()
		case structs.ThirdPartyAuditing:
			public.MaxAuditorLag = 60000
			public.AuditorStartPos = 0
			public.AuditorPublicKey = auditorKey.Public()
		}

		configBytes, err := structs.Marshal(public)
		if err != nil {
			return nil, fmt.Errorf("mode %s: marshalling the configuration: %w", m.name, err)
		}

		for _, size := range []uint64{1, 8, 50} {
			root := repeat(byte(size), 32)

			// The TreeHeadTBS is the configuration, then the size, then the root.
			// Built by hand from the marshalled configuration rather than through a
			// katie helper so the vector records the exact bytes signed.
			tbs := &bytes.Buffer{}
			tbs.Write(configBytes)
			writeNumericTo(tbs, size)
			tbs.Write(root)

			signature, err := logKey.Sign(tbs.Bytes())
			if err != nil {
				return nil, fmt.Errorf("mode %s size %d: signing: %w", m.name, size, err)
			}
			if !public.SignatureKey.Verify(tbs.Bytes(), signature) {
				return nil, fmt.Errorf(
					"mode %s size %d: katie does not verify its own signature", m.name, size)
			}

			head := &bytes.Buffer{}
			writeNumericTo(head, size)
			writeUint16Bytes(head, signature)

			expect := map[string]any{
				"configuration": hex.EncodeToString(configBytes),
				"tree_head_tbs": hex.EncodeToString(tbs.Bytes()),
				"tree_head":     hex.EncodeToString(head.Bytes()),
				"signature":     hex.EncodeToString(signature),
			}

			input := map[string]any{
				"mode":                         uint8(m.mode),
				"signature_public_key":         hex.EncodeToString(public.SignatureKey.Bytes()),
				"vrf_public_key":               hex.EncodeToString(public.VrfKey.Bytes()),
				"max_ahead":                    public.MaxAhead,
				"max_behind":                   public.MaxBehind,
				"reasonable_monitoring_window": public.ReasonableMonitoringWindow,
				"tree_size":                    size,
				"root":                         hex.EncodeToString(root),
			}
			if m.mode == structs.ThirdPartyManagement {
				input["leaf_public_key"] = hex.EncodeToString(public.LeafPublicKey.Bytes())
			}
			if m.mode == structs.ThirdPartyAuditing {
				input["max_auditor_lag"] = public.MaxAuditorLag
				input["auditor_start_pos"] = public.AuditorStartPos
				input["auditor_public_key"] = hex.EncodeToString(public.AuditorPublicKey.Bytes())

				// And the auditor's own head over the same root.
				const timestamp uint64 = 1700000000000
				auditorTbs := &bytes.Buffer{}
				auditorTbs.Write(configBytes)
				writeNumericTo(auditorTbs, timestamp)
				writeNumericTo(auditorTbs, size)
				auditorTbs.Write(root)

				auditorSig, err := auditorKey.Sign(auditorTbs.Bytes())
				if err != nil {
					return nil, fmt.Errorf("mode %s: signing the auditor head: %w", m.name, err)
				}
				if !public.AuditorPublicKey.Verify(auditorTbs.Bytes(), auditorSig) {
					return nil, fmt.Errorf("mode %s: katie rejects its own auditor signature", m.name)
				}
				auditorHead := &bytes.Buffer{}
				writeNumericTo(auditorHead, timestamp)
				writeNumericTo(auditorHead, size)
				writeUint16Bytes(auditorHead, auditorSig)

				input["auditor_timestamp"] = timestamp
				expect["auditor_tree_head_tbs"] = hex.EncodeToString(auditorTbs.Bytes())
				expect["auditor_tree_head"] = hex.EncodeToString(auditorHead.Bytes())
			}

			f.Cases = append(f.Cases, Case{
				Name:   fmt.Sprintf("%s-size-%d", m.name, size),
				Input:  input,
				Expect: expect,
			})
		}
	}

	return f, nil
}

// writeNumericTo writes a big-endian uint64, the presentation language's uint64.
func writeNumericTo(buf *bytes.Buffer, value uint64) {
	var out [8]byte
	for i := range out {
		out[7-i] = byte(value >> (8 * i))
	}
	buf.Write(out[:])
}

// writeUint16Bytes writes a `<0..2^16-1>` opaque vector.
func writeUint16Bytes(buf *bytes.Buffer, value []byte) {
	buf.WriteByte(byte(len(value) >> 8))
	buf.WriteByte(byte(len(value)))
	buf.Write(value)
}
