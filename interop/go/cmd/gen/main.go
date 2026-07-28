// Command gen emits cross-implementation test vectors for the Rust
// implementation in ../../../crates to verify against.
//
// It links github.com/Bren2010/katie, which is AGPL-3.0 — which is why this Go
// module is AGPL-3.0 and structurally separate from the Cargo workspace. See
// ../../README.md and ../../../docs/licensing.md.
//
// Vectors are deterministic: no randomness at generation time, so regenerating
// is a no-op diff and real drift from an upstream bump stands out.
//
// Usage:
//
//	go run ./cmd/gen -out ../vectors
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Bren2010/katie/crypto/commitments"
	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// File is the on-disk vector format. See ../../README.md for the contract.
type File struct {
	Primitive   string    `json:"primitive"`
	Draft       string    `json:"draft"`
	Generator   Generator `json:"generator"`
	CipherSuite uint16    `json:"cipher_suite"`
	Notes       string    `json:"notes,omitempty"`
	Cases       []Case    `json:"cases"`
}

// Generator records where the expected values came from, so a failing vector can
// be regenerated and blamed.
type Generator struct {
	Impl string `json:"impl"`
	SHA  string `json:"sha"`
}

// Case is a single named test case.
type Case struct {
	Name   string         `json:"name"`
	Input  map[string]any `json:"input"`
	Expect map[string]any `json:"expect"`
}

const draftRev = "draft-ietf-keytrans-protocol-05"

func main() {
	out := flag.String("out", "../vectors", "directory to write vectors into")
	flag.Parse()

	sha, err := katieSHA()
	if err != nil {
		fatal("resolving katie SHA: %v", err)
	}

	f, err := commitmentVectors(sha)
	if err != nil {
		fatal("generating commitment vectors: %v", err)
	}
	if err := write(*out, "commitment.json", f); err != nil {
		fatal("writing commitment vectors: %v", err)
	}
	fmt.Printf("wrote %s (%d cases, katie %s)\n",
		filepath.Join(*out, "commitment.json"), len(f.Cases), sha[:12])
}

// commitmentVectors covers draft §11.6: commitment = HMAC(Kc, CommitmentValue).
//
// Note a presentation difference from the draft that is not a wire difference:
// the draft puts `opaque opening[Nc]` as the first field of CommitmentValue,
// whereas katie keeps `opening` out of its CommitmentValue struct and passes it
// to Commit separately, where it is written to the HMAC first. The bytes hashed
// are identical — opening || label || version || update — so this is only a
// difference in where the field lives, not in what is committed. The Rust side
// should follow the draft and put opening inside the struct.
func commitmentVectors(sha string) (*File, error) {
	cs := suites.KTSha256Ed25519{}

	inputs := []struct {
		name    string
		opening []byte
		label   []byte
		version uint32
		value   []byte
	}{
		{"empty-label-empty-value", fixed(0x00), []byte{}, 0, []byte{}},
		{"simple", fixed(0x10), []byte("alice@example.com"), 0, []byte("key-material-1")},
		{"version-one", fixed(0x10), []byte("alice@example.com"), 1, []byte("key-material-2")},
		{"version-max", fixed(0x20), []byte("bob@example.com"), ^uint32(0), []byte("k")},
		{"label-max-len", fixed(0x30), repeat(0x61, 255), 7, []byte("v")},
		{"value-with-nulls", fixed(0x40), []byte("carol"), 3, []byte{0x00, 0x01, 0x00, 0xff}},
	}

	f := &File{
		Primitive:   "commitment",
		Draft:       draftRev + " §11.6",
		Generator:   Generator{Impl: "katie", SHA: sha},
		CipherSuite: 0x0002, // KT_128_SHA256_Ed25519
		Notes: "commitment = HMAC-SHA256(Kc, opening || label || version || update). " +
			"commitment_value is the serialized CommitmentValue per the draft, i.e. " +
			"opening followed by the label/version/update encoding; the Rust wire " +
			"codec should reproduce it byte for byte.",
	}

	for _, in := range inputs {
		body, err := structs.Marshal(&structs.CommitmentValue{
			Label:   in.label,
			Version: in.version,
			Update:  structs.UpdateValue{Value: in.value},
		})
		if err != nil {
			return nil, fmt.Errorf("case %q: %w", in.name, err)
		}
		commitment := commitments.Commit(cs, in.opening, body)
		if !commitments.Verify(cs, in.opening, body, commitment) {
			return nil, fmt.Errorf("case %q: katie does not verify its own commitment", in.name)
		}

		f.Cases = append(f.Cases, Case{
			Name: in.name,
			Input: map[string]any{
				"opening": hex.EncodeToString(in.opening),
				"label":   hex.EncodeToString(in.label),
				"version": in.version,
				"update":  map[string]any{"value": hex.EncodeToString(in.value)},
			},
			Expect: map[string]any{
				"commitment_value": hex.EncodeToString(append(in.opening, body...)),
				"commitment":       hex.EncodeToString(commitment),
			},
		})
	}

	// A negative case: the same inputs with one bit flipped in the opening must
	// not verify against the unmodified commitment.
	base := f.Cases[1]
	tampered := fixed(0x10)
	tampered[0] ^= 0x01
	f.Cases = append(f.Cases, Case{
		Name: "wrong-opening-does-not-verify",
		Input: map[string]any{
			"opening":    hex.EncodeToString(tampered),
			"label":      base.Input["label"],
			"version":    base.Input["version"],
			"update":     base.Input["update"],
			"commitment": base.Expect["commitment"],
		},
		Expect: map[string]any{"error": true},
	})

	return f, nil
}

// fixed returns a deterministic Nc-byte opening seeded by b.
func fixed(b byte) []byte {
	out := make([]byte, suites.KTSha256Ed25519{}.CommitmentOpeningSize())
	for i := range out {
		out[i] = b + byte(i)
	}
	return out
}

func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// katieSHA reports the commit of the pinned katie submodule, so every vector
// records exactly which upstream produced it.
func katieSHA() (string, error) {
	cmd := exec.Command("git", "-C", "../../upstream/katie", "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func write(dir, name string, f *File) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	buf, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), append(buf, '\n'), 0o644)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gen: "+format+"\n", args...)
	os.Exit(1)
}
