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

	"math"

	"github.com/Bren2010/katie/crypto/commitments"
	"github.com/Bren2010/katie/crypto/suites"
	ktmath "github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// File is the on-disk vector format. See ../../README.md for the contract.
//
// CipherSuite is omitted for primitives that do not depend on one: the implicit
// binary search tree and the binary ladders are integer math with no hash, no
// key, and no suite parameters in sight.
type File struct {
	Primitive   string    `json:"primitive"`
	Draft       string    `json:"draft"`
	Generator   Generator `json:"generator"`
	CipherSuite uint16    `json:"cipher_suite,omitempty"`
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

	generators := []struct {
		name string
		fn   func(string) (*File, error)
	}{
		{"commitment.json", commitmentVectors},
		{"ibst.json", ibstVectors},
		{"binary-ladder.json", ladderVectors},
		{"vrf.json", vrfVectors},
		{"update-view.json", updateViewVectors},
		{"log-math.json", logMathVectors},
		{"log-tree.json", logTreeVectors},
		{"log-append.json", appendVectors},
		{"prefix-tree.json", prefixTreeVectors},
		{"prefix-mutation.json", mutationVectors},
		{"auditor-update.json", auditorVectors},
		{"search.json", searchVectors},
		{"tree-head.json", headVectors},
		{"requests.json", requestVectors},
		{"ladder-interpretation.json", ladderInterpretationVectors},
		{"distinguished.json", distinguishedVectors},
		{"tampered.json", tamperedVectors},
	}

	for _, g := range generators {
		f, err := g.fn(sha)
		if err != nil {
			fatal("generating %s: %v", g.name, err)
		}
		if err := write(*out, g.name, f); err != nil {
			fatal("writing %s: %v", g.name, err)
		}
		fmt.Printf("wrote %s (%d cases, katie %s)\n",
			filepath.Join(*out, g.name), len(f.Cases), sha[:12])
	}
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

// ibstVectors covers draft §4.1 and Appendix A: the implicit binary search tree
// over log entry indices.
//
// Only katie's exported API is used, so every expected value in the file comes
// from the peer: Root, Left, Right, and Frontier. Appendix A's log2 and level are
// unexported there, and are not in the file — the Rust side checks those against
// a literal transcription of the pseudocode instead, which is a better oracle for
// a pure bit trick than a second implementation of it would be.
//
// Two inputs are refusals rather than values, and are recorded as JSON nulls:
//
//   - `left` of an even index. Leaves have no children (Appendix A raises).
//   - `right` of the rightmost entry, size-1. Its right subtree spans indices
//     above the end of the log, so it is empty. Appendix A's `right` walks left
//     from a nonexistent child until it lands inside the tree, which for this
//     input walks off the bottom of the tree and asks a leaf for a child; katie
//     panics. Both implementations refuse, so a null here means "must not
//     produce a value".
func ibstVectors(sha string) (*File, error) {
	// Sizes chosen for the boundaries: powers of two and their neighbours, where
	// the root moves; §4.1's worked example of 50; and sizes near the top of the
	// u64 range, where a 63-bit level has to be shifted without overflowing.
	sizes := []uint64{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 14, 15, 16, 17,
		31, 32, 33, 49, 50, 51, 63, 64, 65, 100, 127, 128, 129,
		1000, 1023, 1024, 1025, 1 << 20, 1 << 40, 1 << 62, 1 << 63,
		math.MaxUint64 / 3, math.MaxUint64 - 1, math.MaxUint64,
	}

	f := &File{
		Primitive: "ibst",
		Draft:     draftRev + " §4.1, Appendix A",
		Generator: Generator{Impl: "katie", SHA: sha},
		Notes: "Implicit binary search tree over log entry indices. No cipher suite: " +
			"pure integer math. `root` is 2^floor(log2(size))-1, `frontier` is the root " +
			"followed by repeated right children to the last entry. In `nodes`, a null " +
			"`left` means the index is a leaf and a null `right` means the node is the " +
			"rightmost entry and its right subtree is empty; both must be refused rather " +
			"than answered. `nodes` lists every index when size <= 64 and the frontier " +
			"otherwise.",
	}

	for _, size := range sizes {
		nodes := make([]map[string]any, 0)
		for _, x := range ibstNodeIndices(size) {
			node := map[string]any{"index": x}
			if ktmath.IsLeaf(x) {
				node["left"] = nil
				node["right"] = nil
			} else {
				node["left"] = ktmath.Left(x)
				if x == size-1 {
					node["right"] = nil
				} else {
					node["right"] = ktmath.Right(x, size)
				}
			}
			nodes = append(nodes, node)
		}

		f.Cases = append(f.Cases, Case{
			Name:  fmt.Sprintf("size-%d", size),
			Input: map[string]any{"size": size},
			Expect: map[string]any{
				"root":     ktmath.Root(size),
				"frontier": ktmath.Frontier(size),
				"nodes":    nodes,
			},
		})
	}

	return f, nil
}

// ibstNodeIndices picks the indices to record children for: all of them in a
// small tree, the frontier in a large one. The frontier is the interesting path
// in a large tree — it is where `right` has to walk back down into range.
func ibstNodeIndices(size uint64) []uint64 {
	if size <= 64 {
		out := make([]uint64, 0, size)
		for x := uint64(0); x < size; x++ {
			out = append(out, x)
		}
		return out
	}
	return ktmath.Frontier(size)
}

// ladderVectors covers draft §5 and Appendix B: the versions looked up in a
// binary ladder.
//
// katie's baseBinaryLadder is unexported, but SearchBinaryLadder(n, n, nil, nil)
// is exactly it: the search ladder stops at the first lookup that distinguishes
// the target from the greatest version, and with target == greatest there is no
// such lookup, so the base ladder runs to the end. The generator cross-checks
// that against Appendix B's pseudocode (transcribed below) and refuses to emit
// vectors if the two disagree.
//
// Two places where the pinned katie is behind draft-05, both worked around here
// rather than papered over:
//
//   - Appendix B's search_binary_ladder iterates the base ladder of the greatest
//     version; katie iterates the base ladder of the target. The outputs are
//     equal — see draftSearchBinaryLadder, which is checked against katie over a
//     grid below — so the vectors are still a valid oracle for either shape.
//   - Appendix B's monitoring_binary_ladder takes a left_inclusion set to
//     deduplicate lookups already proven to the left; katie's takes only the
//     target. So monitoring vectors are emitted with an empty set only, and the
//     deduplicating behaviour is left to Rust-side tests.
//
// The largest greatest-version covered is 2^31-2, because the pinned peer does
// not terminate above that. katie computes its ladder in uint32, and the binary
// search phase takes the midpoint as `(lower + upper) / 2`; once
// `lower + upper` exceeds MaxUint32 that sum wraps, the midpoint lands *below*
// the lower bound, and the loop walks away from its own interval, appending
// forever. The first affected input is 2^31-1, where the upper bound becomes
// 2^32-1: verified at pin 00da5254, where 2^31-2 returns a 62-rung ladder and
// 2^31-1 is killed by the OOM killer. Separately, at MaxUint32 phase 1 itself
// does not terminate: `uint32(1) << 32` is 0 in Go, so the rung wraps to
// MaxUint32, which never exceeds MaxUint32.
//
// Neither is reachable from the Rust side, which computes rungs in u64 and
// reports the one genuinely impossible case — a greatest version of MaxUint32,
// whose ladder needs a non-inclusion proof for version 2^32 — as an error. Those
// edges are pinned by Rust-side tests. Both peer bugs are worth an upstream
// report; a client's `n` comes from what the log proves, so a log can choose it.
func ladderVectors(sha string) (*File, error) {
	f := &File{
		Primitive: "binary-ladder",
		Draft:     draftRev + " §5, Appendix B",
		Generator: Generator{Impl: "katie", SHA: sha},
		Notes: "Versions looked up in a binary ladder. No cipher suite: pure integer " +
			"math. `kind` selects the variant: base (§5), search (§6.2), or monitoring " +
			"(§8.1). Base vectors come from SearchBinaryLadder(n, n) because a search " +
			"ladder whose target equals the greatest version never terminates early. " +
			"Monitoring vectors use an empty left_inclusion set only, since the pinned " +
			"peer predates that parameter. Versions stop at 2^31-2, above which the " +
			"peer's uint32 midpoint overflows and its binary search does not " +
			"terminate; see the generator comment.",
	}

	// The peer diverges at 2^31-1 and above, so that is the ceiling here. See the
	// function comment for the derivation.
	const peerCeiling = uint32(1)<<31 - 2

	greatest := []uint32{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 31, 32, 33,
		63, 64, 65, 100, 255, 256, 257, 1000, 65535, 65536,
		1 << 20, 1 << 30, peerCeiling - 1, peerCeiling,
	}
	for _, n := range greatest {
		ladder := katieBaseBinaryLadder(n)
		if want := draftBaseBinaryLadder(n); !equalVersions(ladder, want) {
			return nil, fmt.Errorf(
				"base ladder for greatest=%d: katie has %v, draft Appendix B has %v",
				n, ladder, want)
		}
		f.Cases = append(f.Cases, Case{
			Name:   fmt.Sprintf("base-greatest-%d", n),
			Input:  map[string]any{"kind": "base", "greatest": n},
			Expect: map[string]any{"versions": ladder},
		})
	}

	// Search ladders. The pairs cover: target below, at, and above the greatest
	// version; the boundaries where a power-of-two rung settles it immediately;
	// and both ends of the range.
	type searchCase struct {
		target, greatest  uint32
		left, rightAbsent []uint32
	}
	searches := []searchCase{
		{0, 0, nil, nil},
		{0, 1, nil, nil},
		{1, 0, nil, nil},
		{5, 100, nil, nil},
		{100, 5, nil, nil},
		{6, 6, nil, nil},
		{7, 6, nil, nil},
		{6, 7, nil, nil},
		{63, 64, nil, nil},
		{64, 63, nil, nil},
		{1000, 1000, nil, nil},
		{999, 1000, nil, nil},
		{1000, 999, nil, nil},
		{0, peerCeiling, nil, nil},
		{peerCeiling, 0, nil, nil},
		{peerCeiling, peerCeiling, nil, nil},
		{peerCeiling - 1, peerCeiling, nil, nil},
		// Deduplication against proofs already given to the left and right.
		{5, 100, []uint32{0, 1}, nil},
		{5, 100, []uint32{7}, nil},
		{5, 100, nil, []uint32{3}},
		{5, 100, []uint32{0, 1, 3, 7}, nil},
		{6, 6, []uint32{0, 1, 3}, []uint32{5}},
		{1000, 1000, []uint32{0, 1, 3, 7, 15, 31}, []uint32{1023}},
	}
	for i, s := range searches {
		ladder := ktmath.SearchBinaryLadder(
			s.target, s.greatest, versionSet(s.left), versionSet(s.rightAbsent))
		if want := draftSearchBinaryLadder(s.target, s.greatest, s.left, s.rightAbsent); !equalVersions(ladder, want) {
			return nil, fmt.Errorf(
				"search ladder for target=%d greatest=%d: katie has %v, draft Appendix B has %v",
				s.target, s.greatest, ladder, want)
		}
		f.Cases = append(f.Cases, Case{
			Name: fmt.Sprintf("search-%d-target-%d-greatest-%d", i, s.target, s.greatest),
			Input: map[string]any{
				"kind":                "search",
				"target":              s.target,
				"greatest":            s.greatest,
				"left_inclusion":      versions(s.left),
				"right_non_inclusion": versions(s.rightAbsent),
			},
			Expect: map[string]any{"versions": ladder},
		})
	}

	// A wider grid, checked in the generator rather than written out case by
	// case: katie's target-indexed search ladder and Appendix B's
	// greatest-indexed one must agree everywhere, not just on the pairs above.
	for target := uint32(0); target <= 130; target++ {
		for n := uint32(0); n <= 130; n++ {
			got := ktmath.SearchBinaryLadder(target, n, nil, nil)
			if want := draftSearchBinaryLadder(target, n, nil, nil); !equalVersions(got, want) {
				return nil, fmt.Errorf(
					"search ladder grid at target=%d greatest=%d: katie has %v, draft has %v",
					target, n, got, want)
			}
		}
	}

	monitored := []uint32{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17, 63, 64, 100, 255, 256,
		1000, 65535, 1 << 20, 1 << 30, peerCeiling,
	}
	for _, t := range monitored {
		ladder := ktmath.MonitoringBinaryLadder(t)
		if want := draftMonitoringBinaryLadder(t, nil); !equalVersions(ladder, want) {
			return nil, fmt.Errorf(
				"monitoring ladder for target=%d: katie has %v, draft Appendix B has %v",
				t, ladder, want)
		}
		f.Cases = append(f.Cases, Case{
			Name: fmt.Sprintf("monitoring-target-%d", t),
			Input: map[string]any{
				"kind":           "monitoring",
				"target":         t,
				"left_inclusion": versions(nil),
			},
			Expect: map[string]any{"versions": ladder},
		})
	}

	return f, nil
}

// katieBaseBinaryLadder returns the peer's base binary ladder for `n`.
//
// baseBinaryLadder is unexported, so this goes through SearchBinaryLadder with
// the target equal to the greatest version, which never terminates early.
func katieBaseBinaryLadder(n uint32) []uint32 {
	return ktmath.SearchBinaryLadder(n, n, nil, nil)
}

// draftBaseBinaryLadder is Appendix B's base_binary_ladder, transcribed from the
// draft (which is where the pseudocode is meant to be taken from) and computed in
// uint64 so the rungs above MaxUint32 are representable instead of wrapping.
func draftBaseBinaryLadder(n uint32) []uint32 {
	wide := draftBaseLadderRungs(uint64(n))
	out := make([]uint32, 0, len(wide))
	for _, rung := range wide {
		if rung > math.MaxUint32 {
			// Not representable as a version; the caller's `n` never reaches
			// MaxUint32, so this cannot be hit for the emitted vectors.
			break
		}
		out = append(out, uint32(rung))
	}
	return out
}

func draftBaseLadderRungs(n uint64) []uint64 {
	out := make([]uint64, 0)

	// Powers of two minus one until reaching a value greater than n.
	for exponent := 0; exponent <= 33; exponent++ {
		value := (uint64(1) << exponent) - 1
		out = append(out, value)
		if value > n {
			break
		}
	}

	// Binary search between the established lower and upper bounds.
	lower, upper := out[len(out)-2], out[len(out)-1]
	for lower+1 < upper {
		value := (lower + upper) / 2
		out = append(out, value)
		if value <= n {
			lower = value
		} else {
			upper = value
		}
	}

	return out
}

// draftSearchBinaryLadder is Appendix B's search_binary_ladder: the base ladder
// of the *greatest* version, truncated at the first lookup that settles whether
// the greatest version reaches the target, minus lookups already answered.
func draftSearchBinaryLadder(target, greatest uint32, left, rightAbsent []uint32) []uint32 {
	wouldEnd := func(v uint64) bool {
		t, n := uint64(target), uint64(greatest)
		return (v <= n && v > t) || (v > n && v <= t)
	}

	out := make([]uint32, 0)
	for _, rung := range draftBaseLadderRungs(uint64(greatest)) {
		if rung > math.MaxUint32 {
			break
		}
		v := uint32(rung)
		if !containsVersion(left, v) && !containsVersion(rightAbsent, v) {
			out = append(out, v)
		}
		if wouldEnd(rung) {
			break
		}
	}
	return out
}

// draftMonitoringBinaryLadder is Appendix B's monitoring_binary_ladder: the base
// ladder of the monitored version, keeping only the rungs at or below it.
func draftMonitoringBinaryLadder(target uint32, left []uint32) []uint32 {
	out := make([]uint32, 0)
	for _, rung := range draftBaseLadderRungs(uint64(target)) {
		if rung > uint64(target) {
			continue
		}
		v := uint32(rung)
		if !containsVersion(left, v) {
			out = append(out, v)
		}
	}
	return out
}

func containsVersion(haystack []uint32, needle uint32) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func equalVersions(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// versionSet converts to the set shape katie's ladder functions take.
func versionSet(vs []uint32) map[uint32]struct{} {
	if vs == nil {
		return nil
	}
	out := make(map[uint32]struct{}, len(vs))
	for _, v := range vs {
		out[v] = struct{}{}
	}
	return out
}

// versions normalizes nil to an empty slice so the JSON has [] rather than null:
// an absent set and an empty set are the same thing here, and a decoder should
// not have to handle both.
func versions(vs []uint32) []uint32 {
	if vs == nil {
		return []uint32{}
	}
	return vs
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
