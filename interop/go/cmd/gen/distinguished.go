// Vectors for distinguished log entries (draft §6.1).
//
// Distinguished entries are the protocol's common reference points: users check consistency
// against them instead of against every entry, so two users who agree about one are
// provably looking at the same log. §6.1 chooses them with a recursion over the implicit
// binary search tree — an entry is distinguished when the gap between the timestamps
// bracketing it reaches the Reasonable Monitoring Window, and then both halves are
// examined the same way.
//
// What makes this worth pinning is that katie does not run that recursion. It walks the
// frontier instead: `RightmostDistinguished` descends from the root while the current node's
// right child is still distinguished, which is O(log n) instead of O(size of the set).
// `PreviousRightmost` is stranger still — it has a special case for when the rightmost
// entry is itself distinguished, and then hunts for the rightmost edge of a subtree.
//
// Neither shortcut is obviously the recursion. So these vectors record what katie answers,
// and the Rust side answers from §6.1 directly and compares. The shortcut being correct is
// then a result rather than an assumption — and if it ever is not, the disagreement is
// about a set that decides which log entries every user in the deployment must inspect.
//
// The `timestamps` in each case are the ones the algorithm is allowed to consult, which is
// deliberately not "all of them": katie's DataProvider refuses timestamps that are not
// monotonic and refuses to be asked the same position twice, so a case that supplies a
// position the algorithm never visits would fail loudly rather than pass quietly. That
// makes `requested` — the positions katie actually asked about — evidence in its own right.
package main

import (
	"errors"
	"fmt"
	"sort"

	"github.com/Bren2010/katie/crypto/suites"
	"github.com/Bren2010/katie/crypto/vrf/edwards25519"
	"github.com/Bren2010/katie/tree/transparency/algorithms"
	"github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// timestampHandle answers timestamp queries from a fixed map and refuses everything else.
//
// The refusals matter: only GetTimestamp should ever be called for these algorithms, and an
// implementation of this interface that quietly returned zeroes would let a vector record an
// answer computed from data the algorithm was never entitled to.
type timestampHandle struct {
	timestamps map[uint64]uint64
	requested  []uint64
}

func (h *timestampHandle) GetTimestamp(x uint64) (uint64, error) {
	ts, ok := h.timestamps[x]
	if !ok {
		return 0, fmt.Errorf("no timestamp available for log entry %d", x)
	}
	h.requested = append(h.requested, x)
	return ts, nil
}

func (h *timestampHandle) GetSearchBinaryLadder(uint64, uint32, bool) ([]byte, int, error) {
	return nil, 0, errors.New("unexpected call to GetSearchBinaryLadder")
}

func (h *timestampHandle) GetMonitoringBinaryLadder(uint64, uint32) ([]byte, error) {
	return nil, errors.New("unexpected call to GetMonitoringBinaryLadder")
}

func (h *timestampHandle) GetInclusionProof(uint64, []uint32) ([]byte, error) {
	return nil, errors.New("unexpected call to GetInclusionProof")
}

func (h *timestampHandle) GetPrefixTrees([]uint64) ([][]byte, error) {
	return nil, errors.New("unexpected call to GetPrefixTrees")
}

func (h *timestampHandle) Finish() ([][]byte, error) {
	return nil, errors.New("unexpected call to Finish")
}

func (h *timestampHandle) Output([]uint64, uint64, *uint64, *uint64) (*structs.CombinedTreeProof, error) {
	return nil, errors.New("unexpected call to Output")
}

func (h *timestampHandle) StopCondition(uint64, int) bool { return false }

func (h *timestampHandle) Tracker() *math.VersionTracker { return &math.VersionTracker{} }

// distinguishedVectors covers draft §6.1.
func distinguishedVectors(sha string) (*File, error) {
	cs := suites.KTSha256Ed25519{}

	f := &File{
		Primitive: "distinguished",
		Draft:     draftRev + " §6.1",
		Generator: Generator{Impl: "katie", SHA: sha},
		Notes: "Distinguished log entries, the reference points every user checks against. " +
			"`size` is the tree size, `window` the Reasonable Monitoring Window, and " +
			"`timestamps` a position-to-timestamp map the algorithm may consult. " +
			"`rightmost` is the rightmost distinguished entry and `previous_rightmost` the " +
			"rightmost one left of the log's last entry, both absent where there is none. " +
			"`requested` lists the positions the peer asked about, in order: the peer " +
			"reaches these answers by walking the frontier rather than by running §6.1's " +
			"recursion, so which entries it needed to see is part of what is being pinned.",
	}

	// A configuration whose only relevant field is the monitoring window; the keys are
	// fixed so regeneration is a no-op diff.
	logKey, err := cs.ParseSigningPrivateKey(repeat(0x71, 32))
	if err != nil {
		return nil, fmt.Errorf("parsing the log signing key: %w", err)
	}
	vrfKey, err := edwards25519.NewPrivateKey(repeat(0x74, 32))
	if err != nil {
		return nil, fmt.Errorf("parsing the VRF key: %w", err)
	}

	for _, spec := range distinguishedCases() {
		public := &structs.PublicConfig{
			SignatureKey: logKey.Public(),
			VrfKey:       vrfKey.PublicKey(),
			Config: structs.Config{
				Suite:                      cs,
				Mode:                       structs.ContactMonitoring,
				MaxAhead:                   10000,
				MaxBehind:                  10000,
				ReasonableMonitoringWindow: spec.window,
			},
		}

		timestamps := make(map[uint64]uint64, spec.size)
		for i := range spec.size {
			timestamps[i] = spec.timestamp(i)
		}

		rightmost, requestedRightmost, err := runRightmost(public, spec.size, timestamps)
		if err != nil {
			return nil, fmt.Errorf("case %q: %w", spec.name, err)
		}
		previous, requestedPrevious, err := runPrevious(public, spec.size, timestamps)
		if err != nil {
			return nil, fmt.Errorf("case %q: %w", spec.name, err)
		}

		// Whatever the shortcut returns has to be to the left of the rightmost log entry,
		// or the two functions do not mean what their names say.
		if previous != nil && spec.size > 0 && *previous >= spec.size-1 {
			return nil, fmt.Errorf(
				"case %q: previous rightmost %d is not left of entry %d",
				spec.name, *previous, spec.size-1)
		}

		expect := map[string]any{
			"requested":           dedupeSorted(append(requestedRightmost, requestedPrevious...)),
			"requested_rightmost": indices(requestedRightmost),
			"requested_previous":  indices(requestedPrevious),
		}
		if rightmost != nil {
			expect["rightmost"] = *rightmost
		}
		if previous != nil {
			expect["previous_rightmost"] = *previous
		}

		f.Cases = append(f.Cases, Case{
			Name: spec.name,
			Input: map[string]any{
				"size":       spec.size,
				"window":     spec.window,
				"timestamps": timestampsJSON(timestamps, spec.size),
			},
			Expect: expect,
		})
	}

	return f, nil
}

func runRightmost(
	public *structs.PublicConfig, size uint64, timestamps map[uint64]uint64,
) (*uint64, []uint64, error) {
	handle := &timestampHandle{timestamps: timestamps}
	provider := algorithms.NewDataProvider(public.Suite, handle)
	out, err := algorithms.RightmostDistinguished(public, size, provider)
	if err != nil {
		return nil, nil, fmt.Errorf("rightmost distinguished: %w", err)
	}
	return out, handle.requested, nil
}

func runPrevious(
	public *structs.PublicConfig, size uint64, timestamps map[uint64]uint64,
) (*uint64, []uint64, error) {
	handle := &timestampHandle{timestamps: timestamps}
	provider := algorithms.NewDataProvider(public.Suite, handle)
	out, err := algorithms.PreviousRightmost(public, size, provider)
	if err != nil {
		return nil, nil, fmt.Errorf("previous rightmost: %w", err)
	}
	return out, handle.requested, nil
}

type distinguishedCase struct {
	name      string
	size      uint64
	window    uint64
	timestamp func(uint64) uint64
}

func distinguishedCases() []distinguishedCase {
	// Timestamps a fixed step apart, so a window of k*step makes a run of k entries the
	// unit of distinction and the expected answers are readable by hand.
	const step = 1000
	evenly := func(position uint64) uint64 { return position * step }

	// Timestamps that stall and then jump: a log that goes quiet for a while and then
	// catches up. Distinguished entries should cluster around the jump rather than the
	// entries, which is the whole point of choosing them by time rather than by count.
	bursty := func(position uint64) uint64 {
		if position < 32 {
			return position
		}
		return 32 + (position-32)*10*step
	}

	cases := make([]distinguishedCase, 0, 64)

	// A sweep over sizes at a window of 8 entries' worth of time, which puts several
	// distinguished entries in the tree without making every entry one.
	for _, size := range []uint64{0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 127, 128, 129, 200, 255, 256, 257, 1000} {
		cases = append(cases, distinguishedCase{
			name:      fmt.Sprintf("evenly-size-%d", size),
			size:      size,
			window:    8 * step,
			timestamp: evenly,
		})
	}

	// A sweep over windows at a fixed size, from "everything" to "nothing".
	for _, window := range []uint64{0, 1, step, 2 * step, 8 * step, 32 * step, 99 * step, 100 * step, 1 << 40} {
		cases = append(cases, distinguishedCase{
			name:      fmt.Sprintf("window-%d-size-100", window),
			size:      100,
			window:    window,
			timestamp: evenly,
		})
	}

	// The uneven log.
	for _, size := range []uint64{33, 40, 64, 100} {
		cases = append(cases, distinguishedCase{
			name:      fmt.Sprintf("bursty-size-%d", size),
			size:      size,
			window:    5 * step,
			timestamp: bursty,
		})
	}

	// Every entry sharing one timestamp: the gap is always zero, so only a window of zero
	// distinguishes anything. A log that adds a batch of entries in the same millisecond
	// produces exactly this.
	for _, window := range []uint64{0, 1} {
		cases = append(cases, distinguishedCase{
			name:      fmt.Sprintf("simultaneous-window-%d", window),
			size:      50,
			window:    window,
			timestamp: func(uint64) uint64 { return 1700000000000 },
		})
	}

	return cases
}

func timestampsJSON(timestamps map[uint64]uint64, size uint64) []uint64 {
	out := make([]uint64, 0, size)
	for i := range size {
		out = append(out, timestamps[i])
	}
	return out
}

func dedupeSorted(values []uint64) []uint64 {
	out := make([]uint64, len(values))
	copy(out, values)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	deduped := out[:0]
	for i, v := range out {
		if i == 0 || out[i-1] != v {
			deduped = append(deduped, v)
		}
	}
	if deduped == nil {
		return []uint64{}
	}
	return deduped
}
