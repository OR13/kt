package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"

	"github.com/Bren2010/katie/crypto/suites"
	ktmath "github.com/Bren2010/katie/tree/transparency/math"
	"github.com/Bren2010/katie/tree/transparency/structs"
)

// auditorStateView is the auditor's persisted state, decoded. katie unexported its state type
// when it started persisting more than the tree head, so the only way to see what the auditor is
// carrying is to read the bytes it hands to its AuditorStore. That layout is katie's, not the
// draft's (§15.2 says what an auditor must retain, not how), so it is read here and only here.
type auditorStateView struct {
	TreeHead     structs.AuditorTreeHead
	FullSubtrees [][]byte
	Timestamps   []uint64
	PrefixTree   []byte
	Inserted     []insertedVrf
}

type insertedVrf struct {
	Pos       uint64
	VrfOutput []byte
}

func decodeAuditorState(cs suites.CipherSuite, raw []byte) (*auditorStateView, error) {
	buf := bytes.NewBuffer(raw)
	head, err := structs.NewAuditorTreeHead(buf)
	if err != nil {
		return nil, err
	}
	out := &auditorStateView{TreeHead: *head}

	out.FullSubtrees = make([][]byte, bits.OnesCount64(head.TreeSize))
	for i := range out.FullSubtrees {
		out.FullSubtrees[i] = make([]byte, cs.HashSize())
		if _, err := io.ReadFull(buf, out.FullSubtrees[i]); err != nil {
			return nil, err
		}
	}
	out.Timestamps = make([]uint64, len(ktmath.Frontier(head.TreeSize)))
	for i := range out.Timestamps {
		if err := binary.Read(buf, binary.BigEndian, &out.Timestamps[i]); err != nil {
			return nil, err
		}
	}
	out.PrefixTree = make([]byte, cs.HashSize())
	if _, err := io.ReadFull(buf, out.PrefixTree); err != nil {
		return nil, err
	}
	var count uint32
	if err := binary.Read(buf, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	for range count {
		var ins insertedVrf
		if err := binary.Read(buf, binary.BigEndian, &ins.Pos); err != nil {
			return nil, err
		}
		ins.VrfOutput = make([]byte, cs.HashSize())
		if _, err := io.ReadFull(buf, ins.VrfOutput); err != nil {
			return nil, err
		}
		out.Inserted = append(out.Inserted, ins)
	}
	if buf.Len() != 0 {
		return nil, fmt.Errorf("%d trailing bytes in auditor state", buf.Len())
	}
	return out, nil
}
