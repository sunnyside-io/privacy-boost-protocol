package addressprotocol

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
)

// Position distinguishes historical and native events within the same block,
// including logs on either side of the upgrade transaction.
type Position struct {
	BlockNumber      uint64 `json:"blockNumber"`
	TransactionIndex uint32 `json:"transactionIndex"`
	LogIndex         uint32 `json:"logIndex"`
}

// Compare orders chain events by block, transaction, then log index, returning
// -1, 0, or 1. The within-block position distinguishes both sides of activation.
func (p Position) Compare(other Position) int {
	for _, pair := range [][2]uint64{
		{p.BlockNumber, other.BlockNumber},
		{uint64(p.TransactionIndex), uint64(other.TransactionIndex)},
		{uint64(p.LogIndex), uint64(other.LogIndex)},
	} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}

	return 0
}

// Activation binds the native deployment context to its exact on-chain event.
type Activation struct {
	Context         Context     `json:"context"`
	Position        Position    `json:"position"`
	BlockHash       common.Hash `json:"blockHash"`
	TransactionHash common.Hash `json:"transactionHash"`
}

// Validate requires a complete deployment context and nonzero chain evidence.
// The caller is responsible for verifying that evidence against the canonical chain.
func (a Activation) Validate() error {
	if err := a.Context.Validate(); err != nil {
		return err
	}
	if a.BlockHash == (common.Hash{}) || a.TransactionHash == (common.Hash{}) {
		return errors.New("missing activation chain evidence")
	}

	return nil
}

// ActiveAt includes the activation log itself when comparing event positions.
func (a Activation) ActiveAt(position Position) bool { return position.Compare(a.Position) >= 0 }

// NoteFormat selects the format from the tree boundary and rejects native notes
// that precede activation. Legacy trees remain legacy after activation.
func (a Activation) NoteFormat(position Position, tree uint32) (string, error) {
	if a.Validate() != nil || tree > MaxTreeNumber {
		return "", errors.New("invalid note format context")
	}
	if tree >= a.Context.FirstNoteTreeV2 {
		if !a.ActiveAt(position) {
			return "", errors.New("native note precedes activation")
		}

		return AssetFormat, nil
	}

	return AssetFormatV1, nil
}
