package api

import (
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/wire"
)

func MarshalPrefundInputs(inputs []*wire.TxIn) []*RevealLeafKeysResponseInput {
	res := make([]*RevealLeafKeysResponseInput, len(inputs))
	for i, in := range inputs {
		res[i] = &RevealLeafKeysResponseInput{
			Amount:   in.ValueIn,
			Hash:     in.PreviousOutPoint.Hash[:],
			Index:    in.PreviousOutPoint.Index,
			Tree:     uint32(in.PreviousOutPoint.Tree),
			Sequence: in.Sequence,
		}
	}
	return res
}

func MarshalMapByteSlices(in map[uint32][][]byte) map[uint32]*ByteSlices {
	res := make(map[uint32]*ByteSlices, len(in))
	for k, v := range in {
		res[k] = &ByteSlices{Data: v}
	}
	return res
}

func UnmarshalMapByteSlices(in map[uint32]*ByteSlices) map[uint32][][]byte {
	res := make(map[uint32][][]byte, len(in))
	for k, v := range in {
		res[k] = v.Data
	}
	return res
}

func UnmarshalInputs(in []*RevealLeafKeysResponseInput) ([]*wire.TxIn, error) {
	res := make([]*wire.TxIn, len(in))
	var hash chainhash.Hash
	for i, in := range in {
		if err := hash.SetBytes(in.Hash); err != nil {
			return nil, err
		}
		res[i] = &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  hash,
				Index: in.Index,
				Tree:  int8(in.Tree),
			},
			ValueIn:  in.Amount,
			Sequence: in.Sequence,
		}
	}
	return res, nil
}
