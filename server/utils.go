package server

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"decred.org/mrttree/api"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/wire"
)

func readRand(b []byte) error {
	for {
		n, err := rand.Read(b[:])
		if err != nil {
			return fmt.Errorf("entropy failure: %w", err)
		}
		if n == len(b) {
			return nil
		}
		b = b[n:]
	}
}

func hashKeyIV(key, iv []byte) []byte {
	b := make([]byte, len(key)+len(iv))
	copy(b, key[:])
	copy(b[len(key):], iv)
	res := chainhash.HashB(b)
	return res
}

func verifyKeyIVHashes(keys [][]byte, ivs [][]byte, hashes [][]byte) error {
	var buff [16 + 33]byte
	for i := 0; i < len(keys); i++ {
		copy(buff[:33], keys[i])
		copy(buff[33:], ivs[i])
		verifyHash := chainhash.HashB(buff[:])
		if !bytes.Equal(verifyHash[:], hashes[i]) {
			return fmt.Errorf("key %d does not hash to correct value", i)
		}
	}
	return nil
}

func verifyKeyHashes(keys [][]byte, hashes [][]byte) error {
	for i := 0; i < len(keys); i++ {
		verifyHash := chainhash.HashB(keys[i])
		if !bytes.Equal(verifyHash[:], hashes[i]) {
			return fmt.Errorf("key %d does not hash to correct value", i)
		}
	}
	return nil
}

func verifySanePubKeys(keys [][]byte) error {
	for i := 0; i < len(keys); i++ {
		_, err := secp256k1.ParsePubKey(keys[i])
		if err != nil {
			return fmt.Errorf("invalid key %d: %w", i, err)
		}
	}
	return nil
}

func marshalPrefundInputs(inputs []*wire.TxIn) []*api.RevealLeafKeysResponseInput {
	res := make([]*api.RevealLeafKeysResponseInput, len(inputs))
	for i, in := range inputs {
		res[i] = &api.RevealLeafKeysResponseInput{
			Amount:   in.ValueIn,
			Hash:     in.PreviousOutPoint.Hash[:],
			Index:    in.PreviousOutPoint.Index,
			Tree:     uint32(in.PreviousOutPoint.Tree),
			Sequence: in.Sequence,
		}
	}
	return res
}

func marshalMapByteSlices(in map[uint32][][]byte) map[uint32]*api.ByteSlices {
	res := make(map[uint32]*api.ByteSlices, len(in))
	for k, v := range in {
		res[k] = &api.ByteSlices{Data: v}
	}
	return res
}

func unmarshalMapByteSlices(in map[uint32]*api.ByteSlices) map[uint32][][]byte {
	res := make(map[uint32][][]byte, len(in))
	for k, v := range in {
		res[k] = v.Data
	}
	return res
}

func unmarshalInputs(in []*api.RevealLeafKeysResponseInput) ([]*wire.TxIn, error) {
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
