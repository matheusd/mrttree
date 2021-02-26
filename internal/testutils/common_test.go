package server

import (
	"io"
	"math/rand"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

func mustRead(b []byte, r io.Reader) {
	n, err := r.Read(b)
	if err != nil {
		panic(err)
	}
	if n != len(b) {
		panic("wrong nb of bytes read")
	}
}

func randKey(rnd *rand.Rand) *secp256k1.PrivateKey {
	var k [32]byte
	_, err := rnd.Read(k[:])
	if err != nil {
		panic(err)
	}
	pk := secp256k1.PrivKeyFromBytes(k[:])
	return pk
}
