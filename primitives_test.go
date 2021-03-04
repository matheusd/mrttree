package mrttree

import (
	"math/rand"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrec/secp256k1/v3/schnorr"
)

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestPartialMusigSign(t *testing.T) {
	rnd := rand.New(rand.NewSource(0x22345670))

	msg := make([]byte, 32)
	rnd.Read(msg)
	tag := "testTag"

	nbKeys := 8
	keys := make([]*secp256k1.PrivateKey, nbKeys)
	pubKeys := make([]*secp256k1.PublicKey, nbKeys)
	nonces := make([]*secp256k1.PrivateKey, nbKeys)
	nonceBytes := make([][]byte, nbKeys)
	for i := 0; i < nbKeys; i++ {
		keys[i] = randKey(rnd)
		pubKeys[i] = keys[i].PubKey()
		nonces[i] = randKey(rnd)
		nonceBytes[i] = nonces[i].PubKey().SerializeCompressed()
	}

	groupKey, musigL, err := musigGroupKeyFromKeys(tag, pubKeys...)
	assertNoError(t, err)

	RPub, inverted, err := produceR(nonceBytes)
	assertNoError(t, err)

	fullS := new(secp256k1.ModNScalar)
	for i := 0; i < nbKeys; i++ {
		s, err := partialMuSigSign(RPub, inverted, musigL, nonces[i],
			keys[i], msg)
		assertNoError(t, err)
		fullS.Add(s)
	}

	var R secp256k1.JacobianPoint
	RPub.AsJacobian(&R)
	sig := schnorr.NewSignature(&R.X, fullS)

	if !sig.Verify(msg, groupKey) {
		t.Fatal("signature did not verify")
	}
}
