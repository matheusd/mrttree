package testutils

import (
	"math/rand"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

type User struct {
	rnd     rand.Rand
	t       *testing.T
	UserIVs [][]byte

	KeysPrivs  map[[33]byte]*secp256k1.PrivateKey
	Keys       [][]byte
	KeysHashes [][]byte

	SellsPrivs  map[[33]byte]*secp256k1.PrivateKey
	Sells       [][]byte
	SellsHashes [][]byte

	FundsPrivs  map[[33]byte]*secp256k1.PrivateKey
	Funds       [][]byte
	FundsHashes [][]byte

	TreeNoncesPrivs  map[[33]byte]*secp256k1.PrivateKey
	TreeNonces       [][]byte
	TreeNoncesHashes [][]byte

	FundNoncesPrivs  map[[33]byte]*secp256k1.PrivateKey
	FundNonces       [][]byte
	FundNoncesHashes [][]byte
}

func NewUser(t *testing.T, seed int64) *User {
	rnd := rand.New(rand.NewSource(seed))

	userPrivs := make(map[[33]byte]*secp256k1.PrivateKey, nbLeafs)
	userHashes := make([][]byte, nbLeafs)
	userKeys := make([][]byte, nbLeafs)
	sellPrivs := make(map[[33]byte]*secp256k1.PrivateKey, nbLeafs)
	sellKeys := make([][]byte, nbLeafs)
	sellHashes := make([][]byte, nbLeafs)
	fundPrivs := make(map[[33]byte]*secp256k1.PrivateKey, nbLeafs)
	fundKeys := make([][]byte, nbLeafs)
	fundHashes := make([][]byte, nbLeafs)
	treeNoncePrivs := make(map[[33]byte]*secp256k1.PrivateKey, nbLeafs)
	treeNonces := make([][]byte, nbLeafs)
	treeNonceHashes := make([][]byte, nbLeafs)
	fundNoncePrivs := make(map[[33]byte]*secp256k1.PrivateKey, nbLeafs)
	fundNonces := make([][]byte, nbLeafs)
	fundNonceHashes := make([][]byte, nbLeafs)
	userIVs := make([][]byte, nbLeafs)

	triplets := []struct {
		privs  map[[33]byte]*secp256k1.PrivateKey
		keys   [][]byte
		hashes [][]byte
		useIV  bool
	}{
		{userPrivs, userKeys, userHashes, true},
		{sellPrivs, sellKeys, sellHashes, true},
		{fundPrivs, fundKeys, fundHashes, true},
		{treeNoncePrivs, treeNonces, treeNonceHashes, false},
		{fundNoncePrivs, fundNonces, fundNonceHashes, false},
	}

	for i := 0; i < nbLeafs; i++ {
		userIVs[i] = make([]byte, 16)
		mustRead(userIVs[i], rnd)

		for _, triplet := range triplets {
			var p [33]byte
			priv := randKey(rnd)
			copy(p[:], priv.PubKey().SerializeCompressed())
			triplet.privs[p] = priv
			triplet.keys[i] = p[:]
			if triplet.useIV {
				triplet.hashes[i] = hashKeyIV(p[:], userIVs[i])
			} else {
				triplet.hashes[i] = chainhash.HashB(p[:])
			}
		}

	}

	return &User{
		rnd:     rnd,
		UserIVs: userIVs,

		KeysPrivs:  userPrivs,
		Keys:       userKeys,
		KeysHashes: userHashes,

		SellsPrivs: sellPrivs,
		Sells:      sellKeys,
		SellHashes: sellHashes,

		FundsPrivs:  FundsPrivs,
		Funds:       FundsKeys,
		FundsHashes: FundsHashes,

		TreeNoncesPrivs:  TreeNoncesPrivs,
		TreeNonces:       TreeNoncesKeys,
		TreeNoncesHashes: TreeNoncesHashes,

		FundNoncesPrivs:  FundNoncesPrivs,
		FundNonces:       FundNoncesKeys,
		FundNoncesHashes: FundNoncesHashes,
	}
}
