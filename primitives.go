package mrttree

import (
	"fmt"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/crypto/blake256"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/wire"
)

func addPubKeys(p1, p2 *secp256k1.PublicKey) secp256k1.PublicKey {
	var pj1, pj2, res secp256k1.JacobianPoint
	p1.AsJacobian(&pj1)
	p2.AsJacobian(&pj2)
	secp256k1.AddNonConst(&pj1, &pj2, &res)
	res.ToAffine()
	resp := secp256k1.NewPublicKey(&res.X, &res.Y)
	return *resp
}

func scalarMultKey(s *secp256k1.ModNScalar, k *secp256k1.PublicKey) secp256k1.PublicKey {
	var pj, res secp256k1.JacobianPoint
	k.AsJacobian(&pj)
	secp256k1.ScalarMultNonConst(s, &pj, &res)
	res.ToAffine()
	resp := secp256k1.NewPublicKey(&res.X, &res.Y)
	return *resp
}

func musigKeyTweak(L *chainhash.Hash, pubSer []byte) (secp256k1.ModNScalar, error) {
	var buff [32 + 33]byte
	copy(buff[:32], L[:])
	copy(buff[32:], pubSer)
	tweakBytes := blake256.Sum256(buff[:])

	// TODO: bounds check tweakBytes (= 0, >= q)

	var res secp256k1.ModNScalar
	res.SetBytes(&tweakBytes)
	return res, nil
}

func hashKeys(keys ...[]byte) chainhash.Hash {
	hasher := blake256.New()
	for _, key := range keys {
		hasher.Write(key)
	}
	var res chainhash.Hash
	copy(res[:], hasher.Sum(nil))
	return res
}

func hashPubKeys(keys ...*secp256k1.PublicKey) chainhash.Hash {
	hasher := blake256.New()
	for _, key := range keys {
		hasher.Write(key.SerializeCompressed())
	}
	var res chainhash.Hash
	copy(res[:], hasher.Sum(nil))
	return res
}

func musigGroupKey(keys []*secp256k1.PublicKey, serKeys [][]byte) (*secp256k1.PublicKey, *chainhash.Hash, error) {

	L := hashKeys(serKeys...)
	var buff [32 + 33]byte
	copy(buff[:32], L[:])

	var groupKey secp256k1.PublicKey
	var tweakModN secp256k1.ModNScalar

	for i, key := range keys {
		copy(buff[32:], serKeys[i])
		tweak := blake256.Sum256(buff[:])

		// TODO: bounds check tweak (== 0, >= q)
		tweakModN.SetBytes(&tweak)

		tweakedKey := scalarMultKey(&tweakModN, key)
		groupKey = addPubKeys(&groupKey, &tweakedKey)
	}

	return &groupKey, &L, nil
}

func musigGroupKeyFromKeys(keys ...*secp256k1.PublicKey) (*secp256k1.PublicKey, *chainhash.Hash, error) {
	serKeys := make([][]byte, len(keys))
	for i, key := range keys {
		serKeys[i] = key.SerializeCompressed()
	}
	return musigGroupKey(keys, serKeys)
}

func sumKeys(pubs []*secp256k1.PublicKey) *secp256k1.PublicKey {
	var key secp256k1.PublicKey
	key = *pubs[0]
	for i := 1; i < len(pubs); i++ {
		key = addPubKeys(&key, pubs[i])
	}
	return &key
}

func produceR(nonces [][]byte) (*secp256k1.PublicKey, bool, error) {
	if len(nonces) == 0 {
		return nil, false, fmt.Errorf("no nonces")
	}
	var pj1, pj2, res secp256k1.JacobianPoint
	var p *secp256k1.PublicKey
	var err error

	if p, err = secp256k1.ParsePubKey(nonces[0]); err != nil {
		return nil, false, err
	}
	p.AsJacobian(&pj1)
	res = pj1

	for i := 1; i < len(nonces); i++ {
		if p, err = secp256k1.ParsePubKey(nonces[i]); err != nil {
			return nil, false, err
		}
		p.AsJacobian(&pj2)
		secp256k1.AddNonConst(&pj1, &pj2, &res)
		pj1 = res
	}

	inverted := false
	res.ToAffine()
	if res.Y.IsOdd() {
		res.Y.Negate(1)
		res.ToAffine()
		inverted = true
	}
	resp := secp256k1.NewPublicKey(&res.X, &res.Y)

	return resp, inverted, nil
}

func ProduceR(nonces [][]byte) (*secp256k1.PublicKey, error) {
	pk, _, err := produceR(nonces)
	return pk, err
}

func partialMuSigSign(RPub *secp256k1.PublicKey, invertedR bool, L *chainhash.Hash,
	nonce, priv *secp256k1.PrivateKey, msg []byte) (*secp256k1.ModNScalar, error) {

	const scalarSize = 32
	var R secp256k1.JacobianPoint
	RPub.AsJacobian(&R)

	k := nonce.Key

	// Step 5.
	//
	// Negate nonce k if R.y is odd (R.y is the y coordinate of the point R)
	//
	// Note that R must be in affine coordinates for this check.
	if invertedR {
		k.Negate()
	}

	// Step 6.
	//
	// r = R.x (R.x is the x coordinate of the point R)
	r := &R.X

	// Step 7.
	//
	// e = BLAKE-256(r || m) (Ensure r is padded to 32 bytes)
	var commitmentInput [scalarSize * 2]byte
	r.PutBytesUnchecked(commitmentInput[0:scalarSize])
	copy(commitmentInput[scalarSize:], msg[:])
	commitment := blake256.Sum256(commitmentInput[:])

	// Step 8.
	//
	// Repeat from step 1 (with iteration + 1) if e >= N
	var e secp256k1.ModNScalar
	if overflow := e.SetBytes(&commitment); overflow != 0 {
		str := "hash of (R || m) too big"
		return nil, fmt.Errorf(str)
	}

	// t is the musig tweak for this particular private key.
	t, err := musigKeyTweak(L, priv.PubKey().SerializeCompressed())
	if err != nil {
		return nil, err
	}

	// Step 9.
	//
	// s = k - e*d*t mod n
	s := new(secp256k1.ModNScalar).Mul2(&e, &priv.Key).Mul(&t).Negate().Add(&k)

	return s, nil
}

func partialMuSigVerify(RPub *secp256k1.PublicKey, L *chainhash.Hash, msg []byte, partialNonces [][]byte,
	partialKeys []*secp256k1.PublicKey, partialSig *secp256k1.ModNScalar) error {

	const scalarSize = 32
	var R secp256k1.JacobianPoint
	RPub.AsJacobian(&R)
	Rx := &R.X

	Upub, err := ProduceR(partialNonces)
	if err != nil {
		return err
	}
	var U secp256k1.JacobianPoint
	Upub.AsJacobian(&U)

	var Ppub secp256k1.PublicKey

	// Sum of partial tweak*pubKey.
	var t secp256k1.ModNScalar
	for _, key := range partialKeys {
		tweak, err := musigKeyTweak(L, key.SerializeCompressed())
		if err != nil {
			return err
		}
		t.Add(&tweak)

		tweakedKey := scalarMultKey(&tweak, key)
		Ppub = addPubKeys(&Ppub, &tweakedKey)
	}

	var P secp256k1.JacobianPoint
	Ppub.AsJacobian(&P)

	fmt.Printf("OOOOO U %x P %x\n", Upub.SerializeCompressed(), Ppub.SerializeCompressed())

	// The verification equation is:
	//
	//     s'G ?= U - H(R || m) * H(L || P) * P
	//
	// Rewriting we get:
	//
	//    s'G + H(R || m) * H(L || P) * P ?= U
	//
	// Where U is the sum of partial nonces, s' is the partial sig scalar
	// and P is the partial sum of keys.

	// Calculate commitment = Hash(R || m).
	var commitmentInput [scalarSize * 2]byte
	Rx.PutBytesUnchecked(commitmentInput[0:scalarSize])
	copy(commitmentInput[scalarSize:], msg[:])
	commitment := blake256.Sum256(commitmentInput[:])

	var e secp256k1.ModNScalar
	if overflow := e.SetBytes(&commitment); overflow != 0 {
		str := "hash of (R || m) too big"
		return fmt.Errorf(str)
	}

	// Multiply by the pubkey to get E = Hash(R ||m) * P.
	var E secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(&e, &P, &E)

	// We want to verify whether s'G + E == U , so calculate s'G.
	var sG secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(partialSig, &sG)

	// Add everything to get s'G + Hash(T+U || m) * P.
	var challenge secp256k1.JacobianPoint
	secp256k1.AddNonConst(&sG, &E, &challenge)
	challenge.ToAffine()

	// That must equal the partial nonce U = uG
	if !challenge.X.Equals(&U.X) {
		return fmt.Errorf("challenge does not equal expected value")
	}
	return nil
}

func sumInputAmounts(ins []*wire.TxIn) int64 {
	var sum int64
	for _, in := range ins {
		sum += in.ValueIn
	}
	return sum
}
