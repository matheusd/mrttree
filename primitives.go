package mrttree

import (
	"fmt"
	"hash"

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

func taggedHasher(tag string) hash.Hash {
	taghash := blake256.Sum256([]byte(tag))
	hasher := blake256.New()
	hasher.Write(taghash[:])
	hasher.Write(taghash[:])
	return hasher
}

func musigKeyTweak(L *chainhash.Hash, pubSer []byte) (secp256k1.ModNScalar, error) {
	hasher := taggedHasher("muSigKeyTweak")
	hasher.Write(L[:])
	hasher.Write(pubSer)
	tweakBytes := hasher.Sum(nil)

	// TODO: bounds check tweakBytes (= 0, >= q)

	var res secp256k1.ModNScalar
	res.SetByteSlice(tweakBytes)
	return res, nil
}

func hashKeys(tag string, keys ...[]byte) chainhash.Hash {
	hasher := taggedHasher(tag)
	for _, key := range keys {
		hasher.Write(key)
	}
	var res chainhash.Hash
	copy(res[:], hasher.Sum(nil))
	return res
}

func hashPubKeys(tag string, keys ...*secp256k1.PublicKey) chainhash.Hash {
	hasher := taggedHasher(tag)
	for _, key := range keys {
		hasher.Write(key.SerializeCompressed())
	}
	var res chainhash.Hash
	copy(res[:], hasher.Sum(nil))
	return res
}

func mergeKeySlices(s1, s2 []*secp256k1.PublicKey) []*secp256k1.PublicKey {
	r := make([]*secp256k1.PublicKey, 0, len(s1)+len(s2))
	r = append(r, s1...)
	r = append(r, s2...)
	return r
}

func musigGroupKey(tag string, keys []*secp256k1.PublicKey, serKeys [][]byte) (*secp256k1.PublicKey, *chainhash.Hash, error) {

	L := hashKeys(tag, serKeys...)
	var buff [32 + 33]byte
	copy(buff[:32], L[:])

	var groupKey secp256k1.PublicKey

	for i, key := range keys {
		tweakModN, err := musigKeyTweak(&L, serKeys[i])
		if err != nil {
			return nil, nil, err
		}

		tweakedKey := scalarMultKey(&tweakModN, key)
		groupKey = addPubKeys(&groupKey, &tweakedKey)
	}

	return &groupKey, &L, nil
}

func musigGroupKeyFromKeys(tag string, keys ...*secp256k1.PublicKey) (*secp256k1.PublicKey, *chainhash.Hash, error) {
	serKeys := make([][]byte, len(keys))
	for i, key := range keys {
		serKeys[i] = key.SerializeCompressed()
	}
	return musigGroupKey(tag, keys, serKeys)
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

// schnorrVerifyWithPubSig verifies the scalar of the given sigPub will produce
// a valid schnorr signature for the given msg and public key, along with the
// given nonce pub.
func schnorrVerifyWithPubSig(RPub, sigPub, key *secp256k1.PublicKey, msg []byte) error {
	const scalarSize = 32
	var sG, R, P secp256k1.JacobianPoint

	// The verification equation is:
	//
	//     sG ?= R - eP
	//
	// Rewriting we get:
	//
	//    sG + eP ?= R
	//
	// Therefore, we calculate eP, add to sG (the sigPub argument) and
	// verify it equals the public nonce.
	sigPub.AsJacobian(&sG)
	RPub.AsJacobian(&R)
	key.AsJacobian(&P)

	// Calculate the hash commitment e = H(R.x || msg)
	var commitmentInput [scalarSize * 2]byte
	R.X.PutBytesUnchecked(commitmentInput[0:scalarSize])
	copy(commitmentInput[scalarSize:], msg[:])
	commitment := blake256.Sum256(commitmentInput[:])
	var e secp256k1.ModNScalar
	if overflow := e.SetBytes(&commitment); overflow != 0 {
		str := "hash of (R || m) too big"
		return fmt.Errorf(str)
	}

	// Calculate eP
	var eP secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(&e, &P, &eP)

	// Add to find the challenge = sG + eP.
	var challenge secp256k1.JacobianPoint
	secp256k1.AddNonConst(&sG, &eP, &challenge)

	// Ensure they match.
	challenge.ToAffine()
	if !challenge.X.Equals(&R.X) {
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
