package mrttree

import (
	"fmt"
	"io"
	"math/rand"
	"testing"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrec/secp256k1/v3/schnorr"
	"github.com/decred/dcrd/txscript/v3"
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

func hashKeyIV(key, iv []byte) []byte {
	b := make([]byte, len(key)+len(iv))
	copy(b, key[:])
	copy(b[len(key):], iv)
	res := chainhash.HashB(b)
	return res
}

type TestUser struct {
	rnd     *rand.Rand
	t       *testing.T
	tree    *Tree
	Name    string
	UserIVs [][]byte

	KeysPrivs  map[[33]byte]*secp256k1.PrivateKey
	Keys       [][]byte
	KeysHashes [][]byte

	SellPrivs  map[[33]byte]*secp256k1.PrivateKey
	Sell       [][]byte
	SellHashes [][]byte

	FundPrivs  map[[33]byte]*secp256k1.PrivateKey
	Fund       [][]byte
	FundHashes [][]byte

	FundNoncesPrivs  map[[33]byte]*secp256k1.PrivateKey
	FundNonces       [][]byte
	FundNoncesHashes [][]byte

	NodeIndices      map[uint32]int
	TreeNoncesPrivs  map[[33]byte]*secp256k1.PrivateKey
	TreeNonces       map[uint32][][]byte
	TreeNoncesHashes map[uint32][][]byte

	TreeSigs map[uint32][][]byte
	FundSigs [][]byte
}

func (u *TestUser) GenerateNonces(tree *Tree) {
	u.t.Helper()

	// Gather all our leaf keys.
	leafKeys := make([]*secp256k1.PublicKey, len(u.Keys))
	for i, k := range u.Keys {
		var err error
		leafKeys[i], err = secp256k1.ParsePubKey(k)
		if err != nil {
			u.t.Fatal(err)
		}
	}

	// Generate the map of how many times we are included in each node.
	var err error
	leafToNodes := tree.BuildLeafPubKeyMap()
	u.NodeIndices, err = leafToNodes.AncestorBranchesCount(leafKeys)
	if err != nil {
		u.t.Fatal(err)
	}

	// Generate the correct number of nonces for each node.
	noncesPrivs := make(map[[33]byte]*secp256k1.PrivateKey)
	nonces := make(map[uint32][][]byte)
	noncesHashes := make(map[uint32][][]byte)
	for nodeIndex, nbNonces := range u.NodeIndices {
		for i := 0; i < nbNonces; i++ {
			var p [33]byte
			priv := randKey(u.rnd)
			copy(p[:], priv.PubKey().SerializeCompressed())
			nonceHash := chainhash.HashB(p[:])
			noncesPrivs[p] = priv
			nonces[nodeIndex] = append(nonces[nodeIndex], p[:])
			noncesHashes[nodeIndex] = append(noncesHashes[nodeIndex], nonceHash)
		}
	}

	u.tree = tree
	u.TreeNoncesPrivs = noncesPrivs
	u.TreeNonces = nonces
	u.TreeNoncesHashes = noncesHashes
}

func (u *TestUser) SignTree(allNonces map[uint32][][]byte, allFundNonces [][]byte) error {
	// Sign each node where we participate in the tree.
	sigs := make(map[uint32][][]byte, len(u.NodeIndices))
	for index, nbSigs := range u.NodeIndices {
		R, invertedR, err := produceR(allNonces[index])
		if err != nil {
			return err
		}
		sigs[index] = make([][]byte, nbSigs)

		node := u.tree.Nodes[index]

		redeemScript, err := node.RedeemScript()
		if err != nil {
			return err
		}

		tx := node.Tx
		sigHash, err := txscript.CalcSignatureHash(redeemScript,
			txscript.SigHashAll, tx, 0, nil)
		if err != nil {
			return err
		}

		// Generate the group key and musig group tweak L.
		leafKeys := node.SubtreeUserLeafKeys()
		groupKey, musigL, err := musigGroupKeyFromKeys(leafKeys...)
		if err != nil {
			return err
		}

		// Filter keys to leave only the ones owned by this user.
		for i := 0; i < len(leafKeys); {
			var k [33]byte
			copy(k[:], leafKeys[i].SerializeCompressed())
			if _, ok := u.KeysPrivs[k]; ok {
				// User key.
				i++
			} else {
				// Non-user key (remove from list).
				leafKeys[i] = leafKeys[len(leafKeys)-1]
				leafKeys = leafKeys[:len(leafKeys)-1]
			}
		}

		// Sanity check.
		if len(leafKeys) != nbSigs {
			return fmt.Errorf("did not find correct nb of user keys "+
				"(want %d, got %d)", nbSigs, len(leafKeys))
		}

		fullS := new(secp256k1.ModNScalar)

		for i := 0; i < nbSigs; i++ {
			// Determine which nonce and priv key to use for this
			// partial sig.
			var myNoncePub, myPubKey [33]byte
			copy(myNoncePub[:], u.TreeNonces[index][i])
			r := u.TreeNoncesPrivs[myNoncePub]

			copy(myPubKey[:], leafKeys[i].SerializeCompressed())
			priv := u.KeysPrivs[myPubKey]

			sig, err := partialMuSigSign(R, invertedR, musigL, r, priv, sigHash)
			if err != nil {
				return err
			}
			s := sig.Bytes()
			sigs[index][i] = s[:]

			fullS.Add(sig)

			// Verify the aggregated sig so far.
			err = partialMuSigVerify(R, musigL, sigHash, u.TreeNonces[index][:i+1],
				leafKeys[:i+1], fullS)
			if err != nil {
				return fmt.Errorf("partial verify failed: %v", err)
			}
		}

		// Double check it's valid (only works if we have all leaf
		// keys)
		Rj := new(secp256k1.JacobianPoint)
		R.AsJacobian(Rj)
		sig := schnorr.NewSignature(&(Rj.X), fullS)
		if !sig.Verify(sigHash, groupKey) {
			return fmt.Errorf("full sig failed to validate")
		} else {
			fmt.Printf("XXXXX txh %s\n", tx.TxHash())
			fmt.Printf("XXXXX validated full sig msg %x\n", sigHash)
			fmt.Printf("XXXXX nbSigs %d s %x R %x\n", nbSigs, fullS.Bytes(),
				R.SerializeCompressed())
			fmt.Printf("XXXXX group key %x\n", groupKey.SerializeCompressed())
		}

		// Verify the final user's partial aggregated signature.
		err = partialMuSigVerify(R, musigL, sigHash, u.TreeNonces[index],
			leafKeys, fullS)
		if err != nil {
			return fmt.Errorf("partial verify failed: %v", err)
		}
	}

	// Sign the fund tx.
	R, invertedR, err := produceR(allFundNonces)
	if err != nil {
		return err
	}

	redeemScript, err := u.tree.FundScript()
	if err != nil {
		return err
	}

	tx := u.tree.Tx
	sigHash, err := txscript.CalcSignatureHash(redeemScript,
		txscript.SigHashAll, tx, 0, nil)
	if err != nil {
		return err
	}

	fundKey, fundMusigL, err := u.tree.FundKey()
	if err != nil {
		return err
	}

	// Create tuples of <fundKeyPriv, fundNoncePriv> to ease partial
	// signing.
	fundTuples := make([]struct {
		priv  *secp256k1.PrivateKey
		nonce *secp256k1.PrivateKey
	}, len(u.FundPrivs))
	fundNonces := make([][]byte, len(u.FundPrivs))
	fundPubs := make([]*secp256k1.PublicKey, len(u.FundPrivs))
	i := 0
	for _, key := range u.FundPrivs {
		fundTuples[i].priv = key
		fundPubs[i] = key.PubKey()
		i += 1
	}
	i = 0
	for _, nonce := range u.FundNoncesPrivs {
		fundTuples[i].nonce = nonce
		fundNonces[i] = nonce.PubKey().SerializeCompressed()
		i += 1
	}

	fundSigs := make([][]byte, len(u.FundPrivs))
	fundFullS := new(secp256k1.ModNScalar)
	for i, tuple := range fundTuples {
		sig, err := partialMuSigSign(R, invertedR, fundMusigL, tuple.nonce,
			tuple.priv, sigHash)
		if err != nil {
			return err
		}
		s := sig.Bytes()
		fundSigs[i] = s[:]
		fundFullS.Add(sig)
	}

	// Verify the final user's partial aggregated signature.
	err = partialMuSigVerify(R, fundMusigL, sigHash, fundNonces,
		fundPubs, fundFullS)
	if err != nil {
		return fmt.Errorf("partial verify of fund sig failed: %v", err)
	}

	// Double check it's valid (only works if we have all leaf keys)
	Rj := new(secp256k1.JacobianPoint)
	R.AsJacobian(Rj)
	sig := schnorr.NewSignature(&(Rj.X), fundFullS)
	if !sig.Verify(sigHash, fundKey) {
		return fmt.Errorf("full fund sig failed to validate")
	} else {
		fmt.Printf("YYYY txh %s\n", tx.TxHash())
		fmt.Printf("YYYY validated full sig msg %x\n", sigHash)
		fmt.Printf("YYYY s %x R %x\n", fundFullS.Bytes(),
			R.SerializeCompressed())
	}

	u.TreeSigs = sigs
	u.FundSigs = fundSigs
	return nil
}

func NewTestUser(t *testing.T, name string, seed int64, nbLeafs int) *TestUser {
	rnd := rand.New(rand.NewSource(seed))

	userIVs := make([][]byte, nbLeafs)
	userPrivs := make(map[[33]byte]*secp256k1.PrivateKey, nbLeafs)
	userHashes := make([][]byte, nbLeafs)
	userKeys := make([][]byte, nbLeafs)
	sellPrivs := make(map[[33]byte]*secp256k1.PrivateKey, nbLeafs)
	sellKeys := make([][]byte, nbLeafs)
	sellHashes := make([][]byte, nbLeafs)
	fundPrivs := make(map[[33]byte]*secp256k1.PrivateKey, nbLeafs)
	fundKeys := make([][]byte, nbLeafs)
	fundHashes := make([][]byte, nbLeafs)

	fundNoncePrivs := make(map[[33]byte]*secp256k1.PrivateKey, nbLeafs)
	fundNonceKeys := make([][]byte, nbLeafs)
	fundNonceHashes := make([][]byte, nbLeafs)

	triplets := []struct {
		privs  map[[33]byte]*secp256k1.PrivateKey
		keys   [][]byte
		hashes [][]byte
		useIV  bool
	}{
		{userPrivs, userKeys, userHashes, true},
		{sellPrivs, sellKeys, sellHashes, true},
		{fundPrivs, fundKeys, fundHashes, true},
		{fundNoncePrivs, fundNonceKeys, fundNonceHashes, false},
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

	return &TestUser{
		t:       t,
		rnd:     rnd,
		Name:    name,
		UserIVs: userIVs,

		KeysPrivs:  userPrivs,
		Keys:       userKeys,
		KeysHashes: userHashes,

		SellPrivs:  sellPrivs,
		Sell:       sellKeys,
		SellHashes: sellHashes,

		FundPrivs:  fundPrivs,
		Fund:       fundKeys,
		FundHashes: fundHashes,

		FundNoncesPrivs:  fundNoncePrivs,
		FundNonces:       fundNonceKeys,
		FundNoncesHashes: fundNonceHashes,
	}
}
