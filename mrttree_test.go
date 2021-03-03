package mrttree

import (
	"os"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/crypto/blake256"
	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/txscript/v3"
	"github.com/decred/dcrd/wire"
	"github.com/decred/slog"
)

const (
	providerKeyInt     byte = 1
	providerSellKeyInt      = 2
	userKeyInt              = 3
	userSellKeyInt          = 4
	fundKeyInt              = 5

	defaultFeeRate dcrutil.Amount = 1e4
	coin           int64          = 1e8
)

var (
	dummyPkScript   = []byte{0x76, 0xa9, 0x14, 23: 0x88, 24: 0xac}
	providerKey     = secp256k1.PrivKeyFromBytes([]byte{providerKeyInt}).PubKey()
	providerSellKey = secp256k1.PrivKeyFromBytes([]byte{providerSellKeyInt}).PubKey()
	userKey         = secp256k1.PrivKeyFromBytes([]byte{userKeyInt}).PubKey()
	userSellKey     = secp256k1.PrivKeyFromBytes([]byte{userSellKeyInt}).PubKey()
	fundKey         = secp256k1.PrivKeyFromBytes([]byte{fundKeyInt}).PubKey()

	simnetParams          = chaincfg.SimNetParams()
	opTrueScript          = []byte{txscript.OP_TRUE}
	opTrueRedeemScript    = []byte{txscript.OP_DATA_1, txscript.OP_TRUE}
	opTrueP2SHAddr, _     = dcrutil.NewAddressScriptHash(opTrueScript, simnetParams)
	opTrueP2SHPkScript, _ = txscript.PayToAddrScript(opTrueP2SHAddr)

	testScriptFlags = txscript.ScriptDiscourageUpgradableNops |
		txscript.ScriptVerifyCheckLockTimeVerify |
		txscript.ScriptVerifyCheckSequenceVerify |
		txscript.ScriptVerifyCleanStack |
		txscript.ScriptVerifySigPushOnly |
		txscript.ScriptVerifySHA256 |
		txscript.ScriptVerifyTreasury
)

func debugTree(t *testing.T, tree *Tree) {
	root := tree.Root

	stack := make([]*Node, 0)
	push := func(n *Node) {
		stack = append(stack, n)
	}
	pop := func() (n *Node) {
		n, stack = stack[len(stack)-1], stack[:len(stack)-1]
		return n
	}

	_ = spew.Sdump("")
	//t.Logf("fund tx: %s", spew.Sdump(tree.Tx))

	print := func(n *Node) {
		lockedKey, _, err := n.ScriptKeys()
		if err != nil {
			t.Fatal(err)
		}
		prefix := strings.Repeat("    ", int(n.Level))
		t.Logf("%s lvl %d (idx %d) - %s pk %x", prefix, n.Level,
			n.Index, n.Amount, lockedKey.SerializeCompressed())
		//t.Logf("tx: %s", spew.Sdump(n.Tx))
	}

	push(root)
	for len(stack) > 0 {
		n := pop()
		print(n)
		if n.Children[0] != nil {
			push(n.Children[1])
			push(n.Children[0])
		}
	}
}

type redeemBranch int

const (
	redeemBranchImmediate redeemBranch = iota
	redeemBranchLocked
)

func genGroupMuSigPrivKey(nb int, keys ...byte) *secp256k1.PrivateKey {
	// Generate the individual pub keys.
	pubKeys := make([]*secp256k1.PublicKey, len(keys))
	pubSerKeys := make([][]byte, len(keys))
	for i, key := range keys {
		privKey := secp256k1.PrivKeyFromBytes([]byte{byte(key)})
		pubKeys[i] = privKey.PubKey()
		pubSerKeys[i] = pubKeys[i].SerializeCompressed()
	}

	// Generate L.
	hasher := blake256.New()
	for i := 0; i < nb; i++ {
		for _, key := range pubSerKeys {
			hasher.Write(key)
		}
	}
	var L chainhash.Hash
	copy(L[:], hasher.Sum(nil))

	// Accumulate the group key.
	var tweakModN, groupPriv secp256k1.ModNScalar
	var buff [32 + 33]byte
	copy(buff[:32], L[:])

	for i := 0; i < nb; i++ {
		for j := 0; j < len(keys); j++ {
			copy(buff[32:], pubSerKeys[j])
			tweak := blake256.Sum256(buff[:])

			// TODO: bounds check tweak (== 0, >= q)
			tweakModN.SetBytes(&tweak)

			var priv secp256k1.ModNScalar
			groupPriv.Add(priv.SetInt(uint32(keys[j])).Mul(&tweakModN))
		}
	}

	return secp256k1.NewPrivateKey(&groupPriv)
}

func signFundTx(t *testing.T, tree *Tree) {
	nbKeys := len(tree.Leafs)
	privKey := genGroupMuSigPrivKey(nbKeys, fundKeyInt)
	pubKey := privKey.PubKey()

	prevPkScript := tree.PrefundTx.TxOut[0].PkScript
	redeemScript, err := fundScript(pubKey, &tree.ChangeKey, tree.FundLockTime)
	if err != nil {
		t.Fatal(err)
	}

	rawSig, err := txscript.RawTxInSignature(tree.Tx, 0, redeemScript,
		txscript.SigHashAll, privKey.Serialize(),
		dcrec.STSchnorrSecp256k1)
	if err != nil {
		t.Fatal(err)
	}

	bldr := txscript.NewScriptBuilder()
	bldr.AddData(rawSig).AddData(pubKey.SerializeCompressed()).AddData(redeemScript)
	sigScript, err := bldr.Script()
	if err != nil {
		t.Fatal(err)
	}

	tree.Tx.TxIn[0].SignatureScript = sigScript

	bknd := slog.NewBackend(os.Stdout)
	logg := bknd.Logger("XXXX")
	//logg.SetLevel(slog.LevelTrace)
	txscript.UseLogger(logg)

	// Now verify.
	vm, err := txscript.NewEngine(prevPkScript, tree.Tx, 0, testScriptFlags, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = vm.Execute()
	if err != nil {
		t.Fatal(err)
	}
}

func signNode(t *testing.T, node *Node, redeemBranch redeemBranch) {
	// Determine how many copies of the test key are needed to sign at this
	// level.
	nbKeys := node.LeafCount

	// Test private keys are simple ints, so just figure out which redeem
	// branch is being used and multiply by the nb of keys.
	//
	// Additionally, if signing a non-default branch, adjust the outputs
	// and sequence. Recall that only the provider can unilaterally sign
	// the non-default branches, either by waiting for the LongTimelock or
	// by having purchased all UserSellableKeys.
	var (
		keys []byte
	)
	switch redeemBranch {
	case redeemBranchImmediate:
		// userKey
		keys = []byte{providerKeyInt, userSellKeyInt}
		node.Tx.TxIn[0].Sequence = 0
		node.Tx.TxOut = node.Tx.TxOut[:1]
		node.Tx.TxOut[0].PkScript = dummyPkScript

	case redeemBranchLocked:
		// userKey
		keys = []byte{userKeyInt}

		// When signing leaf nodes (which naturally only have a single output) fill in
		// the dummy pkscript as output script.
		if len(node.Tx.TxOut) == 1 {
			node.Tx.TxOut[0].PkScript = dummyPkScript
		}
	}

	prevPkScript := node.Tree.Tx.TxOut[0].PkScript
	if node.Level > 0 {
		prevPkScript = node.Parent.Tx.TxOut[node.ParentIndex].PkScript
	}

	redeemScript, err := node.RedeemScript()
	if err != nil {
		t.Fatal(err)
	}

	privKey := genGroupMuSigPrivKey(nbKeys, keys...)
	pubKeyData := privKey.PubKey().SerializeCompressed()

	rawSig, err := txscript.RawTxInSignature(node.Tx, 0, redeemScript,
		txscript.SigHashAll, privKey.Serialize(),
		dcrec.STSchnorrSecp256k1)
	if err != nil {
		t.Fatal(err)
	}

	bldr := txscript.NewScriptBuilder()
	bldr.AddData(rawSig).AddData(pubKeyData).AddData(redeemScript)
	sigScript, err := bldr.Script()
	if err != nil {
		t.Fatal(err)
	}

	node.Tx.TxIn[0].SignatureScript = sigScript

	bknd := slog.NewBackend(os.Stdout)
	logg := bknd.Logger("XXXX")
	//logg.SetLevel(slog.LevelTrace)
	txscript.UseLogger(logg)

	t.Logf("XXXXX %x", redeemScript)

	// Now verify.
	vm, err := txscript.NewEngine(prevPkScript, node.Tx, 0, testScriptFlags, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = vm.Execute()
	if err != nil {
		t.Fatal(err)
	}
}

func signSubtree(t *testing.T, node *Node, redeemBranch redeemBranch) {
	signNode(t, node, redeemBranch)
	if node.Children[0] != nil {
		signSubtree(t, node.Children[0], redeemBranch)
		signSubtree(t, node.Children[1], redeemBranch)
	}
}

func TestNodeFees(t *testing.T) {
	feeRate := dcrutil.Amount(1e4)
	nodeFeeRate := calcNodeTxFee(feeRate)
	leafFeeRate := calcLeafRedeemTxFee(feeRate)
	t.Logf("XXXXX node fee %s", dcrutil.Amount(nodeFeeRate))
	t.Logf("XXXXX leaf fee %s", dcrutil.Amount(leafFeeRate))
}

func TestBuildTree(t *testing.T) {
	leafs := make([]ProposedLeaf, 8)

	/*
		for i := 0; i < 36; i++ {
			pk := secp256k1.PrivKeyFromBytes([]byte{byte(i)}).PubKey()
			t.Logf("pk %d - %x", i, pk.SerializeCompressed())
		}
	*/

	for i := 0; i < len(leafs); i++ {
		leafs[i] = ProposedLeaf{
			Amount:              1e8,
			ProviderKey:         *providerKey,
			ProviderSellableKey: *providerSellKey,
			UserKey:             *userKey,
			UserSellableKey:     *userSellKey,
		}
	}
	proposal := &ProposedTree{
		PrefundInputs: []*wire.TxIn{
			{ValueIn: 100e8},
		},
		Leafs:           leafs,
		LockTime:        10,
		InitialLockTime: 1000,
	}

	tree, err := BuildTree(proposal)
	if err != nil {
		t.Fatal(err)
	}
	debugTree(t, tree)
	signSubtree(t, tree.Root, redeemBranchLocked)
}
