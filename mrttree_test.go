package mrttree

import (
	"os"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg/v3"
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

	defaultFeeRate dcrutil.Amount = 1e4
	coin           int64          = 1e8
)

var (
	dummyPkScript   = []byte{0x76, 0xa9, 0x14, 23: 0x88, 24: 0xac}
	providerKey     = secp256k1.PrivKeyFromBytes([]byte{providerKeyInt}).PubKey()
	providerSellKey = secp256k1.PrivKeyFromBytes([]byte{providerSellKeyInt}).PubKey()
	userKey         = secp256k1.PrivKeyFromBytes([]byte{userKeyInt}).PubKey()
	userSellKey     = secp256k1.PrivKeyFromBytes([]byte{userSellKeyInt}).PubKey()

	simnetParams          = chaincfg.SimNetParams()
	opTrueScript          = []byte{txscript.OP_TRUE}
	opTrueRedeemScript    = []byte{txscript.OP_DATA_1, txscript.OP_TRUE}
	opTrueP2SHAddr, _     = dcrutil.NewAddressScriptHash(opTrueScript, simnetParams)
	opTrueP2SHPkScript, _ = txscript.PayToAddrScript(opTrueP2SHAddr)
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
		_, _, shortKey, _ := n.ScriptKeys()
		prefix := strings.Repeat("    ", int(n.Level))
		t.Logf("%s lvl %d (idx %d) - %s pk %x", prefix, n.Level,
			n.Index, n.Amount, shortKey.SerializeCompressed())
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
	redeemBranchShortLockTime
	redeemBranchMediumLockTime
	redeemBranchLongLockTime
)

func signNode(t *testing.T, node *Node, redeemBranch redeemBranch) {
	// Determine how many copies of the test key are needed to sign at this
	// level.
	nbKeys := 1 << (node.Tree.Levels - node.Level - 1)
	t.Logf("leaf count %d", node.LeafCount)
	t.Logf("nb keys: %d", nbKeys)
	nbKeys = node.LeafCount
	//nbKeys := node.ChildrenCount + 1

	// Test private keys are simple ints, so just figure out which redeem
	// branch is being used and multiply by the nb of keys.
	//
	// Additionally, if signing a non-default branch, adjust the outputs
	// and sequence. Recall that only the provider can unilaterally sign
	// the non-default branches, either by waiting for the LongTimelock or
	// by having purchased all UserSellableKeys.
	var (
		privKeyInt int
	)
	switch redeemBranch {
	case redeemBranchImmediate:
		// providerKey + userSellKey
		privKeyInt = int(providerKeyInt+userSellKeyInt) * nbKeys
		node.Tx.TxIn[0].Sequence = 0
		node.Tx.TxOut = node.Tx.TxOut[:1]
		node.Tx.TxOut[0].PkScript = dummyPkScript

	case redeemBranchMediumLockTime:
		// providerKey + userKey
		privKeyInt = int(providerKeyInt+userKeyInt) * nbKeys

		// When signing leaf nodes (which naturally only have a single output) fill in
		// the dummy pkscript as output script.
		if len(node.Tx.TxOut) == 1 {
			node.Tx.TxOut[0].PkScript = dummyPkScript
		}

	case redeemBranchShortLockTime:
		// providerSellKey + userKey
		privKeyInt = (providerSellKeyInt + userKeyInt) * nbKeys
		node.Tx.TxIn[0].Sequence = 0
		node.Tx.TxOut = node.Tx.TxOut[:1]
		node.Tx.TxOut[0].PkScript = dummyPkScript

	case redeemBranchLongLockTime:
		// providerKey
		privKeyInt = int(providerKeyInt) * nbKeys
		node.Tx.TxIn[0].Sequence = node.Tree.LongLockTime
		node.Tx.TxOut = node.Tx.TxOut[:1]
		node.Tx.TxOut[0].PkScript = dummyPkScript
	}

	prevPkScript := node.Tree.Tx.TxOut[0].PkScript
	if node.Level > 0 {
		prevPkScript = node.Parent.Tx.TxOut[node.ParentIndex].PkScript
	}

	redeemScript, err := node.RedeemScript()
	if err != nil {
		t.Fatal(err)
	}

	privKey := secp256k1.PrivKeyFromBytes([]byte{byte(privKeyInt)})
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
	scriptFlags := txscript.ScriptDiscourageUpgradableNops |
		txscript.ScriptVerifyCheckLockTimeVerify |
		txscript.ScriptVerifyCheckSequenceVerify |
		txscript.ScriptVerifyCleanStack |
		txscript.ScriptVerifySigPushOnly |
		txscript.ScriptVerifySHA256 |
		txscript.ScriptVerifyTreasury
	vm, err := txscript.NewEngine(prevPkScript, node.Tx, 0, scriptFlags, 0, nil)
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
	leafs := make([]ProposedLeaf, 9)

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
		Inputs: []*wire.TxIn{
			{ValueIn: 100e8},
		},
		Leafs:           leafs,
		LongLockTime:    100,
		MediumLockTime:  10,
		ShortLockTime:   1,
		InitialLockTime: 1000,
	}

	tree, err := BuildTree(proposal)
	if err != nil {
		t.Fatal(err)
	}
	debugTree(t, tree)
	signSubtree(t, tree.Root, redeemBranchMediumLockTime)
}
