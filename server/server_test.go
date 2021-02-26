package server

import (
	"context"
	"fmt"
	"math/rand"
	"testing"

	"decred.org/mrttree"
	"decred.org/mrttree/api"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/txscript/v3"
	"github.com/decred/dcrd/wire"
)

const (
	defaultFeeRate dcrutil.Amount = 1e4
	coin           int64          = 1e8
)

var (
	dummyPkScript  = []byte{0x76, 0xa9, 0x14, 23: 0x88, 24: 0xac}
	testChangePriv = secp256k1.PrivKeyFromBytes([]byte{0x01, 0x02, 0x03, 0x04})
	testChangePub  = testChangePriv.PubKey()

	/*
		providerKey     = secp256k1.PrivKeyFromBytes([]byte{providerKeyInt}).PubKey()
		providerSellKey = secp256k1.PrivKeyFromBytes([]byte{providerSellKeyInt}).PubKey()
		userKey         = secp256k1.PrivKeyFromBytes([]byte{userKeyInt}).PubKey()
		userSellKey     = secp256k1.PrivKeyFromBytes([]byte{userSellKeyInt}).PubKey()

		simnetParams          = chaincfg.SimNetParams()
		opTrueScript          = []byte{txscript.OP_TRUE}
		opTrueRedeemScript    = []byte{txscript.OP_DATA_1, txscript.OP_TRUE}
		opTrueP2SHAddr, _     = dcrutil.NewAddressScriptHash(opTrueScript, simnetParams)
		opTrueP2SHPkScript, _ = txscript.PayToAddrScript(opTrueP2SHAddr)
	*/
)

func testCfg() *Config {
	outp := wire.OutPoint{Hash: chainhash.Hash{0: 0x01}}
	return &Config{
		ChangeKeySourcer: func(ctx context.Context) (*secp256k1.PublicKey, error) {
			return testChangePub, nil
		},
		InputSourcer: func(ctx context.Context, amount dcrutil.Amount) ([]*wire.TxIn, error) {
			in := wire.NewTxIn(&outp, int64(amount*2), nil)
			return []*wire.TxIn{in}, nil
		},
		InputReleaser: func(ctx context.Context, inputs []*wire.TxIn) error {
			return nil
		},
		TxFeeRate: defaultFeeRate,
		Rand:      rand.New(rand.NewSource(0x81234567)),
	}
}

func buildTree(t *testing.T, joinRes *api.JoinSessionResponse, keysRes *api.RevealLeafKeysResponse) *mrttree.Tree {
	nbLeafs := len(joinRes.UserPkHashes)
	leafs := make([]mrttree.ProposedLeaf, nbLeafs)
	for i := 0; i < nbLeafs; i++ {
		userKey, err := secp256k1.ParsePubKey(keysRes.UserKeys[i])
		if err != nil {
			t.Fatal(err)
		}
		sellKey, err := secp256k1.ParsePubKey(keysRes.UserSellableKeys[i])
		if err != nil {
			t.Fatal(err)
		}
		providerKey, err := secp256k1.ParsePubKey(keysRes.ProviderKeys[i])
		if err != nil {
			t.Fatal(err)
		}
		fundKey, err := secp256k1.ParsePubKey(keysRes.FundKeys[i])
		if err != nil {
			t.Fatal(err)
		}
		leafs[i] = mrttree.ProposedLeaf{
			Amount:              dcrutil.Amount(joinRes.LeafAmount),
			ProviderKey:         *providerKey,
			ProviderSellableKey: *providerKey,
			UserKey:             *userKey,
			UserSellableKey:     *sellKey,
			FundKey:             *fundKey,
		}
	}

	prefundInputs, err := unmarshalInputs(keysRes.PrefundInputs)
	if err != nil {
		t.Fatal(err)
	}

	changeKey, err := secp256k1.ParsePubKey(joinRes.ChangeKey)
	if err != nil {
		t.Fatal(err)
	}
	proposal := &mrttree.ProposedTree{
		Leafs:           leafs,
		LockTime:        joinRes.LockTime,
		InitialLockTime: joinRes.InitialLockTime,
		FundLockTime:    joinRes.FundLockTime,
		PrefundInputs:   prefundInputs,
		ChangeKey:       *changeKey,
		TxFeeRate:       dcrutil.Amount(joinRes.TxFeeRate),
	}

	tree, err := mrttree.BuildTree(proposal)
	if err != nil {
		t.Fatal(err)
	}

	return tree
}

func verifySignedNode(node *mrttree.Node, noncesRes *api.RevealNoncesResponse,
	sigsRes *api.SignedTreeResponse) error {

	var s secp256k1.ModNScalar
	s.SetByteSlice(sigsRes.TreeSignatures[node.Index])

	allNonces := noncesRes.TreeNonces[node.Index].Data
	R, err := mrttree.ProduceR(allNonces)
	if err != nil {
		return err
	}

	if err := node.AssembleLockedSigScript(R, &s); err != nil {
		return err
	}

	prevOut := node.PrevOutput
	vm, err := txscript.NewEngine(prevOut.PkScript, node.Tx, 0,
		testScriptFlags, prevOut.Version, nil)
	if err != nil {
		return err
	}
	err = vm.Execute()
	if err != nil {
		return err
	}

	return nil
}

func verifySignedFundTx(tree *mrttree.Tree, noncesRes *api.RevealNoncesResponse,
	sigsRes *api.SignedTreeResponse) error {

	var s secp256k1.ModNScalar
	s.SetByteSlice(sigsRes.FundSignature)

	R, err := mrttree.ProduceR(noncesRes.FundNonces)
	if err != nil {
		return err
	}

	if err := tree.AssembleLockedSigScript(R, &s); err != nil {
		return err
	}

	prevOut := tree.PrefundTx.TxOut[0]
	vm, err := txscript.NewEngine(prevOut.PkScript, tree.Tx, 0,
		testScriptFlags, prevOut.Version, nil)
	if err != nil {
		return err
	}
	err = vm.Execute()
	if err != nil {
		return err
	}

	return nil
}

func verifySignedTree(tree *mrttree.Tree, noncesRes *api.RevealNoncesResponse,
	sigsRes *api.SignedTreeResponse) error {

	nodes := make([]*mrttree.Node, 0)
	nodes = append(nodes, tree.Root)
	for len(nodes) > 0 {
		l := len(nodes)
		node := nodes[l-1]
		nodes = nodes[:l-1]
		if node.Leaf {
			continue
		}
		nodes = append(nodes, node.Children[:]...)

		if err := verifySignedNode(node, noncesRes, sigsRes); err != nil {
			return err
		}
	}

	if err := verifySignedFundTx(tree, noncesRes, sigsRes); err != nil {
		return fmt.Errorf("verifySignedFundTx failed: %v", err)
	}

	return nil
}

func TestBasicRoundtrip(t *testing.T) {
	cfg := testCfg()
	rnd := rand.New(rand.NewSource(0x12345678))

	svr, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	go svr.Run(testCtx(t))

	// Generate a new session.
	nbLeafs := 2
	lockTime := uint32(10)
	initialLockTime := lockTime * 3
	leafAmount := dcrutil.Amount(coin)
	providerPrivs := make(map[[33]byte]*secp256k1.PrivateKey, nbLeafs)
	providerKeys := make([]*secp256k1.PublicKey, nbLeafs)
	for i := 0; i < nbLeafs; i++ {
		var p [33]byte
		priv := randKey(rnd)
		copy(p[:], priv.PubKey().SerializeCompressed())
		providerKeys[i] = priv.PubKey()
		providerPrivs[p] = priv
	}

	_, sessID, err := svr.newSession(nbLeafs, leafAmount, lockTime,
		initialLockTime, providerKeys)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a test user.
	user := mrttree.NewTestUser(t, "user", 0x12345678, nbLeafs)

	// First: attempt to join a session, committing to keys.
	joinReq := &api.JoinSessionRequest{
		SessionId:            sessID[:],
		UserPkHashes:         user.KeysHashes,
		UserSellablePkHashes: user.SellHashes,
		FundPkHashes:         user.FundHashes,
	}
	joinRes, err := svr.JoinSession(testCtx(t), joinReq)
	if err != nil {
		t.Fatal(err)
	}

	// Second: Send keys.
	keysReq := &api.RevealLeafKeysRequest{
		SessionToken:     joinRes.SessionToken,
		UserKeys:         user.Keys,
		UserSellableKeys: user.Sell,
		FundKeys:         user.Fund,
		UserIvs:          user.UserIVs,
	}
	keysRes, err := svr.RevealLeafKeys(testCtx(t), keysReq)
	if err != nil {
		t.Fatal(err)
	}

	// After the last call returns, we have enough data to build the tree.
	// So do it to figure out where our leafs are.
	tree := buildTree(t, joinRes, keysRes)
	t.Logf("tree tx hash: %s", tree.Tx.TxHash())

	// Now generate enough nonces for the user to send on the next step.
	user.GenerateNonces(tree)

	// Third: Commit to nonces.
	nonceHashesReq := &api.CommitToNoncesRequest{
		SessionToken:    joinRes.SessionToken,
		TreeNonceHashes: marshalMapByteSlices(user.TreeNoncesHashes),
		FundNonceHashes: user.FundNoncesHashes,
	}
	nonceHashesRes, err := svr.CommitToNonces(testCtx(t), nonceHashesReq)
	if err != nil {
		t.Fatal(err)
	}

	// Fourth: Reveal nonces.
	noncesReq := &api.RevealNoncesRequest{
		SessionToken: joinRes.SessionToken,
		TreeNonces:   marshalMapByteSlices(user.TreeNonces),
		FundNonces:   user.FundNonces,
	}
	noncesRes, err := svr.RevealNonces(testCtx(t), noncesReq)
	if err != nil {
		t.Fatal(err)
	}

	// Partially sign tree and fund tx.
	allNonces := unmarshalMapByteSlices(noncesRes.TreeNonces)
	allFundNonces := noncesRes.FundNonces
	if err := user.SignTree(allNonces, allFundNonces); err != nil {
		t.Fatal(err)
	}

	// Fifth: Send signatures to all users.
	sigsReq := &api.SignedTreeRequest{
		SessionToken:   joinRes.SessionToken,
		TreeSignatures: marshalMapByteSlices(user.TreeSigs),
		FundSignatures: user.FundSigs,
	}
	sigsRes, err := svr.SignedTree(testCtx(t), sigsReq)
	if err != nil {
		t.Fatal(err)
	}

	// Fill in every sig in the tree and verify it's correct.
	if err := verifySignedTree(tree, noncesRes, sigsRes); err != nil {
		t.Fatal(err)
	}

	_ = sigsRes
	_ = nonceHashesRes
}
