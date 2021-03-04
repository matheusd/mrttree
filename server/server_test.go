package server

import (
	"context"
	"math/rand"
	"testing"

	"decred.org/mrttree"
	"decred.org/mrttree/api"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/wire"
)

const (
	defaultFeeRate dcrutil.Amount = 1e4
	coin           int64          = 1e8
)

var (
	testChangePriv = secp256k1.PrivKeyFromBytes([]byte{0x01, 0x02, 0x03, 0x04})
	testChangePub  = testChangePriv.PubKey()
)

func testCfg(t *testing.T, nbLeafs int) *Config {
	outp := wire.OutPoint{Hash: chainhash.Hash{0: 0x01}}

	// Handle the provider as if it were another user.
	user := mrttree.NewTestUser(t, "provider", 0x99123192, nbLeafs)
	return &Config{
		ChangeKeySourcer: func(ctx context.Context) (*secp256k1.PublicKey, error) {
			return testChangePub, nil
		},

		TreeKeySourcer: func(ctx context.Context, nbLeafs int) ([]*secp256k1.PublicKey, error) {
			keys := make([]*secp256k1.PublicKey, nbLeafs)
			for i := range keys {
				keys[i], _ = secp256k1.ParsePubKey(user.Keys[i])
			}
			return keys, nil
		},

		TreeNoncer: func(ctx context.Context, tree *mrttree.Tree) (map[uint32][][]byte, [][]byte, error) {
			err := user.GenerateNonces(tree)
			return user.TreeNonces, user.FundNonces, err
		},

		TreeSigner: func(ctx context.Context, tree *mrttree.Tree, allNonces map[uint32][][]byte, allFundNonces [][]byte) (map[uint32][][]byte, [][]byte, error) {
			err := user.SignTree(allNonces, allFundNonces)
			return user.TreeSigs, user.FundSigs, err
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
		providerKey, err := secp256k1.ParsePubKey(keysRes.ProviderKeys[i])
		if err != nil {
			t.Fatal(err)
		}
		leafs[i] = mrttree.ProposedLeaf{
			Amount:      dcrutil.Amount(joinRes.LeafAmount),
			ProviderKey: *providerKey,
			UserKey:     *userKey,
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

func verifySignedTree(tree *mrttree.Tree, noncesRes *api.RevealNoncesResponse,
	sigsRes *api.SignedTreeResponse) error {

	treeNonces := unmarshalMapByteSlices(noncesRes.TreeNonces)
	err := tree.FillTxSignatures(treeNonces, sigsRes.TreeSignatures,
		noncesRes.FundNonces, sigsRes.FundSignature)
	if err != nil {
		return err
	}

	return tree.VerifyTxSignatures()
}

func TestBasicRoundtrip(t *testing.T) {
	nbLeafs := 2
	cfg := testCfg(t, nbLeafs)

	svr, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	go svr.Run(testCtx(t))

	// Generate a new session.
	lockTime := uint32(10)
	initialLockTime := lockTime * 3
	leafAmount := dcrutil.Amount(coin)

	_, sessID, err := svr.newSession(nbLeafs, leafAmount, lockTime,
		initialLockTime)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a test user.
	user := mrttree.NewTestUser(t, "user", 0x12345678, nbLeafs)

	// First: attempt to join a session, committing to keys.
	joinReq := &api.JoinSessionRequest{
		SessionId:    sessID[:],
		UserPkHashes: user.KeysHashes,
	}
	joinRes, err := svr.JoinSession(testCtx(t), joinReq)
	if err != nil {
		t.Fatal(err)
	}

	// Second: Send keys.
	keysReq := &api.RevealLeafKeysRequest{
		SessionToken: joinRes.SessionToken,
		UserKeys:     user.Keys,
		UserIvs:      user.UserIVs,
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
	if err := user.GenerateNonces(tree); err != nil {
		t.Fatal(err)
	}

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

	_ = nonceHashesRes
}
