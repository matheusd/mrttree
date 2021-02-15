package mrttree

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/rpcclient/v6"
	"github.com/decred/dcrd/rpctest"
	"github.com/decred/dcrd/wire"
	"github.com/stretchr/testify/require"
)

// defaultTimeout is the default timeout for test contexts.
const defaultTimeout = time.Second * 30

// timeoutCtx returns a context that gets canceled after the specified time or
// after the test ends.
func timeoutCtx(t *testing.T, timeout time.Duration) context.Context {
	ctxt, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	return ctxt
}

// testCtx returns a context that gets canceled after defaultTimeout or after
// the test ends.
func testCtx(t *testing.T) context.Context {
	return timeoutCtx(t, defaultTimeout)
}

// rpctestHarness generates an rpctest harness used for tests.
func rpctestHarness(t *testing.T, net *chaincfg.Params, name string) *rpctest.Harness {
	var handlers *rpcclient.NotificationHandlers

	// Setup the log dir for tests to ease debugging after failures.
	testDir := strings.ReplaceAll(t.Name(), "/", "_")
	logDir := filepath.Join(".dcrdlogs", testDir, name)
	extraArgs := []string{
		"--debuglevel=debug",
		"--rejectnonstd",
		"--logdir=" + logDir,
	}
	info, err := os.Stat(logDir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("error stating log dir: %v", err)
	}
	if info != nil {
		if !info.IsDir() {
			t.Fatalf("logdir (%s) is not a dir", logDir)
		}
		err = os.RemoveAll(logDir)
		if err != nil {
			t.Fatalf("error removing logdir: %v", err)
		}
	}

	// Create the rpctest harness and mine outputs for the voting wallet to
	// use.
	hn, err := rpctest.New(t, net, handlers, extraArgs)
	if err != nil {
		t.Fatal(err)
	}
	err = hn.SetUp(false, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hn.TearDown() })
	return hn
}

// rpctestHarnessAndVW generates a new rpctest harness node and voting wallet
// for rpctest-based tests.
//
// name is used to disambiguate when multiple harnesses are used in the same
// test.
func rpctestHarnessAndVW(t *testing.T, net *chaincfg.Params, name string) (*rpctest.Harness, *rpctest.VotingWallet) {
	hn := rpctestHarness(t, net, name)

	// Generate funds for the voting wallet.
	_, err := rpctest.AdjustedSimnetMiner(testCtx(t), hn.Node, 64)
	if err != nil {
		t.Fatal(err)
	}

	// Create the voting wallet.
	vw, err := rpctest.NewVotingWallet(context.Background(), hn)
	if err != nil {
		t.Fatalf("unable to create voting wallet for test: %v", err)
	}
	err = vw.Start()
	if err != nil {
		t.Fatalf("unable to setup voting wallet: %v", err)
	}
	vw.SetErrorReporting(func(vwerr error) {
		t.Fatalf("voting wallet errored: %v", vwerr)
	})
	vw.SetMiner(func(ctx context.Context, nb uint32) ([]*chainhash.Hash, error) {
		return rpctest.AdjustedSimnetMiner(ctx, hn.Node, nb)
	})

	return hn, vw
}

func TestRpcTest(t *testing.T) {
	net := chaincfg.SimNetParams()
	hn, vw := rpctestHarnessAndVW(t, net, "main")

	mine := func(nb uint32) []*chainhash.Hash {
		t.Helper()
		res, err := vw.GenerateBlocks(testCtx(t), nb)
		require.NoError(t, err)
		return res
	}
	assertMined := func(txh *chainhash.Hash) {
		t.Helper()
		res, err := hn.Node.GetRawTransactionVerbose(testCtx(t), txh)
		require.NoError(t, err)
		if res.BlockHash == "" {
			t.Fatalf("tx %s was not mined", txh)
		}
	}
	sendTx := func(tx *wire.MsgTx) *chainhash.Hash {
		t.Helper()
		txh, err := hn.Node.SendRawTransaction(testCtx(t), tx, true)
		require.NoError(t, err)
		return txh
	}
	assertSendTxFailsSeqLock := func(tx *wire.MsgTx) {
		t.Helper()
		txh, err := hn.Node.SendRawTransaction(testCtx(t), tx, true)
		if err == nil {
			t.Fatalf("expected error but tx %s was published", txh)
		}
		if !strings.Contains(err.Error(), "sequence locks on inputs not met") {
			t.Fatalf("expected seq locks not met error, instead got %v", err)
		}
	}

	const nbLeafs = 4

	// Create the output to fund the mrttree funding tx.
	inputAmount := coin * nbLeafs * 2 // * to add enough for tx fees.
	targetOut := wire.NewTxOut(inputAmount, opTrueP2SHPkScript)
	inputTx, err := hn.SendOutputs([]*wire.TxOut{targetOut}, defaultFeeRate)
	require.NoError(t, err)
	mine(2)
	treeInputOutp := wire.NewOutPoint(inputTx, 0, 0)
	treeInputs := []*wire.TxIn{wire.NewTxIn(treeInputOutp, inputAmount, opTrueRedeemScript)}

	leafs := make([]ProposedLeaf, nbLeafs)
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
		Leafs:           leafs,
		LongLockTime:    7,
		MediumLockTime:  5,
		ShortLockTime:   3,
		InitialLockTime: 10,
		ChangeScript:    opTrueP2SHPkScript,
		Inputs:          treeInputs,
		TxFeeRate:       defaultFeeRate,
	}

	tree, err := BuildTree(proposal)
	if err != nil {
		t.Fatal(err)
	}
	debugTree(t, tree)
	signSubtree(t, tree.Root, redeemBranchMediumLockTime)

	// Publish and mine the funding tx.
	fundingTxh := sendTx(tree.Tx)
	mine(1)
	assertMined(fundingTxh)
	t.Logf("Mined funding tx %s", fundingTxh)

	// Attempt to mine each tx. Each level of the tree can only be
	// published after the seqlock expires, so attempt to publish at every
	// height, assert it is not in fact published, then assert it can be
	// published after it expires.
	nodes := []*Node{tree.Root}
	txs := []*wire.MsgTx{tree.Root.Tx}
	for len(txs) != 0 {
		locktime := txs[0].TxIn[0].Sequence

		// Mine until just before the locktime expires and assert the
		// tx can't be published.
		for i := uint32(0); i < locktime-1; i++ {
			for _, tx := range txs {
				assertSendTxFailsSeqLock(tx)
			}
			mine(1)
		}

		// Assert all txs can now be published after the seqlock
		// expires.
		for _, tx := range txs {
			sendTx(tx)
		}
		mine(1)
		for _, tx := range txs {
			assertMined(tx.CachedTxHash())
			t.Logf("mined level %d tx %s", nodes[0].Level, tx.CachedTxHash())
		}

		// Pass on to the next level.
		newNodes := make([]*Node, 0, len(nodes)*2)
		txs = txs[:0]
		for _, n := range nodes {
			if n.Children[0] == nil {
				continue
			}
			newNodes = append(newNodes, n.Children[0])
			newNodes = append(newNodes, n.Children[1])
			txs = append(txs, n.Children[0].Tx)
			txs = append(txs, n.Children[1].Tx)
		}
		nodes = newNodes
	}

}
