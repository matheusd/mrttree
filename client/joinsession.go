package client

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"decred.org/mrttree"
	"decred.org/mrttree/api"
	"github.com/decred/dcrlnd/lnrpc"
	"github.com/decred/dcrlnd/lnrpc/walletrpc"
	"google.golang.org/grpc"
)

type LNAdapter interface {
	SendPaymentSync(ctx context.Context, in *lnrpc.SendRequest, opts ...grpc.CallOption) (*lnrpc.SendResponse, error)
	PublishTransaction(ctx context.Context, in *walletrpc.Transaction, opts ...grpc.CallOption) (*walletrpc.PublishResponse, error)
	AddInvoice(ctx context.Context, in *lnrpc.Invoice, opts ...grpc.CallOption) (*lnrpc.AddInvoiceResponse, error)
}

type JoinSessionCfg struct {
	APIClient api.MrttreeClient
	LNClient  LNAdapter
	SessionID []byte
	SampleDir string
}

type jsClient struct {
	api.MrttreeClient

	cfg *JoinSessionCfg
}

func (c *jsClient) run(ctx context.Context) error {

	seed := time.Now().Unix()
	user := mrttree.NewTestUser(nil, "user", seed, 8)

	// First: attempt to join a session, committing to keys.
	joinReq := &api.JoinSessionRequest{
		SessionId:    c.cfg.SessionID,
		UserPkHashes: user.KeysHashes,
	}
	joinRes, err := c.JoinSession(ctx, joinReq)
	if err != nil {
		return errorf(ErrJoinSession, "unable to join session: %v", err)
	}

	log.Infof("Joined session %x token %x", joinReq.SessionId, joinRes.SessionToken)

	// Second: Send keys.
	keysReq := &api.RevealLeafKeysRequest{
		SessionToken: joinRes.SessionToken,
		UserKeys:     user.Keys,
		UserIvs:      user.UserIVs,
	}
	keysRes, err := c.RevealLeafKeys(ctx, keysReq)
	if err != nil {
		return errorf(ErrJoinSession, "unable to reveal keys: %v", err)
	}

	tree, err := buildTree(joinRes, keysRes)
	if err != nil {
		return errorf(ErrJoinSession, "unable to build tree: %v", err)
	}
	log.Infof("tree tx hash: %s", tree.Tx.TxHash())

	// Now generate enough nonces for the user to send on the next step.
	if err := user.GenerateNonces(tree); err != nil {
		return errorf(ErrJoinSession, "unable to generate nonces: %v", err)
	}

	// Third: Commit to nonces.
	nonceHashesReq := &api.CommitToNoncesRequest{
		SessionToken:    joinRes.SessionToken,
		TreeNonceHashes: api.MarshalMapByteSlices(user.TreeNoncesHashes),
		FundNonceHashes: user.FundNoncesHashes,
	}
	nonceHashesRes, err := c.CommitToNonces(ctx, nonceHashesReq)
	if err != nil {
		return errorf(ErrJoinSession, "unable to commit to nonces: %v", err)
	}

	// Fourth: Reveal nonces.
	noncesReq := &api.RevealNoncesRequest{
		SessionToken: joinRes.SessionToken,
		TreeNonces:   api.MarshalMapByteSlices(user.TreeNonces),
		FundNonces:   user.FundNonces,
	}
	noncesRes, err := c.RevealNonces(ctx, noncesReq)
	if err != nil {
		return errorf(ErrJoinSession, "unable to reveal nonces: %v", err)
	}

	// TODO: Verify received nonces.
	_ = nonceHashesRes

	// Partially sign tree and fund tx.
	allNonces := api.UnmarshalMapByteSlices(noncesRes.TreeNonces)
	allFundNonces := noncesRes.FundNonces
	if err := user.SignTree(allNonces, allFundNonces); err != nil {
		return errorf(ErrJoinSession, "unable to sign tree: %v", err)
	}

	// Fifth: Send signatures to all users.
	sigsReq := &api.SignedTreeRequest{
		SessionToken:   joinRes.SessionToken,
		TreeSignatures: api.MarshalMapByteSlices(user.TreeSigs),
		FundSignatures: user.FundSigs,
	}
	sigsRes, err := c.SignedTree(ctx, sigsReq)
	if err != nil {
		return errorf(ErrJoinSession, "unable to send signatures: %v", err)
	}

	// Fill in every sig in the tree and verify it's correct.
	if err := verifySignedTree(tree, noncesRes, sigsRes); err != nil {
		return errorf(ErrJoinSession, "sig verification failed: %v", err)
	}

	// TODO: Ensure the payment request is bound to the correct payment
	// point.

	log.Infof("Payment request: %s", sigsRes.LnPayReq)
	log.Infof("Payment Point: %x", sigsRes.FundSignaturePub)

	// TODO: Wait for prefund tx to be broadcast and confirmed deep enough.

	// Pay for the fund tx signature.
	sendPayReq := &lnrpc.SendRequest{
		PaymentRequest: sigsRes.LnPayReq,
	}
	sendPayRes, err := c.cfg.LNClient.SendPaymentSync(ctx, sendPayReq)
	if err != nil {
		return errorf(ErrJoinSession, "unable to pay ln invoice: %v", err)
	}
	if sendPayRes.PaymentError != "" {
		return errorf(ErrJoinSession, "payment error: %s", sendPayRes.PaymentError)
	}
	log.Infof("Final fund sig: %x", sendPayRes.PaymentPreimage)

	// Fill in the funding sig.
	if err := fillFundSig(tree, noncesRes, sendPayRes.PaymentPreimage); err != nil {
		return errorf(ErrJoinSession, "unable to fill fund sig: %v", err)
	}

	// The three has been atomically paid for! Publish the fund tx.
	rawtx, err := tree.Tx.Bytes()
	if err != nil {
		return err
	}
	req := &walletrpc.Transaction{
		TxHex: rawtx,
	}
	res, err := c.cfg.LNClient.PublishTransaction(ctx, req)
	if err != nil {
		return err
	}
	if res.PublishError != "" {
		return fmt.Errorf("publish error: %s", res.PublishError)
	}
	log.Infof("Published fund tx %s", tree.Tx.TxHash())
	log.Infof("Sample dir: %s", c.cfg.SampleDir)

	// Show every leaf key that can be sent to a remote party for payment.
	allPubs := make([][33]byte, 0, len(user.KeysPrivs))
	for pub, priv := range user.KeysPrivs {
		allPubs = append(allPubs, pub)
		log.Infof("Key %x (pub %x)", priv.Serialize(), pub[:])
	}

	// (Sample only) save session token to file.
	sessTokenHex := fmt.Sprintf("%x", joinRes.SessionToken)
	ioutil.WriteFile(filepath.Join(c.cfg.SampleDir, "user-session"), []byte(sessTokenHex), 0644)

	// (Sample only) Write all but the first key to a file to ease
	// redeeming the tree on the server.
	var keysFile string
	for _, pub := range allPubs[0:] {
		priv := user.KeysPrivs[pub]
		keysFile += fmt.Sprintf("%x\n", priv.Serialize())
	}
	ioutil.WriteFile(filepath.Join(c.cfg.SampleDir, "user-keys"), []byte(keysFile), 0644)

	// (Sample only) Write all node txs to a file.
	txsFile, err := os.Create(filepath.Join(c.cfg.SampleDir, "user-txs"))
	stack := make([]*mrttree.Node, 0)
	stack = append(stack, tree.Root)
	for len(stack) > 0 {
		l := len(stack)
		node := stack[l-1]
		stack = stack[:l-1]
		if node.Leaf {
			continue
		}

		stack = append(stack, node.Children[1])
		stack = append(stack, node.Children[0])
		rawTx, err := node.Tx.Bytes()
		if err != nil {
			log.Error(err)
			continue
		}
		rawTxHex := hex.EncodeToString(rawTx)
		txsFile.Write([]byte(rawTxHex))
		txsFile.Write([]byte("\n"))
	}
	if err := txsFile.Close(); err != nil {
		log.Error(err)
	}

	return nil
}

func JoinSession(ctx context.Context, cfg *JoinSessionCfg) error {
	c := &jsClient{
		cfg:           cfg,
		MrttreeClient: cfg.APIClient,
	}

	return c.run(ctx)
}
