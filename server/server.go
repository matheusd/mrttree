package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"

	"decred.org/mrttree"
	"decred.org/mrttree/api"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrlnd/lnrpc"
	"google.golang.org/grpc"
)

type LNAdapter interface {
	AddInvoice(ctx context.Context, in *lnrpc.Invoice, opts ...grpc.CallOption) (*lnrpc.AddInvoiceResponse, error)
	SendPaymentSync(ctx context.Context, in *lnrpc.SendRequest, opts ...grpc.CallOption) (*lnrpc.SendResponse, error)
}

type Config struct {
	ChangeKeySourcer func(ctx context.Context) (*secp256k1.PublicKey, error)
	TreeKeySourcer   func(ctx context.Context, nbLeafs int) ([]*secp256k1.PublicKey, error)
	TreeNoncer       func(ctx context.Context, tree *mrttree.Tree) (map[uint32][][]byte, [][]byte, error)
	TreeSigner       func(ctx context.Context, tree *mrttree.Tree, allNonces map[uint32][][]byte, allFundNonces [][]byte) (map[uint32][][]byte, [][]byte, error)
	TreeRedeemer     func(ctx context.Context, tree *mrttree.Tree, allUserKeys [][]byte) error
	InputSourcer     func(ctx context.Context, amount dcrutil.Amount) ([]*wire.TxIn, error)
	InputReleaser    func(ctx context.Context, inputs []*wire.TxIn) error
	PrefundSigner    func(ctx context.Context, prefundTx *wire.MsgTx) error
	TxPublisher      func(ctx context.Context, tx *wire.MsgTx) error
	TxFeeRate        dcrutil.Amount
	Rand             io.Reader
	LNClient         LNAdapter
}

func (cfg *Config) readRand(b []byte) error {
	n, err := cfg.Rand.Read(b[:])
	if err != nil {
		return fmt.Errorf("entropy failure: %w", err)
	}
	if n != len(b) {
		return fmt.Errorf("entroy failure: too few bytes read")
	}
	return nil
}

type Server struct {
	cfg *Config
	ctx context.Context

	mtx             sync.Mutex
	waitingSessions map[sessionID]*waitingSession
	sessions        sync.Map
}

var _ api.MrttreeServer = (*Server)(nil)

func (s *Server) newSession(nbLeafs int, leafAmount dcrutil.Amount, lockTime, initialLockTime uint32) (*session, sessionID, error) {
	providerKeys, err := s.cfg.TreeKeySourcer(s.ctx, nbLeafs)
	if err != nil {
		return nil, sessionID{}, err
	}
	providerPks := make([][]byte, nbLeafs)
	providerPkHashes := make([][]byte, nbLeafs)
	providerIvs := make([][]byte, nbLeafs)
	for i, key := range providerKeys {
		providerPks[i] = key.SerializeCompressed()
		providerIvs[i] = make([]byte, 16)
		if err := s.cfg.readRand(providerIvs[i]); err != nil {
			return nil, sessionID{}, err
		}
		providerPkHashes[i] = hashKeyIV(providerPks[i], providerIvs[i])
	}

	sess := &session{
		nbLeafs:             nbLeafs,
		leafAmount:          leafAmount,
		lockTime:            lockTime,
		initialLockTime:     initialLockTime,
		fundLockTime:        6, // TODO: parametrize?
		txFeeRate:           s.cfg.TxFeeRate,
		userSessions:        make(map[sessionToken]*userSession),
		allProviderPkHashes: providerPkHashes,
		allProviderKeys:     providerPks,
		allProviderIVs:      providerIvs,
		gotAllKeys:          make(chan struct{}),
		gotAllNonceHashes:   make(chan struct{}),
		gotAllNonces:        make(chan struct{}),
		gotAllSigs:          make(chan struct{}),
		failed:              make(chan struct{}),
	}
	ws := &waitingSession{
		session:     sess,
		enoughLeafs: make(chan struct{}),
	}

	var sessID sessionID
	s.mtx.Lock()
	for {
		if err := readRand(sessID[:]); err != nil {
			s.mtx.Unlock()
			return nil, sessionID{}, err
		}
		_, ok := s.waitingSessions[sessID]
		if !ok {
			sess.id = sessID
			s.waitingSessions[sessID] = ws
			break
		}
	}
	s.mtx.Unlock()
	return sess, sessID, nil
}

func (s *Server) NewSession(nbLeafs int, leafAmount dcrutil.Amount, lockTime, initialLockTime uint32) (sessionID, error) {
	_, id, err := s.newSession(nbLeafs, leafAmount, lockTime, initialLockTime)
	return id, err
}

func (s *Server) findSession(token sessionToken) (*session, error) {
	intf, ok := s.sessions.Load(token)
	if !ok {
		return nil, fmt.Errorf("session %x not found", token)
	}
	return intf.(*session), nil
}

func (s *Server) preStartSession(sess *session) error {
	changeKey, err := s.cfg.ChangeKeySourcer(s.ctx)
	if err != nil {
		sess.Unlock()
		return err
	}
	sess.changeKey = changeKey

	// Build the prefund tx to lock funds for off-chain users to purchase
	// their leafs.
	totalTxs := mrttree.CalcTreeTxs(sess.nbLeafs)
	nodeFee := mrttree.CalcNodeTxFee(sess.txFeeRate)
	fundFee := mrttree.CalcFundTxFee(sess.txFeeRate, 0)
	prefundFee := mrttree.CalcPrefundTxFee(sess.txFeeRate, 0)
	totalInputAmount := nodeFee*dcrutil.Amount(totalTxs) +
		dcrutil.Amount(sess.nbLeafs)*sess.leafAmount +
		fundFee + prefundFee

	// minus inputs from other participants that are contributing
	// on-chain.
	//
	// plus prefund tx fees.
	//
	// plus fund tx fees.

	inputs, err := s.cfg.InputSourcer(s.ctx, totalInputAmount)
	if err != nil {
		return err
	}
	sess.inputs = inputs

	return nil
}

// failSession asynchronously fails the given session and cleans up any left
// over.
func (s *Server) failSession(sess *session, err error) {
	go func() {
		sess.Lock()
		sess.failSession(err)
		inputs := sess.inputs

		for sessToken := range sess.userSessions {
			s.sessions.Delete(sessToken)
		}

		sess.Unlock()
		if inputs != nil {
			if err := s.cfg.InputReleaser(s.ctx, inputs); err != nil {
				svrLog.Errorf("Unable to release inputs: %v", err)
			}
		}
	}()
}

func (s *Server) publishPrefund(sess *session) {
	sess.Lock()
	prefundTx := sess.tree.PrefundTx
	sess.Unlock()

	err := s.cfg.PrefundSigner(s.ctx, prefundTx)
	if err != nil {
		svrLog.Errorf("Prefund signer failed: %v", err)
		s.failSession(sess, fmt.Errorf("unable to sign prefund tx: %v", err))
		return
	}

	err = s.cfg.TxPublisher(s.ctx, prefundTx)
	if err != nil {
		svrLog.Errorf("Tx publisher failed: %v", err)
		s.failSession(sess, fmt.Errorf("unable to publish prefund tx: %v", err))
		return
	}
	svrLog.Infof("Published prefund tx %s", prefundTx.TxHash())
}

func (s *Server) redeemTree(sess *session) {
	sess.Lock()
	tree := sess.tree
	allPrivs := sess.allUserPrivs
	sess.Unlock()

	err := s.cfg.TreeRedeemer(s.ctx, tree, allPrivs)
	if err != nil {
		svrLog.Errorf("Unable to redeem tree: %v", err)
	}
}

func (s *Server) JoinSession(ctx context.Context, req *api.JoinSessionRequest) (*api.JoinSessionResponse, error) {
	if len(req.UserPkHashes) == 0 {
		return nil, fmt.Errorf("no pk hashes sent")
	}

	// Verify the session by this id exists.
	s.mtx.Lock()
	var sessID sessionID
	copy(sessID[:], req.SessionId)
	waitingSess, ok := s.waitingSessions[sessID]
	if !ok {
		s.mtx.Unlock()
		return nil, fmt.Errorf("session %x does not exist", req.SessionId)
	}
	sess := waitingSess.session
	s.mtx.Unlock()

	// Perform all ops under the session lock.
	sess.Lock()

	// Perform any steps that might cause an error before actually
	// registering the new user in the session.

	// Ensure we haven't started before acquiring the lock.
	if waitingSess.started() {
		sess.Unlock()
		return nil, fmt.Errorf("session already started")
	}

	// Verify the proposed new leaf count is correct.
	leafsLeft := sess.nbLeafs - waitingSess.nbWaitingLeafs
	gotLeafs := waitingSess.enoughLeafs
	startsSession := leafsLeft == len(req.UserPkHashes)
	if leafsLeft < len(req.UserPkHashes) {
		sess.Unlock()
		return nil, fmt.Errorf("too many pk hashes provided")
	}

	// Initialize a new user session.
	userSess, err := sess.newUserSession()
	if err != nil {
		sess.Unlock()
		return nil, err
	}

	if startsSession {
		if err := s.preStartSession(sess); err != nil {
			sess.Unlock()
			return nil, err
		}
	}

	// Register the new waiting user.
	waitingSess.nbWaitingLeafs += len(req.UserPkHashes)
	userSess.userPkHashes = req.UserPkHashes

	if startsSession {
		sess.start()
		close(waitingSess.enoughLeafs)

		for sessToken := range sess.userSessions {
			s.sessions.Store(sessToken, sess)
		}
	}
	sess.Unlock()

	if startsSession {
		// If the session started, remove from the list of waiting
		// sessions.
		s.mtx.Lock()
		delete(s.waitingSessions, sessID)
		s.mtx.Unlock()
	}

	// Wait for a resolution to this request (session starts or user
	// disconnects).
	select {
	case <-ctx.Done():
		// User disconnected.
		sess.Lock()
		waitingSess.nbWaitingLeafs -= len(req.UserPkHashes)
		delete(sess.userSessions, userSess.token)

		if waitingSess.started() {
			s.failSession(sess, fmt.Errorf("user disconnected after session started"))
		}
		sess.Unlock()

		return nil, ctx.Err()

	case <-sess.failed:
		// Session failed for some reason.
		return nil, sess.err

	case <-gotLeafs:
		// Starting session.
	}

	sess.Lock()
	userSess.state = ussWaitingKeys
	resp := &api.JoinSessionResponse{
		SessionToken:     userSess.token[:],
		LockTime:         sess.lockTime,
		InitialLockTime:  sess.initialLockTime,
		FundLockTime:     sess.fundLockTime,
		ChangeKey:        sess.changeKey.SerializeCompressed(),
		TxFeeRate:        int64(sess.txFeeRate),
		LeafAmount:       int64(sess.leafAmount),
		UserPkHashes:     sess.allUserPkHashes,
		ProviderPkHashes: sess.allProviderPkHashes,
	}

	sess.Unlock()

	return resp, nil
}

func (s *Server) RevealLeafKeys(ctx context.Context, req *api.RevealLeafKeysRequest) (*api.RevealLeafKeysResponse, error) {

	if len(req.UserIvs) != len(req.UserKeys) {
		return nil, fmt.Errorf("inconsistent nb of keys and ivs")
	}

	var sessToken sessionToken
	copy(sessToken[:], req.SessionToken)
	sess, err := s.findSession(sessToken)
	if err != nil {
		return nil, err
	}

	sess.Lock()
	userSess, ok := sess.userSessions[sessToken]
	if !ok {
		// Shouldn't happen, but err on side of caution.
		sess.Unlock()
		return nil, fmt.Errorf("user session %x not found", sessToken)
	}
	if userSess.state != ussWaitingKeys {
		sess.Unlock()
		return nil, fmt.Errorf("user session already advanced the state")
	}
	userSess.state = ussVerifyingKeys
	userHashes := userSess.userPkHashes
	nbUserLeafs := len(userHashes)
	sess.Unlock()

	// Verify the keys match the commitments from the first request.
	if len(req.UserKeys) != nbUserLeafs {
		return nil, fmt.Errorf("wrong nb of keys")
	}
	if err := verifyKeyIVHashes(req.UserKeys, req.UserIvs, userHashes); err != nil {
		return nil, err
	}

	// Verify all pubkeys are sane.
	//
	// TODO: look for duplicate keys?
	if err := verifySanePubKeys(req.UserKeys); err != nil {
		return nil, err
	}

	sess.Lock()
	userSess.userKeys = req.UserKeys
	userSess.state = ussWaitingAllKeys
	sess.nbFilledKeys += nbUserLeafs
	gotAllKeys := sess.gotAllKeys
	if sess.nbFilledKeys == sess.nbLeafs {
		sess.keysFilled()
		var err error
		if err = sess.createTree(); err != nil {
			s.failSession(sess, fmt.Errorf("unable to create tree: %v", err))
		} else {

			sess.providerTreeNonces, sess.providerFundNonces, err =
				s.cfg.TreeNoncer(ctx, sess.tree)
			if err != nil {
				s.failSession(sess, fmt.Errorf("unable to generate nonces: %v", err))
			}
		}

		if err == nil {
			sess.calcProviderNonceHashes()
			close(gotAllKeys)
		}
	}
	sessFailed := sess.failed
	sess.Unlock()

	select {
	case <-ctx.Done():
		s.failSession(sess, fmt.Errorf("user disconnected after session started"))
		return nil, ctx.Err()

	case <-sessFailed:
		return nil, fmt.Errorf("session has failed: %v", sess.err)

	case <-gotAllKeys:
	}

	sess.Lock()
	userSess.state = ussWaitingNonceHashes
	resp := &api.RevealLeafKeysResponse{
		PrefundInputs: marshalPrefundInputs(sess.inputs),
		UserKeys:      sess.allUserKeys,
		UserIvs:       sess.allUserIVs,
		ProviderKeys:  sess.allProviderKeys,
		ProviderIvs:   sess.allProviderIVs,
	}
	sess.Unlock()

	return resp, nil
}

func (s *Server) CommitToNonces(ctx context.Context, req *api.CommitToNoncesRequest) (*api.CommitToNoncesResponse, error) {
	var sessToken sessionToken
	copy(sessToken[:], req.SessionToken)
	sess, err := s.findSession(sessToken)
	if err != nil {
		return nil, err
	}

	sess.Lock()
	userSess, ok := sess.userSessions[sessToken]
	if !ok {
		// Shouldn't happen, but err on side of caution.
		sess.Unlock()
		return nil, fmt.Errorf("user session %x not found", sessToken)
	}
	if userSess.state != ussWaitingNonceHashes {
		sess.Unlock()
		return nil, fmt.Errorf("user session already advanced the state")
	}
	userSess.state = ussVerifyingNonceHashes
	userNodeIndices := userSess.nodeIndices
	sess.Unlock()

	// Verify nonce hash count.
	if len(userNodeIndices) != len(req.TreeNonceHashes) {
		return nil, fmt.Errorf("unexpected nb of hash entries (want %d, got %d)",
			len(userNodeIndices), len(req.TreeNonceHashes))
	}
	for index, count := range userNodeIndices {
		gotCount := len(req.TreeNonceHashes[index].Data)
		if count != gotCount {
			return nil, fmt.Errorf("unexpected nb of hashes in index %d "+
				"(want %d, got %d)", index, count, gotCount)
		}
	}

	sess.Lock()
	userSess.treeNonceHashes = unmarshalMapByteSlices(req.TreeNonceHashes)
	userSess.fundNonceHashes = req.FundNonceHashes
	userSess.state = ussWaitingAllNonceHashes
	sess.nbFilledNonceHashes += 1
	gotAllNonceHashes := sess.gotAllNonceHashes
	if sess.nbFilledNonceHashes == len(sess.userSessions) {
		sess.nonceHashesFilled()
		close(gotAllNonceHashes)
	}
	sessFailed := sess.failed
	sess.Unlock()

	select {
	case <-ctx.Done():
		s.failSession(sess, fmt.Errorf("user disconnected after session started"))
		return nil, ctx.Err()

	case <-sessFailed:
		return nil, fmt.Errorf("session has failed: %v", sess.err)

	case <-gotAllNonceHashes:
	}

	sess.Lock()
	userSess.state = ussWaitingNonces
	resp := &api.CommitToNoncesResponse{
		TreeNonceHashes: marshalMapByteSlices(sess.allTreeNonceHashes),
		FundNonceHashes: sess.allFundNonceHashes,
	}
	sess.Unlock()

	return resp, nil
}

func (s *Server) RevealNonces(ctx context.Context, req *api.RevealNoncesRequest) (*api.RevealNoncesResponse, error) {
	var sessToken sessionToken
	copy(sessToken[:], req.SessionToken)
	sess, err := s.findSession(sessToken)
	if err != nil {
		return nil, err
	}

	sess.Lock()
	userSess, ok := sess.userSessions[sessToken]
	if !ok {
		// Shouldn't happen, but err on side of caution.
		sess.Unlock()
		return nil, fmt.Errorf("user session %x not found", sessToken)
	}
	if userSess.state != ussWaitingNonces {
		sess.Unlock()
		return nil, fmt.Errorf("user session already advanced the state")
	}
	userSess.state = ussVerifyingNonces
	treeNonceHashes := userSess.treeNonceHashes
	fundNonceHashes := userSess.fundNonceHashes
	sess.Unlock()

	// Verify the nonces match the commitments from the previous stage and
	// are sane points.
	if err := verifyKeyHashes(req.FundNonces, fundNonceHashes); err != nil {
		return nil, err
	}
	if err := verifySanePubKeys(req.FundNonces); err != nil {
		return nil, err
	}
	if len(treeNonceHashes) != len(req.TreeNonces) {
		return nil, fmt.Errorf("unexpected nb of hash entries (want %d, got %d)",
			len(treeNonceHashes), len(req.TreeNonces))
	}
	for index, hashes := range treeNonceHashes {
		gotNonces := req.TreeNonces[index].Data
		if len(hashes) != len(gotNonces) {
			return nil, fmt.Errorf("unexpected nb of hashes in index %d "+
				"(want %d, got %d)", index, len(hashes), len(gotNonces))
		}
		for i := 0; i < len(hashes); i++ {
			gotHash := chainhash.HashB(gotNonces[i])
			if !bytes.Equal(gotHash, hashes[i]) {
				return nil, fmt.Errorf("hash at index (%d,%d) "+
					"does not validate (want %x, got %x)",
					index, i, hashes[i], gotHash)
			}
		}
	}

	sess.Lock()
	userSess.state = ussWaitingAllNonces
	userSess.treeNonces = unmarshalMapByteSlices(req.TreeNonces)
	userSess.fundNonces = req.FundNonces
	sess.nbFilledNonces += 1
	gotAllNonces := sess.gotAllNonces
	if sess.nbFilledNonces == len(sess.userSessions) {
		sess.noncesFilled()
		close(gotAllNonces)
	}
	sessFailed := sess.failed
	sess.Unlock()

	select {
	case <-ctx.Done():
		s.failSession(sess, fmt.Errorf("user disconnected after session started"))
		return nil, ctx.Err()

	case <-sessFailed:
		return nil, fmt.Errorf("session has failed: %v", sess.err)

	case <-gotAllNonces:
	}

	sess.Lock()
	userSess.state = ussWaitingSignatures
	resp := &api.RevealNoncesResponse{
		TreeNonces: marshalMapByteSlices(sess.allTreeNonces),
		FundNonces: sess.allFundNonces,
	}
	sess.Unlock()

	return resp, nil
}

func (s *Server) SignedTree(ctx context.Context, req *api.SignedTreeRequest) (*api.SignedTreeResponse, error) {
	var sessToken sessionToken
	copy(sessToken[:], req.SessionToken)
	sess, err := s.findSession(sessToken)
	if err != nil {
		return nil, err
	}

	sess.Lock()
	userSess, ok := sess.userSessions[sessToken]
	if !ok {
		// Shouldn't happen, but err on side of caution.
		sess.Unlock()
		return nil, fmt.Errorf("user session %x not found", sessToken)
	}
	if userSess.state != ussWaitingSignatures {
		sess.Unlock()
		return nil, fmt.Errorf("user session already advanced the state")
	}
	userSess.state = ussVerifyingSignatures
	sess.Unlock()

	// TODO: validate all the sigs.

	sess.Lock()
	userSess.state = ussWaitingAllSignatures
	userSess.treeSigs = unmarshalMapByteSlices(req.TreeSignatures)
	userSess.fundSigs = req.FundSignatures
	sess.nbFilledSigs += 1
	gotAllSigs := sess.gotAllSigs
	totalUserInput := dcrutil.Amount(len(userSess.userPkHashes)) * sess.leafAmount // + fees
	if sess.nbFilledSigs == len(sess.userSessions) {
		// All user signatures received, provider will sign.
		var err error
		sess.providerTreeSigs, sess.providerFundSigs, err = s.cfg.TreeSigner(ctx, sess.tree, sess.allTreeNonces, sess.allFundNonces)
		if err != nil {
			s.failSession(sess, fmt.Errorf("unable to sign tree: %v", err))
		} else {
			if err := sess.signaturesFilled(); err != nil {
				s.failSession(sess, fmt.Errorf("unable to fill tree sigs: %v", err))
			} else {
				// Publish the prefund tx.
				go s.publishPrefund(sess)
				close(gotAllSigs)
			}
		}
	}
	sessFailed := sess.failed
	sess.Unlock()

	select {
	case <-ctx.Done():
		s.failSession(sess, fmt.Errorf("user disconnected after session started"))
		return nil, ctx.Err()

	case <-sessFailed:
		return nil, fmt.Errorf("session has failed: %v", sess.err)

	case <-gotAllSigs:
	}

	sess.Lock()
	userSess.state = ussDone
	resp := &api.SignedTreeResponse{
		TreeSignatures:   sess.allTreeSigs,
		FundSignaturePub: sess.fundSigPub,
	}
	sess.Unlock()

	// Generate an LN invoice for this user to send his funds and receive
	// back the full funding tx sig.
	//
	// TODO: add a per-use tweak so multiple invoices can be generated on a
	// single session.
	invoice := &lnrpc.Invoice{
		Memo:      "MRTTREE purchase",
		RPreimage: sess.fundSig,
		IsPtlc:    true,
		Value:     int64(totalUserInput),
	}
	invoiceRes, err := s.cfg.LNClient.AddInvoice(ctx, invoice)
	if err != nil {
		s.failSession(sess, fmt.Errorf("failed to generate invoice: %v", err))
		return nil, err
	}

	resp.LnPayReq = invoiceRes.PaymentRequest

	return resp, nil
}

func (s *Server) RedeemLeaf(ctx context.Context, req *api.RedeemLeafRequest) (*api.RedeemLeafResponse, error) {
	// TODO: it shouldn't be the per-user session token but rather the
	// global session id.
	var sessToken sessionToken
	copy(sessToken[:], req.SessionToken)
	sess, err := s.findSession(sessToken)
	if err != nil {
		return nil, err
	}

	sess.Lock()
	amount := sess.leafAmount // + fees?
	userSess, ok := sess.userSessions[sessToken]
	if !ok {
		// Shouldn't happen, but err on side of caution.
		sess.Unlock()
		return nil, fmt.Errorf("user session %x not found", sessToken)
	}
	if userSess.state != ussDone {
		sess.Unlock()
		return nil, fmt.Errorf("user session already advanced the state")
	}
	sess.Unlock()

	// TODO: verify the pubkey in the payment request is actually part of
	// this session.

	// Perform the LN payment to figure out the user private key.
	sendPayReq := &lnrpc.SendRequest{
		Amt:            int64(amount),
		PaymentRequest: req.LnPayReq,
	}
	sendPayRes, err := s.cfg.LNClient.SendPaymentSync(ctx, sendPayReq)
	if err != nil {
		return nil, fmt.Errorf("unable to pay ln invoice: %v", err)
	}
	if sendPayRes.PaymentError != "" {
		return nil, fmt.Errorf("payment error: %s", sendPayRes.PaymentError)
	}
	svrLog.Infof("Found out priv key %x", sendPayRes.PaymentPreimage)

	sess.Lock()
	userSess.privKeys = append(userSess.privKeys, sendPayRes.PaymentPreimage)
	sess.nbPrivKeys += 1
	if sess.nbPrivKeys == sess.nbLeafs {
		// Found all mrttree leaf keys. Close it out on chain.
		sess.privKeysReceived()
		go s.redeemTree(sess)
	}
	sess.Unlock()

	return &api.RedeemLeafResponse{}, nil
}

func (s *Server) UserError(context.Context, *api.UserErrorRequest) (*api.UserErrorResponse, error) {
	return nil, nil
}

func (s *Server) Run(ctx context.Context) error {
	s.ctx = ctx
	<-ctx.Done()
	return ctx.Err()
}

func NewServer(cfg *Config) (*Server, error) {
	s := &Server{
		cfg:             cfg,
		waitingSessions: make(map[sessionID]*waitingSession),
	}

	return s, nil
}
