package server

import (
	"fmt"
	"sync"

	"decred.org/mrttree"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/wire"
)

type sessionID [8]byte
type sessionToken [8]byte

type userSessionState int

const (
	ussUnknown userSessionState = iota
	ussWaitingSessionStart
	ussWaitingKeys
	ussVerifyingKeys
	ussWaitingAllKeys
	ussWaitingNonceHashes
	ussVerifyingNonceHashes
	ussWaitingAllNonceHashes
	ussWaitingNonces
	ussVerifyingNonces
	ussWaitingAllNonces
	ussWaitingSignatures
	ussVerifyingSignatures
	ussWaitingAllSignatures
	ussDone
)

type userSession struct {
	state        userSessionState
	token        sessionToken
	userPkHashes [][]byte
	sellPkHashes [][]byte
	fundPkHashes [][]byte

	nodeIndices     map[uint32]int
	treeNonceHashes map[uint32][][]byte
	fundNonceHashes [][]byte

	userKeys   [][]byte
	userIVs    [][]byte
	treeNonces map[uint32][][]byte
	fundNonces [][]byte
	treeSigs   map[uint32][][]byte
	fundSigs   [][]byte
}

type session struct {
	sync.RWMutex

	nbLeafs int

	nbFilledKeys int
	gotAllKeys   chan struct{}

	nbFilledNonceHashes int
	gotAllNonceHashes   chan struct{}

	nbFilledNonces int
	gotAllNonces   chan struct{}

	nbFilledSigs int
	gotAllSigs   chan struct{}

	providerTreeNonceHashes map[uint32][][]byte
	providerTreeNonces      map[uint32][][]byte
	providerFundNonceHashes [][]byte
	providerFundNonces      [][]byte
	providerTreeSigs        map[uint32][][]byte
	providerFundSigs        [][]byte

	allUserPkHashes     [][]byte
	allProviderPkHashes [][]byte
	allUserIVs          [][]byte
	allUserKeys         [][]byte
	allProviderIVs      [][]byte
	allProviderKeys     [][]byte
	allTreeNonceHashes  map[uint32][][]byte
	allFundNonceHashes  [][]byte
	allTreeNonces       map[uint32][][]byte
	allFundNonces       [][]byte
	allTreeSigs         map[uint32][]byte
	fundSig             []byte
	fundSigPub          []byte

	lockTime        uint32
	initialLockTime uint32
	fundLockTime    uint32
	prefundTx       *wire.MsgTx
	inputs          []*wire.TxIn
	changeKey       *secp256k1.PublicKey
	leafAmount      dcrutil.Amount
	userSessions    map[sessionToken]*userSession
	txFeeRate       dcrutil.Amount
	tree            *mrttree.Tree
	failed          chan struct{}
	err             error
}

func (sess *session) failSession(err error) {
	sess.err = err
	close(sess.failed)
}

func (sess *session) FailSession(err error) {
	sess.Lock()
	sess.failSession(err)
	sess.Unlock()
}

func (sess *session) newUserSession() (*userSession, error) {
	// Generate a unique user token.
	var token sessionToken
	for {
		if err := readRand(token[:]); err != nil {
			return nil, err
		}

		if _, ok := sess.userSessions[token]; !ok {
			break
		}
	}

	us := &userSession{
		token: token,
		state: ussWaitingSessionStart,
	}
	sess.userSessions[token] = us
	return us, nil
}

func (sess *session) start() {
	allUserHashes := make([][]byte, 0, sess.nbLeafs)
	for _, us := range sess.userSessions {
		allUserHashes = append(allUserHashes, us.userPkHashes...)
	}
	// TODO: shuffle entries since order doesn't matter.
	sess.allUserPkHashes = allUserHashes
}

func (sess *session) keysFilled() {
	allUserKeys := make([][]byte, 0, sess.nbLeafs)
	allUserIVs := make([][]byte, 0, sess.nbLeafs)
	for _, us := range sess.userSessions {
		allUserKeys = append(allUserKeys, us.userKeys...)
		allUserIVs = append(allUserIVs, us.userIVs...)
	}
	sess.allUserKeys = allUserKeys
	sess.allUserIVs = allUserIVs

	// TODO: Pre-sort keys according to cannonical ordering in the tree.
}

func (sess *session) createTree() error {
	leafs := make([]mrttree.ProposedLeaf, sess.nbLeafs)
	for i := 0; i < sess.nbLeafs; i++ {
		userKey, err := secp256k1.ParsePubKey(sess.allUserKeys[i])
		if err != nil {
			return err
		}
		providerKey, err := secp256k1.ParsePubKey(sess.allProviderKeys[i])
		if err != nil {
			return err
		}
		leafs[i] = mrttree.ProposedLeaf{
			Amount:      dcrutil.Amount(sess.leafAmount),
			ProviderKey: *providerKey,
			UserKey:     *userKey,
		}
	}

	proposal := &mrttree.ProposedTree{
		Leafs:           leafs,
		LockTime:        sess.lockTime,
		InitialLockTime: sess.initialLockTime,
		FundLockTime:    sess.fundLockTime,

		PrefundInputs: sess.inputs,
		ChangeKey:     *sess.changeKey,
		TxFeeRate:     sess.txFeeRate,
	}

	tree, err := mrttree.BuildTree(proposal)
	if err != nil {
		return err
	}
	sess.tree = tree

	fmt.Printf("XXXX server tree tx hash: %s\n", tree.Tx.TxHash())

	// Generate the map from pubkeys to leaf nodes.
	leafToNodes := tree.BuildLeafPubKeyMap()

	// Now, for each user, determine the node indexes they are involved in.
	for u, us := range sess.userSessions {
		leafKeys := make([]*secp256k1.PublicKey, len(us.userKeys))
		for i, k := range us.userKeys {
			var err error
			leafKeys[i], err = secp256k1.ParsePubKey(k)
			if err != nil {
				return err
			}
		}

		us.nodeIndices, err = leafToNodes.AncestorBranchesCount(leafKeys)
		if err != nil {
			return fmt.Errorf("error at user %d: %v", u, err)
		}
	}

	return err
}

func (sess *session) calcProviderNonceHashes() {
	sess.providerTreeNonceHashes = make(map[uint32][][]byte, len(sess.providerTreeNonces))

	for i, nonces := range sess.providerTreeNonces {
		hashes := make([][]byte, len(nonces))
		for j, nonce := range nonces {
			hashes[j] = chainhash.HashB(nonce)
		}
		sess.providerTreeNonceHashes[i] = hashes
	}

	fundHashes := make([][]byte, len(sess.providerFundNonces))
	for i, nonce := range sess.providerFundNonces {
		fundHashes[i] = chainhash.HashB(nonce)
	}
	sess.providerFundNonceHashes = fundHashes
}

func (sess *session) nonceHashesFilled() {
	nbTxs := mrttree.CalcTreeTxs(sess.nbLeafs)
	allTreeNonceHashes := make(map[uint32][][]byte, nbTxs)
	allFundNonceHashes := make([][]byte, 0, sess.nbLeafs*2)

	for _, us := range sess.userSessions {
		for index, hashes := range us.treeNonceHashes {
			allTreeNonceHashes[index] = append(allTreeNonceHashes[index], hashes...)
		}
		allFundNonceHashes = append(allFundNonceHashes, us.fundNonceHashes...)
	}

	// Fill in the provider nonces.
	for index, hashes := range sess.providerTreeNonceHashes {
		allTreeNonceHashes[index] = append(allTreeNonceHashes[index], hashes...)
	}
	allFundNonceHashes = append(allFundNonceHashes, sess.providerFundNonceHashes...)

	sess.allTreeNonceHashes = allTreeNonceHashes
	sess.allFundNonceHashes = allFundNonceHashes
}

func (sess *session) noncesFilled() {
	nbTxs := mrttree.CalcTreeTxs(sess.nbLeafs)
	allTreeNonces := make(map[uint32][][]byte, nbTxs)
	allFundNonces := make([][]byte, 0, sess.nbLeafs)
	for _, us := range sess.userSessions {
		for index, nonces := range us.treeNonces {
			allTreeNonces[index] = append(allTreeNonces[index], nonces...)
		}
		allFundNonces = append(allFundNonces, us.fundNonces...)
	}

	// Fill in the provider nonces.
	for index, hashes := range sess.providerTreeNonces {
		allTreeNonces[index] = append(allTreeNonces[index], hashes...)
	}
	allFundNonces = append(allFundNonces, sess.providerFundNonces...)

	// TODO: shuffle entries since order doesn't matter.
	sess.allTreeNonces = allTreeNonces
	sess.allFundNonces = allFundNonces
}

func (sess *session) signaturesFilled() error {
	nbTxs := mrttree.CalcTreeTxs(sess.nbLeafs)
	allTreeSigs := make(map[uint32][]byte, nbTxs)

	treeSigs := make(map[uint32]*secp256k1.ModNScalar, nbTxs)
	var fundSig secp256k1.ModNScalar

	for index, sigs := range sess.providerTreeSigs {
		nsig := new(secp256k1.ModNScalar)
		nsig.SetByteSlice(sigs[0])
		treeSigs[index] = nsig

		var sig secp256k1.ModNScalar
		for _, sigBytes := range sigs[1:] {
			sig.SetByteSlice(sigBytes)
			treeSigs[index].Add(&sig)
		}
	}

	for _, sigBytes := range sess.providerFundSigs {
		var sig secp256k1.ModNScalar
		sig.SetByteSlice(sigBytes)
		fundSig.Add(&sig)
	}

	// Sum up the individual partial sigs.
	for _, us := range sess.userSessions {
		for index, sigs := range us.treeSigs {
			for _, sigBytes := range sigs {
				if _, ok := treeSigs[index]; !ok {
					nsig := new(secp256k1.ModNScalar)
					nsig.SetByteSlice(sigBytes)
					treeSigs[index] = nsig
				} else {
					var sig secp256k1.ModNScalar
					sig.SetByteSlice(sigBytes)
					treeSigs[index].Add(&sig)
				}
			}
		}
		for _, sigBytes := range us.fundSigs {
			var sig secp256k1.ModNScalar
			sig.SetByteSlice(sigBytes)
			fundSig.Add(&sig)
		}
	}

	// Convert the sigs to bytes.
	for index, sig := range treeSigs {
		sigBytes := sig.Bytes()
		allTreeSigs[index] = sigBytes[:]
	}
	fundSigBytes := fundSig.Bytes()

	sess.allTreeSigs = allTreeSigs
	sess.fundSig = fundSigBytes[:]

	// Finally, fill the signatureScript in the tree transactions and the
	// fund transaction.
	if err := sess.tree.FillTreeSignatures(sess.allTreeNonces, sess.allTreeSigs); err != nil {
		return err
	}
	if err := sess.tree.FillFundSignature(sess.allFundNonces, sess.fundSig); err != nil {
		return err
	}

	// And verify the signatures are correct.
	if err := sess.tree.VerifyTreeSignatures(); err != nil {
		return err
	}
	if err := sess.tree.VerifyFundSignature(); err != nil {
		return err
	}

	// Calculate the public point corresponding to the sig scalar.
	var fundSigPubPoint secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&fundSig, &fundSigPubPoint)
	fundSigPubPoint.ToAffine()
	fundSigPub := secp256k1.NewPublicKey(&fundSigPubPoint.X, &fundSigPubPoint.Y)
	sess.fundSigPub = fundSigPub.SerializeCompressed()

	// Double check the pub sig validates the tree.
	err := sess.tree.VerifyFundSignaturePub(sess.allFundNonces, sess.fundSigPub)
	if err != nil {
		return fmt.Errorf("unable to verify fund sig pub: %v", err)
	}

	return nil
}

type waitingSession struct {
	nbWaitingLeafs int
	enoughLeafs    chan struct{}

	session *session
}

func (ws *waitingSession) started() bool {
	select {
	case <-ws.enoughLeafs:
		return true
	default:
		return false
	}
}
