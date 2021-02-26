package server

import (
	"fmt"
	"sync"

	"decred.org/mrttree"
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
	sellKeys   [][]byte
	fundKeys   [][]byte
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

	allUserPkHashes     [][]byte
	allSellPkHashes     [][]byte
	allFundPkHashes     [][]byte
	allProviderPkHashes [][]byte
	allUserIVs          [][]byte
	allUserKeys         [][]byte
	allSellKeys         [][]byte
	allFundKeys         [][]byte
	allProviderIVs      [][]byte
	allProviderKeys     [][]byte
	allTreeNonceHashes  map[uint32][][]byte
	allFundNonceHashes  [][]byte
	allTreeNonces       map[uint32][][]byte
	allFundNonces       [][]byte
	allTreeSigs         map[uint32][]byte
	fundSig             []byte

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
	allSellHashes := make([][]byte, 0, sess.nbLeafs)
	allFundHashes := make([][]byte, 0, sess.nbLeafs)
	for _, us := range sess.userSessions {
		allUserHashes = append(allUserHashes, us.userPkHashes...)
		allSellHashes = append(allSellHashes, us.sellPkHashes...)
		allFundHashes = append(allFundHashes, us.fundPkHashes...)
	}
	// TODO: shuffle entries since order doesn't matter.
	sess.allUserPkHashes = allUserHashes
	sess.allSellPkHashes = allSellHashes
	sess.allFundPkHashes = allFundHashes
}

func (sess *session) keysFilled() {
	allUserKeys := make([][]byte, 0, sess.nbLeafs)
	allSellKeys := make([][]byte, 0, sess.nbLeafs)
	allFundKeys := make([][]byte, 0, sess.nbLeafs)
	allUserIVs := make([][]byte, 0, sess.nbLeafs)
	for _, us := range sess.userSessions {
		allUserKeys = append(allUserKeys, us.userKeys...)
		allSellKeys = append(allSellKeys, us.sellKeys...)
		allFundKeys = append(allFundKeys, us.fundKeys...)
		allUserIVs = append(allUserIVs, us.userIVs...)
	}
	sess.allUserKeys = allUserKeys
	sess.allSellKeys = allSellKeys
	sess.allFundKeys = allFundKeys
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
		sellKey, err := secp256k1.ParsePubKey(sess.allSellKeys[i])
		if err != nil {
			return err
		}
		providerKey, err := secp256k1.ParsePubKey(sess.allProviderKeys[i])
		if err != nil {
			return err
		}
		fundKey, err := secp256k1.ParsePubKey(sess.allFundKeys[i])
		if err != nil {
			return err
		}
		leafs[i] = mrttree.ProposedLeaf{
			Amount:              dcrutil.Amount(sess.leafAmount),
			ProviderKey:         *providerKey,
			ProviderSellableKey: *providerKey,
			UserKey:             *userKey,
			UserSellableKey:     *sellKey,
			FundKey:             *fundKey,
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

func (sess *session) nonceHashesFilled() {
	nbTxs := mrttree.CalcTreeTxs(sess.nbLeafs)
	allTreeNonceHashes := make(map[uint32][][]byte, nbTxs)
	allFundNonceHashes := make([][]byte, 0, sess.nbLeafs)

	for _, us := range sess.userSessions {
		for index, hashes := range us.treeNonceHashes {
			allTreeNonceHashes[index] = append(allTreeNonceHashes[index], hashes...)
		}
		allFundNonceHashes = append(allFundNonceHashes, us.fundNonceHashes...)
	}

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
	// TODO: shuffle entries since order doesn't matter.
	sess.allTreeNonces = allTreeNonces
	sess.allFundNonces = allFundNonces
}

func (sess *session) signaturesFilled() {
	nbTxs := mrttree.CalcTreeTxs(sess.nbLeafs)
	allTreeSigs := make(map[uint32][]byte, nbTxs)

	treeSigs := make(map[uint32]*secp256k1.ModNScalar, nbTxs)
	var fundSig secp256k1.ModNScalar

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
