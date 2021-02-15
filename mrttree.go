package mrttree

import (
	"fmt"
	"math/bits"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/wire"
)

type Node struct {
	ProviderKey         secp256k1.PublicKey
	ProviderSellableKey secp256k1.PublicKey
	UserKey             secp256k1.PublicKey
	UserSellableKey     secp256k1.PublicKey

	Parent      *Node
	ParentIndex int
	Tree        *Tree
	Children    [2]*Node
	Level       uint32
	Index       uint32

	Amount dcrutil.Amount

	Tx *wire.MsgTx
}

// ScriptKeys returns the long, medium, short and immediate keys (respectively)
// for a given MRTTREE node.
func (n *Node) ScriptKeys() (*secp256k1.PublicKey, *secp256k1.PublicKey,
	*secp256k1.PublicKey, *secp256k1.PublicKey) {

	longKey := n.ProviderKey
	mediumKey := addPubKeys(&n.ProviderKey, &n.UserKey)
	shortKey := addPubKeys(&n.ProviderSellableKey, &n.UserKey)
	immediateKey := addPubKeys(&n.ProviderKey, &n.UserSellableKey)

	return &longKey, &mediumKey, &shortKey, &immediateKey
}

func (n *Node) RedeemScript() ([]byte, error) {
	longLT := n.Tree.LongLockTime
	mediumLT := n.Tree.MediumLockTime
	shortLT := n.Tree.ShortLockTime
	if n.Level == 0 {
		longLT += n.Tree.InitialLockTime
		mediumLT += n.Tree.InitialLockTime
		shortLT += n.Tree.InitialLockTime
	}

	longKey, mediumKey, shortKey, immediateKey := n.ScriptKeys()
	redeemScript, err := nodeScript(longKey, mediumKey, shortKey,
		immediateKey, longLT, mediumLT, shortLT)
	if err != nil {
		return nil, err
	}

	return redeemScript, nil
}

func (n *Node) PkScript() ([]byte, error) {
	redeemScript, err := n.RedeemScript()
	if err != nil {
		return nil, err
	}
	return payToScriptHashScript(redeemScript), nil
}

type Tree struct {
	Root   *Node
	Tx     *wire.MsgTx
	Levels uint32

	LongLockTime    uint32
	MediumLockTime  uint32
	ShortLockTime   uint32
	InitialLockTime uint32
}

type ProposedLeaf struct {
	ProviderKey         secp256k1.PublicKey
	ProviderSellableKey secp256k1.PublicKey
	UserKey             secp256k1.PublicKey
	UserSellableKey     secp256k1.PublicKey
	Amount              dcrutil.Amount
}

type ProposedTree struct {
	Leafs           []ProposedLeaf
	LongLockTime    uint32
	MediumLockTime  uint32
	ShortLockTime   uint32
	InitialLockTime uint32

	Inputs       []*wire.TxIn
	ChangeScript []byte
	TxFeeRate    dcrutil.Amount
}

func BuildTree(proposal *ProposedTree) (*Tree, error) {
	// TODO: assert proposal parameters are sane (lock times, fees,
	// amounts, etc).

	// TODO: sort the leafs according to some cannonical ordering.

	// TODO: Maybe support !square nb of leafs?
	leafs := proposal.Leafs
	nbLeafs := len(leafs)
	if !isSquare(nbLeafs) {
		return nil, fmt.Errorf("nb of leafs must be square")
	}

	nbLevels := bits.TrailingZeros(uint(nbLeafs)) + 1

	nodeFee := dcrutil.Amount(calcNodeTxFee(proposal.TxFeeRate))
	leafRedeemFee := dcrutil.Amount(calcLeafRedeemTxFee(proposal.TxFeeRate))

	nbNodes := (nbLeafs << 1) - 1
	nodes := make([]Node, nbNodes)
	fundTx := wire.NewMsgTx()
	tree := &Tree{
		Root:            &nodes[0],
		Tx:              fundTx,
		Levels:          uint32(nbLevels),
		LongLockTime:    proposal.LongLockTime,
		MediumLockTime:  proposal.MediumLockTime,
		ShortLockTime:   proposal.ShortLockTime,
		InitialLockTime: proposal.InitialLockTime,
	}

	// Setup the basic tree (starting from the end, where leafs are).
	parentIdx := nbNodes - nbLeafs - 1
	for i := nbNodes - 1; i >= 0; i-- {
		if i >= nbNodes-nbLeafs {
			// Still a leaf node, so fill in leaf data.
			leafIdx := nbLeafs - (nbNodes - i)
			leaf := leafs[leafIdx]
			nodes[i] = Node{
				ProviderKey:         leaf.ProviderKey,
				ProviderSellableKey: leaf.ProviderSellableKey,
				UserKey:             leaf.UserKey,
				UserSellableKey:     leaf.UserSellableKey,
				Amount:              leaf.Amount,
			}
		} else {
			// Non-leaf keys are the sum of the child keys.
			child := nodes[i].Children
			nodes[i].ProviderKey = addPubKeys(&child[0].ProviderKey,
				&child[1].ProviderKey)
			nodes[i].ProviderSellableKey = addPubKeys(&child[0].ProviderSellableKey,
				&child[1].ProviderSellableKey)
			nodes[i].UserKey = addPubKeys(&child[0].UserKey,
				&child[1].UserKey)
			nodes[i].UserSellableKey = addPubKeys(&child[0].UserSellableKey,
				&child[1].UserSellableKey)
			nodes[i].Amount = child[0].Amount + child[1].Amount + nodeFee
		}

		nodes[i].Level = uint32(31 - bits.LeadingZeros32(uint32(i+1)))
		nodes[i].Tree = tree
		nodes[i].Index = uint32(i)

		// Fill in parent data while not at root.
		if i > 0 {
			parent := &nodes[parentIdx]
			childIdx := (i + 1) % 2
			parent.Children[childIdx] = &nodes[i]
			nodes[i].Parent = parent
			parentIdx += childIdx - 1
			nodes[i].ParentIndex = childIdx
		}
	}

	root := &nodes[0]
	rootScript, err := root.PkScript()
	if err != nil {
		return nil, err
	}

	// Build the funding tx.
	inAmount := sumInputAmounts(proposal.Inputs)
	outAmount := int64(root.Amount)
	changeAmount := inAmount - outAmount - int64(nodeFee)
	if changeAmount < 0 { // TODO: handle dust
		return nil, fmt.Errorf("not enough input funds")
	}

	fundTx.TxIn = proposal.Inputs
	fundTx.AddTxOut(wire.NewTxOut(int64(root.Amount), rootScript))
	fundTx.AddTxOut(wire.NewTxOut(changeAmount, proposal.ChangeScript))

	// Build each node tx.
	for i := 0; i < nbNodes; i++ {
		parentTx := fundTx
		var parentOutput uint32
		if i > 0 {
			parentTx = nodes[i].Parent.Tx
			parentOutput = uint32(nodes[i].ParentIndex)
		}

		tx := wire.NewMsgTx()
		nodes[i].Tx = tx
		tx.Version = 2
		outp := wire.NewOutPoint(parentTx.CachedTxHash(), parentOutput, 0)
		in := wire.NewTxIn(outp, int64(nodes[i].Amount), nil)

		// By default we redeem using the medum lock time, which is
		// pre-signed by both user and provider.
		in.Sequence = proposal.MediumLockTime
		if i == 0 {
			// The root tx also requires the full initial lock time
			// to pass.
			in.Sequence += proposal.InitialLockTime
		}
		tx.AddTxIn(in)

		if nodes[i].Children[0] == nil {
			// For the leaf txs, add a dummy output that will be
			// filled by users.
			tx.AddTxOut(wire.NewTxOut(int64(nodes[i].Amount-leafRedeemFee), []byte{}))
			continue
		}

		// For non-leaf txs, add outputs for both children.

		c0, c1 := nodes[i].Children[0], nodes[i].Children[1]
		c0Script, err := c0.PkScript()
		if err != nil {
			return nil, err
		}
		c1Script, err := c1.PkScript()
		if err != nil {
			return nil, err
		}

		tx.AddTxOut(wire.NewTxOut(int64(c0.Amount), c0Script))
		tx.AddTxOut(wire.NewTxOut(int64(c1.Amount), c1Script))
	}

	return tree, nil
}
