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
	Leaf        bool
	LeafCount   int

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

type nodeStack []*Node

func (stack *nodeStack) push(node *Node) {
	*stack = append(*stack, node)
}

func (stack *nodeStack) pop() *Node {
	n := (*stack)[len(*stack)-1]
	*stack = (*stack)[:len(*stack)-1]
	return n
}

func (stack *nodeStack) len() int {
	return len(*stack)
}

func (stack *nodeStack) e(i int) *Node {
	return (*stack)[i]
}

func makeNodeStack(capHint int) *nodeStack {
	s := make(nodeStack, 0, capHint)
	return &s
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

func buildTree(tree *Tree, proposal *ProposedTree) error {
	// Tx fee required at every node (automatically added to the node
	// amount).
	nodeFee := dcrutil.Amount(calcNodeTxFee(proposal.TxFeeRate))

	// The algo for building the trees uses two alternating stacks to track
	// nodes at each level.
	leafs := proposal.Leafs
	nbLeafs := len(leafs)
	stack0 := makeNodeStack(nbLeafs)
	stack1 := makeNodeStack(nbLeafs)

	// Push the leaves in reverse order to the first stack, initializing a
	// new node as we go.
	for i := nbLeafs - 1; i >= 0; i-- {
		leaf := leafs[i]
		node := &Node{
			ProviderKey:         leaf.ProviderKey,
			ProviderSellableKey: leaf.ProviderSellableKey,
			UserKey:             leaf.UserKey,
			UserSellableKey:     leaf.UserSellableKey,
			Amount:              leaf.Amount,
			Index:               uint32(i),
			Tree:                tree,
			Leaf:                true,
			LeafCount:           1,
		}
		stack0.push(node)
	}
	i := nbLeafs

	// Now zip pairs of nodes in alternating order until only the root is
	// left.
	dir := 0
	tmp := make([]*Node, 0, 2)
	for stack0.len() != 1 {
		// Empty from stack0 into stack1 in pairs.
		for stack0.len() > 0 {
			tmp = append(tmp, stack0.pop())
			if len(tmp) == 2 {
				n0, n1 := tmp[dir], tmp[1-dir]

				// Non-leaf keys are the sum of the child keys.
				parent := &Node{
					ProviderKey: addPubKeys(&n0.ProviderKey,
						&n1.ProviderKey),
					ProviderSellableKey: addPubKeys(&n0.ProviderSellableKey,
						&n1.ProviderSellableKey),
					UserKey: addPubKeys(&n0.UserKey,
						&n1.UserKey),
					UserSellableKey: addPubKeys(&n0.UserSellableKey,
						&n1.UserSellableKey),
					Amount:   n0.Amount + n1.Amount + nodeFee,
					Children: [2]*Node{n0, n1},
					Tree:     tree,
					Index:    uint32(i),
					LeafCount: n0.LeafCount +
						n1.LeafCount,
				}

				// Fill in the parent data in the children.
				n0.Parent = parent
				n1.Parent = parent
				n0.ParentIndex = 0
				n1.ParentIndex = 1

				stack1.push(parent)
				tmp = tmp[:0]
				i += 1
			}
		}

		// If there's a single element left, push it as well, then swap
		// the stacks.
		if len(tmp) == 1 {
			stack1.push(tmp[0])
			tmp = tmp[:0]
		}
		stack0, stack1 = stack1, stack0

		// Revert the direction we set children after popping from the
		// stack so the leafs are maintained in the same order as they
		// are input.
		dir = 1 - dir
	}

	// Root is the single element left in the stack.
	tree.Root = stack0.e(0)

	// Setup the final level information, reusing stack0.
	for stack0.len() > 0 {
		n := stack0.pop()
		if n.Parent != nil {
			n.Level = n.Parent.Level + 1
		}
		if !n.Leaf {
			stack0.push(n.Children[0])
			stack0.push(n.Children[1])
		}
	}

	return nil
}

func buildTreeTxs(tree *Tree, proposal *ProposedTree) error {
	nodeFee := dcrutil.Amount(calcNodeTxFee(proposal.TxFeeRate))
	leafRedeemFee := dcrutil.Amount(calcLeafRedeemTxFee(proposal.TxFeeRate))
	root := tree.Root

	// Build the funding tx.
	fundTx := wire.NewMsgTx()
	tree.Tx = fundTx
	rootScript, err := root.PkScript()
	if err != nil {
		return err
	}

	inAmount := sumInputAmounts(proposal.Inputs)
	outAmount := int64(root.Amount)
	changeAmount := inAmount - outAmount - int64(nodeFee)
	if changeAmount < 0 { // TODO: handle dust
		return fmt.Errorf("not enough input funds")
	}

	fundTx.TxIn = proposal.Inputs
	fundTx.AddTxOut(wire.NewTxOut(int64(root.Amount), rootScript))
	fundTx.AddTxOut(wire.NewTxOut(changeAmount, proposal.ChangeScript))

	// Build each node tx.
	stack := makeNodeStack(len(proposal.Leafs))
	stack.push(tree.Root)
	for stack.len() > 0 {
		node := stack.pop()

		parentTx := fundTx
		var parentOutput uint32
		if node.Parent != nil {
			parentTx = node.Parent.Tx
			parentOutput = uint32(node.ParentIndex)
		}

		tx := wire.NewMsgTx()
		node.Tx = tx
		tx.Version = 2
		outp := wire.NewOutPoint(parentTx.CachedTxHash(), parentOutput, 0)
		in := wire.NewTxIn(outp, int64(node.Amount), nil)

		// By default we redeem using the medium lock time, which is
		// pre-signed by both user and provider.
		in.Sequence = proposal.MediumLockTime
		if node.Parent == nil {
			// The root tx also requires the full initial lock time
			// to pass.
			in.Sequence += proposal.InitialLockTime
		}
		tx.AddTxIn(in)

		if node.Leaf {
			// For the leaf txs, add a dummy output that will be
			// filled by users.
			tx.AddTxOut(wire.NewTxOut(int64(node.Amount-leafRedeemFee), []byte{}))
			continue
		}

		// For non-leaf txs, add outputs for both children.

		c0, c1 := node.Children[0], node.Children[1]
		c0Script, err := c0.PkScript()
		if err != nil {
			return err
		}
		c1Script, err := c1.PkScript()
		if err != nil {
			return err
		}

		tx.AddTxOut(wire.NewTxOut(int64(c0.Amount), c0Script))
		tx.AddTxOut(wire.NewTxOut(int64(c1.Amount), c1Script))

		stack.push(node.Children[0])
		stack.push(node.Children[1])
	}

	return nil
}

func BuildTree(proposal *ProposedTree) (*Tree, error) {
	// TODO: assert proposal parameters are sane (lock times, fees,
	// amounts, etc).

	// TODO: sort the leafs according to some cannonical ordering.

	leafs := proposal.Leafs
	nbLeafs := len(leafs)
	if nbLeafs == 0 {
		return nil, fmt.Errorf("empty tree")
	}

	nbLevels := 33 - bits.LeadingZeros32(uint32(nbLeafs-1))

	tree := &Tree{
		Levels:          uint32(nbLevels),
		LongLockTime:    proposal.LongLockTime,
		MediumLockTime:  proposal.MediumLockTime,
		ShortLockTime:   proposal.ShortLockTime,
		InitialLockTime: proposal.InitialLockTime,
	}

	if err := buildTree(tree, proposal); err != nil {
		return nil, err
	}
	if err := buildTreeTxs(tree, proposal); err != nil {
		return nil, err
	}

	return tree, nil
}
