package mrttree

import (
	"fmt"
	"math/bits"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrec/secp256k1/v3/schnorr"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/wire"
)

type Node struct {
	ProviderKey         secp256k1.PublicKey
	ProviderSellableKey secp256k1.PublicKey
	UserKey             secp256k1.PublicKey
	UserSellableKey     secp256k1.PublicKey
	FundKey             secp256k1.PublicKey

	Parent      *Node
	ParentIndex int
	Tree        *Tree
	Children    [2]*Node
	Level       uint32
	Index       uint32
	Leaf        bool
	LeafCount   int

	Amount dcrutil.Amount

	Tx         *wire.MsgTx
	PrevOutput *wire.TxOut
}

// ScriptKeys returns the locked and immediate keys (respectively) for a given
// MRTTREE node.
func (n *Node) ScriptKeys() (*secp256k1.PublicKey, *secp256k1.PublicKey) {

	lockedKey := n.UserKey
	immediateKey := addPubKeys(&n.ProviderKey, &n.UserSellableKey)

	return &lockedKey, &immediateKey
}

func (n *Node) RedeemScript() ([]byte, error) {
	lockTime := n.Tree.LockTime
	if n.Level == 0 {
		lockTime += n.Tree.InitialLockTime
	}

	lockedKey, immediateKey := n.ScriptKeys()
	redeemScript, err := nodeScript(lockedKey, immediateKey, lockTime)
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

func (n *Node) AssembleLockedSigScript(RPub *secp256k1.PublicKey, s *secp256k1.ModNScalar) error {
	var R secp256k1.JacobianPoint
	RPub.AsJacobian(&R)
	sig := schnorr.NewSignature(&R.X, s)
	pub, _ := n.ScriptKeys()
	redeemScript, err := n.RedeemScript()
	if err != nil {
		return err
	}

	n.Tx.TxIn[0].SignatureScript, err = nodeSigScript(sig, pub, redeemScript)
	return err
}

func (n *Node) SubtreeUserLeafKeys() []*secp256k1.PublicKey {
	stack := nodeStack{n}
	keys := make([]*secp256k1.PublicKey, 0, 1<<(n.Tree.Levels-n.Level-1))
	for len(stack) > 0 {
		p := stack.pop()
		if p.Leaf {
			keys = append(keys, &p.UserKey)
		} else {
			stack.push(p.Children[0])
			stack.push(p.Children[1])
		}
	}
	return keys
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

type LeafPubKeyMap map[secp256k1.PublicKey][]*Node

// AncestorBranchesCount returns a map that counts how many times branch nodes
// are ancestors of leaf nodes which UserKeys are in the passed userLeafKeys.
//
// This assumes every passed key can actually be found in the leaf pubkey map.
// In particular, repeated leaf keys must be found the exact number of times in
// the leaf map. If this assumption is not held, this function errors.
func (m LeafPubKeyMap) AncestorBranchesCount(userLeafKeys []*secp256k1.PublicKey) (map[uint32]int, error) {
	leftOverNodes := make(map[secp256k1.PublicKey][]*Node)
	res := make(map[uint32]int, len(userLeafKeys))
	for _, targetKey := range userLeafKeys {
		nodes := leftOverNodes[*targetKey]
		if nodes == nil {
			nodes = m[*targetKey]
			if nodes == nil {
				return nil, fmt.Errorf("key not used in any leaf: %x",
					targetKey.SerializeCompressed())
			}
		}
		if len(nodes) == 0 {
			return nil, fmt.Errorf("no more nodes left for key %x",
				targetKey.SerializeCompressed())
		}

		// Traverse the tree up, incrementing the count on visited
		// nodes.
		n := nodes[0].Parent
		for n != nil {
			res[n.Index] += 1
			n = n.Parent
		}

		// Handle advancing. If the same key was used in multiple
		// leaves, keep track of which ones we haven't visited yet and
		// make sure we don't visit twice the same key.
		leftOverNodes[*targetKey] = nodes[1:]
	}

	// Ensure no keys were left over (that is, repeated keys were found the
	// correct number of times).
	for key, nodes := range leftOverNodes {
		if len(nodes) != 0 {
			return nil, fmt.Errorf("key %x has %d left over nodes",
				key.SerializeCompressed(), len(nodes))
		}
	}

	return res, nil
}

type Tree struct {
	Root      *Node
	PrefundTx *wire.MsgTx
	Tx        *wire.MsgTx
	Levels    uint32
	Leafs     []*Node
	Nodes     []*Node
	ChangeKey secp256k1.PublicKey

	LockTime        uint32
	InitialLockTime uint32
	FundLockTime    uint32
}

// FundKey returns the group key used to spend the prefund output in the fund
// tx.
func (tree *Tree) FundKey() *secp256k1.PublicKey {
	fundKey := tree.Leafs[0].FundKey
	for i := 1; i < len(tree.Leafs); i++ {
		fundKey = addPubKeys(&fundKey, &tree.Leafs[i].FundKey)
	}
	return &fundKey
}

// FundScript returns the redeemScript of the prefund tx output, spent in the
// fund tx.
func (tree *Tree) FundScript() ([]byte, error) {
	fundKey := tree.FundKey()
	return fundScript(fundKey, &tree.ChangeKey, tree.FundLockTime)
}

func (tree *Tree) FundP2SH() ([]byte, error) {
	fundScript, err := tree.FundScript()
	if err != nil {
		return nil, err
	}
	fundP2SH := payToScriptHashScript(fundScript)
	return fundP2SH, nil
}

// BuildLeafPubKeyMap returns a map that lists every user pubkey to the leaf(s)
// they are involved in. The same pubkey might be involved in multiple leafs in
// case it is repetead.
func (tree *Tree) BuildLeafPubKeyMap() LeafPubKeyMap {
	res := make(LeafPubKeyMap, len(tree.Leafs))
	for _, leaf := range tree.Leafs {
		nodes := res[leaf.UserKey]
		res[leaf.UserKey] = append(nodes, leaf)
	}
	return res
}

func (tree *Tree) AssembleLockedSigScript(RPub *secp256k1.PublicKey, s *secp256k1.ModNScalar) error {
	var R secp256k1.JacobianPoint
	RPub.AsJacobian(&R)
	sig := schnorr.NewSignature(&R.X, s)
	pub := tree.FundKey()
	redeemScript, err := tree.FundScript()
	if err != nil {
		return err
	}

	tree.Tx.TxIn[0].SignatureScript, err = fundSigScript(sig, pub, redeemScript)
	return err
}

type ProposedLeaf struct {
	ProviderKey         secp256k1.PublicKey
	ProviderSellableKey secp256k1.PublicKey
	UserKey             secp256k1.PublicKey
	UserSellableKey     secp256k1.PublicKey
	Amount              dcrutil.Amount
	FundKey             secp256k1.PublicKey
}

type ProposedTree struct {
	Leafs           []ProposedLeaf
	LockTime        uint32
	InitialLockTime uint32
	FundLockTime    uint32

	PrefundInputs []*wire.TxIn
	Inputs        []*wire.TxIn
	ChangeKey     secp256k1.PublicKey
	TxFeeRate     dcrutil.Amount
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

	tree.Leafs = make([]*Node, nbLeafs)
	tree.Nodes = make([]*Node, CalcTreeTxs(nbLeafs)+nbLeafs)

	// Push the leaves in reverse order to the first stack, initializing a
	// new node as we go.
	for i := nbLeafs - 1; i >= 0; i-- {
		leaf := leafs[i]
		node := &Node{
			ProviderKey:         leaf.ProviderKey,
			ProviderSellableKey: leaf.ProviderSellableKey,
			UserKey:             leaf.UserKey,
			UserSellableKey:     leaf.UserSellableKey,
			FundKey:             leaf.FundKey,
			Amount:              leaf.Amount,
			Index:               uint32(i),
			Tree:                tree,
			Leaf:                true,
			LeafCount:           1,
		}
		stack0.push(node)
		tree.Leafs[i] = node
		tree.Nodes[i] = node
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

				tree.Nodes[i] = parent

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

	// Sanity check.
	if tree.Nodes[len(tree.Nodes)-1] == nil {
		return fmt.Errorf("assertion error: empty nodes in Nodes list")
	}

	return nil
}

func buildPrefundTx(tree *Tree, proposal *ProposedTree) error {
	fundP2SH, err := tree.FundP2SH()
	if err != nil {
		return err
	}

	nodeFee := calcNodeTxFee(proposal.TxFeeRate)
	prefundTxFee := calcPrefundTxFee(proposal.TxFeeRate, len(proposal.PrefundInputs))
	fundTxFee := calcFundTxFee(proposal.TxFeeRate, 0)
	inAmount := sumInputAmounts(proposal.PrefundInputs)
	outAmount := int64(tree.Root.Amount) + nodeFee + fundTxFee
	changeAmount := inAmount - outAmount - prefundTxFee

	if changeAmount < 6030 { // TODO: handle change < dust
		return fmt.Errorf("not enough input funds for prefund tx (change %d)", changeAmount)
	}

	changeScript := payToPubKeyHashScript(&proposal.ChangeKey)

	tx := wire.NewMsgTx()
	tx.TxIn = proposal.PrefundInputs
	tx.AddTxOut(wire.NewTxOut(outAmount, fundP2SH))
	tx.AddTxOut(wire.NewTxOut(changeAmount, changeScript))
	tree.PrefundTx = tx

	return nil
}

func buildTreeTxs(tree *Tree, proposal *ProposedTree) error {
	nodeFee := dcrutil.Amount(calcNodeTxFee(proposal.TxFeeRate))
	leafRedeemFee := dcrutil.Amount(calcLeafRedeemTxFee(proposal.TxFeeRate))
	root := tree.Root

	// Build the funding tx.
	rootScript, err := root.PkScript()
	if err != nil {
		return err
	}

	fundTxFee := calcFundTxFee(proposal.TxFeeRate, 0)
	inAmount := tree.PrefundTx.TxOut[0].Value
	outAmount := int64(root.Amount) + int64(nodeFee)
	changeAmount := inAmount - outAmount - fundTxFee
	if changeAmount != 0 {
		return fmt.Errorf("wrong set of input and output amounts (change %d)", changeAmount)
	}

	fundTx := wire.NewMsgTx()
	fundTx.Version = 2
	prefundPrevOut := &wire.OutPoint{Hash: tree.PrefundTx.TxHash()}
	fundTx.AddTxIn(wire.NewTxIn(prefundPrevOut, inAmount, nil))
	fundTx.AddTxOut(wire.NewTxOut(int64(root.Amount), rootScript))
	tree.Tx = fundTx

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
		node.PrevOutput = parentTx.TxOut[parentOutput]

		tx := wire.NewMsgTx()
		node.Tx = tx
		tx.Version = 2
		outp := wire.NewOutPoint(parentTx.CachedTxHash(), parentOutput, 0)
		in := wire.NewTxIn(outp, int64(node.Amount), nil)

		// By default we redeem using the medium lock time, which is
		// pre-signed by both user and provider.
		in.Sequence = proposal.LockTime
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
	if nbLeafs < 2 {
		return nil, fmt.Errorf("too few leafs")
	}

	nbLevels := 33 - bits.LeadingZeros32(uint32(nbLeafs-1))

	tree := &Tree{
		Levels:          uint32(nbLevels),
		LockTime:        proposal.LockTime,
		InitialLockTime: proposal.InitialLockTime,
		FundLockTime:    proposal.FundLockTime,
		ChangeKey:       proposal.ChangeKey,
	}

	if err := buildTree(tree, proposal); err != nil {
		return nil, err
	}

	if err := buildPrefundTx(tree, proposal); err != nil {
		return nil, err
	}

	if err := buildTreeTxs(tree, proposal); err != nil {
		return nil, err
	}

	return tree, nil
}

// Calc the number of intermediate nodes/transctions in the tree. This does
// _NOT_ account for the leaf nodes themselves.
func CalcTreeTxs(nbLeafs int) int {
	// Simulate the tree building algo to figure out the total nb of txs.
	var stack, totalTxs int
	stack = nbLeafs
	for stack > 1 {
		totalTxs += stack / 2
		stack = (stack / 2) + (stack % 2)
	}
	return totalTxs
}

func CalcMaxTreeDepth(nbLeafs int) int {
	nbLevels := 33 - bits.LeadingZeros32(uint32(nbLeafs-1))
	return nbLevels
}
