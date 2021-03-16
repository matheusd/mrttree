package client

import (
	"fmt"

	"decred.org/mrttree"
	"decred.org/mrttree/api"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrutil/v3"
)

func buildTree(joinRes *api.JoinSessionResponse, keysRes *api.RevealLeafKeysResponse) (*mrttree.Tree, error) {
	nbLeafs := len(joinRes.UserPkHashes)
	leafs := make([]mrttree.ProposedLeaf, nbLeafs)
	for i := 0; i < nbLeafs; i++ {
		userKey, err := secp256k1.ParsePubKey(keysRes.UserKeys[i])
		if err != nil {
			return nil, err
		}
		providerKey, err := secp256k1.ParsePubKey(keysRes.ProviderKeys[i])
		if err != nil {
			return nil, err
		}
		leafs[i] = mrttree.ProposedLeaf{
			Amount:      dcrutil.Amount(joinRes.LeafAmount),
			ProviderKey: *providerKey,
			UserKey:     *userKey,
		}
	}

	prefundInputs, err := api.UnmarshalInputs(keysRes.PrefundInputs)
	if err != nil {
		return nil, err
	}

	changeKey, err := secp256k1.ParsePubKey(joinRes.ChangeKey)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	return tree, nil
}

func verifySignedTree(tree *mrttree.Tree, noncesRes *api.RevealNoncesResponse,
	sigsRes *api.SignedTreeResponse) error {

	treeNonces := api.UnmarshalMapByteSlices(noncesRes.TreeNonces)
	err := tree.FillTreeSignatures(treeNonces, sigsRes.TreeSignatures)
	if err != nil {
		return err
	}

	err = tree.VerifyFundSignaturePub(noncesRes.FundNonces, sigsRes.FundSignaturePub)
	if err != nil {
		return fmt.Errorf("unable to verify fund sig pub: %v", err)
	}

	return tree.VerifyTreeSignatures()
}

func fillFundSig(tree *mrttree.Tree, noncesRes *api.RevealNoncesResponse, fundSig []byte) error {
	if err := tree.FillFundSignature(noncesRes.FundNonces, fundSig); err != nil {
		return err
	}

	if err := tree.VerifyFundSignature(); err != nil {
		return err
	}

	return nil
}
