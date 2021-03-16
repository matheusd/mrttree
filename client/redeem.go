package client

import (
	"context"

	"decred.org/mrttree/api"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrlnd/lnrpc"
)

type RedeemLeafCfg struct {
	APIClient    api.MrttreeClient
	LNClient     LNAdapter
	SessionID    []byte
	PrivKeyBytes []byte
}

func (c *RedeemLeafCfg) run(ctx context.Context) error {
	// Add the invoice in the local LN node.
	invoice := &lnrpc.Invoice{
		Memo:      "MRTTREE leaf redeem",
		RPreimage: c.PrivKeyBytes,
		IsPtlc:    true,
		// TODO: also track amount.
	}
	invoiceRes, err := c.LNClient.AddInvoice(ctx, invoice)
	if err != nil {
		return err
	}

	priv := secp256k1.PrivKeyFromBytes(c.PrivKeyBytes)
	pub := priv.PubKey()

	// Send it to the server and ask it to redeem that leaf.
	redeemReq := api.RedeemLeafRequest{
		SessionToken: c.SessionID,
		LnPayReq:     invoiceRes.PaymentRequest,
		LeafPub:      pub.SerializeCompressed(),
	}
	_, err = c.APIClient.RedeemLeaf(ctx, &redeemReq)
	if err != nil {
		return err
	}

	log.Infof("Redeemed leaf pub %x", pub.SerializeCompressed())

	return nil
}

func RedeemLeaf(ctx context.Context, cfg *RedeemLeafCfg) error {
	return cfg.run(ctx)
}
