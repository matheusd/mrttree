package mrttree

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/wire"
)

func addPubKeys(p1, p2 *secp256k1.PublicKey) secp256k1.PublicKey {
	var pj1, pj2, res secp256k1.JacobianPoint
	p1.AsJacobian(&pj1)
	p2.AsJacobian(&pj2)
	secp256k1.AddNonConst(&pj1, &pj2, &res)
	res.ToAffine()
	resp := secp256k1.NewPublicKey(&res.X, &res.Y)
	return *resp
}

func sumInputAmounts(ins []*wire.TxIn) int64 {
	var sum int64
	for _, in := range ins {
		sum += in.ValueIn
	}
	return sum
}
