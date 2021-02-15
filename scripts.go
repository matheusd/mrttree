package mrttree

import (
	"math"

	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/txscript/v3"
	"github.com/decred/dcrd/wire"
)

// nodeScript generates the PKScript required to redeem a node of the MRTTREE.
//
//     DUP HASH160 DUP [immediate-key-hash] EQUAL
//     IF
//       DROP
//     ELSE
//       DUP [short-key-hash] EQUAL
//       IF
//         DROP [short-csv]
//       ELSE
//         DUP [medium-key-hash] EQUAL
//         IF
//           DROP [medium-csv]
//         ELSE
//           DUP [long-key-hash] EQUALVERIFY
//           [long-csv]
//         ENDIF
//       ENDIF
//       CHECKSEQUENCEVERIFY DROP
//     ENDIF
//     [schnorr-sig-type] CHECKSIGALT
func nodeScript(longKey, mediumKey, shortKey, immediateKey *secp256k1.PublicKey,
	longLockTime, mediumLockTime, shortLockTime uint32) ([]byte, error) {

	var b txscript.ScriptBuilder

	shortKeyHash := dcrutil.Hash160(shortKey.SerializeCompressed())
	mediumKeyHash := dcrutil.Hash160(mediumKey.SerializeCompressed())
	longKeyHash := dcrutil.Hash160(longKey.SerializeCompressed())
	immediateKeyHash := dcrutil.Hash160(immediateKey.SerializeCompressed())

	b.AddOp(txscript.OP_DUP)
	b.AddOp(txscript.OP_HASH160)
	b.AddOp(txscript.OP_DUP)
	b.AddData(immediateKeyHash)
	b.AddOp(txscript.OP_EQUAL)

	b.AddOp(txscript.OP_IF)
	b.AddOp(txscript.OP_DROP)

	b.AddOp(txscript.OP_ELSE)
	b.AddOp(txscript.OP_DUP)
	b.AddData(shortKeyHash)
	b.AddOp(txscript.OP_EQUAL)

	b.AddOp(txscript.OP_IF)
	b.AddOp(txscript.OP_DROP)
	b.AddInt64(int64(shortLockTime))

	b.AddOp(txscript.OP_ELSE)
	b.AddOp(txscript.OP_DUP)
	b.AddData(mediumKeyHash)
	b.AddOp(txscript.OP_EQUAL)

	b.AddOp(txscript.OP_IF)
	b.AddOp(txscript.OP_DROP)
	b.AddInt64(int64(mediumLockTime))

	b.AddOp(txscript.OP_ELSE)
	b.AddOp(txscript.OP_DUP)
	b.AddData(longKeyHash)
	b.AddOp(txscript.OP_EQUALVERIFY)
	b.AddInt64(int64(longLockTime))
	b.AddOp(txscript.OP_ENDIF)
	b.AddOp(txscript.OP_ENDIF)

	b.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	b.AddOp(txscript.OP_DROP)
	b.AddOp(txscript.OP_ENDIF)

	b.AddInt64(int64(dcrec.STSchnorrSecp256k1))
	b.AddOp(txscript.OP_CHECKSIGALT)

	return b.Script()
}

func payToScriptHashScript(script []byte) []byte {
	scriptHash := dcrutil.Hash160(script)
	res := []byte{
		0:  txscript.OP_HASH160,
		1:  txscript.OP_DATA_20,
		22: txscript.OP_EQUAL,
	}
	copy(res[2:22], scriptHash)
	return res
}

func calcNodeTxFee(feeRate dcrutil.Amount) int64 {
	// Really crappy way to determine the fee, by creating a full tx.
	//
	// TODO: hardcode size, etc.
	var zeroKey secp256k1.PublicKey
	var sig [65]byte
	var pk [33]byte
	maxLT := uint32(math.MaxUint32)
	redeemScript, err := nodeScript(&zeroKey, &zeroKey, &zeroKey, &zeroKey,
		maxLT, maxLT, maxLT)
	if err != nil {
		panic(err)
	}

	var b txscript.ScriptBuilder
	sigScript, err := b.AddData(sig[:]).AddData(pk[:]).AddData(redeemScript[:]).Script()
	if err != nil {
		panic(err)
	}

	tx := wire.MsgTx{
		TxIn: []*wire.TxIn{
			{SignatureScript: sigScript},
		},
		TxOut: []*wire.TxOut{
			{PkScript: make([]byte, 23)},
			{PkScript: make([]byte, 23)},
		},
	}

	txSize := tx.SerializeSize()
	fee := int64(txSize) * int64(feeRate) / 1000
	return fee
}

func calcLeafRedeemTxFee(feeRate dcrutil.Amount) int64 {
	// Really crappy way to determine the fee, by creating a full tx.
	//
	// TODO: hardcode size, etc.
	var zeroKey secp256k1.PublicKey
	var sig [65]byte
	var pk [33]byte
	maxLT := uint32(math.MaxUint32)
	redeemScript, err := nodeScript(&zeroKey, &zeroKey, &zeroKey, &zeroKey,
		maxLT, maxLT, maxLT)
	if err != nil {
		panic(err)
	}

	var b txscript.ScriptBuilder
	sigScript, err := b.AddData(sig[:]).AddData(pk[:]).AddData(redeemScript[:]).Script()
	if err != nil {
		panic(err)
	}

	tx := wire.MsgTx{
		TxIn: []*wire.TxIn{
			{SignatureScript: sigScript},
		},
		TxOut: []*wire.TxOut{
			{PkScript: make([]byte, 25)},
		},
	}
	txSize := tx.SerializeSize()
	fee := int64(txSize) * int64(feeRate) / 1000
	return fee
}
