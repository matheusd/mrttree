package mrttree

import (
	"math"

	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrec/secp256k1/v3/schnorr"
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
//       [locked-key-hash] EQUALVERIFY
//       [locktime] CHECKSEQUENCEVERIFY DROP
//     ENDIF
//     [schnorr-sig-type] CHECKSIGALT
func nodeScript(lockedKey, immediateKey *secp256k1.PublicKey,
	lockTime uint32) ([]byte, error) {

	var b txscript.ScriptBuilder

	immediateKeyHash := dcrutil.Hash160(immediateKey.SerializeCompressed())
	lockedKeyHash := dcrutil.Hash160(lockedKey.SerializeCompressed())

	b.AddOp(txscript.OP_DUP)
	b.AddOp(txscript.OP_HASH160)
	b.AddOp(txscript.OP_DUP)
	b.AddData(immediateKeyHash)
	b.AddOp(txscript.OP_EQUAL)

	b.AddOp(txscript.OP_IF)
	b.AddOp(txscript.OP_DROP)

	b.AddOp(txscript.OP_ELSE)
	b.AddData(lockedKeyHash)
	b.AddOp(txscript.OP_EQUALVERIFY)
	b.AddInt64(int64(lockTime))
	b.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	b.AddOp(txscript.OP_DROP)
	b.AddOp(txscript.OP_ENDIF)

	b.AddInt64(int64(dcrec.STSchnorrSecp256k1))
	b.AddOp(txscript.OP_CHECKSIGALT)

	return b.Script()
}

// fundScript returns the script that binds the funding output in the prefund
// transaction.
//
//     DUP HASH160 DUP [fund key hash] EQUAL
//     IF
//         DROP
//     ELSE
//        [change key hash] EQUALVERIFY
//        [locktime] CHECKSEQUENCEVERIFY DROP
//     ENDIF
//     [schnorr sig type] CHECKSIGALT
func fundScript(fundKey, changeKey *secp256k1.PublicKey, lockTime uint32) ([]byte, error) {
	var b txscript.ScriptBuilder

	fundKeyHash := dcrutil.Hash160(fundKey.SerializeCompressed())
	changeKeyHash := dcrutil.Hash160(changeKey.SerializeCompressed())

	b.AddOp(txscript.OP_DUP)
	b.AddOp(txscript.OP_HASH160)
	b.AddOp(txscript.OP_DUP)
	b.AddData(fundKeyHash)
	b.AddOp(txscript.OP_EQUAL)

	b.AddOp(txscript.OP_IF)
	b.AddOp(txscript.OP_DROP)

	b.AddOp(txscript.OP_ELSE)
	b.AddData(changeKeyHash)
	b.AddInt64(int64(lockTime))
	b.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	b.AddOp(txscript.OP_DROP)

	b.AddOp(txscript.OP_ENDIF)

	b.AddInt64(int64(dcrec.STSchnorrSecp256k1))
	b.AddOp(txscript.OP_CHECKSIGALT)

	return b.Script()
}

// sigAndScriptSigScript generates a signature script for fullfilling any sort
// of script that consists only of <schnorr-sig> <public key> <redeem script>.
func sigAndScriptSigScript(sig *schnorr.Signature, key *secp256k1.PublicKey, redeemScript []byte) ([]byte, error) {
	var b txscript.ScriptBuilder
	keyBytes := key.SerializeCompressed()
	sigBytes := sig.Serialize()
	sigBytes = append(sigBytes, byte(txscript.SigHashAll))
	b.AddData(sigBytes).AddData(keyBytes).AddData(redeemScript)
	return b.Script()
}

func nodeSigScript(sig *schnorr.Signature, key *secp256k1.PublicKey, redeemScript []byte) ([]byte, error) {
	return sigAndScriptSigScript(sig, key, redeemScript)
}

func fundSigScript(sig *schnorr.Signature, key *secp256k1.PublicKey, redeemScript []byte) ([]byte, error) {
	return sigAndScriptSigScript(sig, key, redeemScript)
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

func payToPubKeyHashScript(pubkey *secp256k1.PublicKey) []byte {
	serKey := pubkey.SerializeCompressed()
	keyHash := dcrutil.Hash160(serKey)
	res := []byte{
		0:  txscript.OP_DUP,
		1:  txscript.OP_HASH160,
		2:  txscript.OP_DATA_20,
		23: txscript.OP_EQUALVERIFY,
		24: txscript.OP_CHECKSIG,
	}
	copy(res[3:23], keyHash)
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
	redeemScript, err := nodeScript(&zeroKey, &zeroKey, maxLT)
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

func CalcNodeTxFee(feeRate dcrutil.Amount) dcrutil.Amount {
	return dcrutil.Amount(calcNodeTxFee(feeRate))
}

func calcLeafRedeemTxFee(feeRate dcrutil.Amount) int64 {
	// Really crappy way to determine the fee, by creating a full tx.
	//
	// TODO: hardcode size, etc.
	var zeroKey secp256k1.PublicKey
	var sig [65]byte
	var pk [33]byte
	maxLT := uint32(math.MaxUint32)
	redeemScript, err := nodeScript(&zeroKey, &zeroKey, maxLT)
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

func calcFundTxFee(feeRate dcrutil.Amount, nbAdditionalP2PKHIns int) int64 {
	return 40000 // TODO: implement
}

func CalcFundTxFee(feeRate dcrutil.Amount, nbAdditionalP2PKHIns int) dcrutil.Amount {
	return dcrutil.Amount(calcFundTxFee(feeRate, nbAdditionalP2PKHIns))
}

func calcPrefundTxFee(feeRate dcrutil.Amount, nbP2PKHIns int) int64 {
	return 40000 // TODO: implement
}

func CalcPrefundTxFee(feeRate dcrutil.Amount, nbP2PKHIns int) dcrutil.Amount {
	return dcrutil.Amount(calcPrefundTxFee(feeRate, nbP2PKHIns))
}
