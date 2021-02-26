package server

import (
	"context"
	"io"
	"math/rand"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/txscript/v3"
)

const (
	testScriptFlags = txscript.ScriptDiscourageUpgradableNops |
		txscript.ScriptVerifyCheckLockTimeVerify |
		txscript.ScriptVerifyCheckSequenceVerify |
		txscript.ScriptVerifyCleanStack |
		txscript.ScriptVerifySigPushOnly |
		txscript.ScriptVerifySHA256 |
		txscript.ScriptVerifyTreasury
)

// defaultTimeout is the default timeout for test contexts.
const defaultTimeout = time.Second * 30

// timeoutCtx returns a context that gets canceled after the specified time or
// after the test ends.
func timeoutCtx(t *testing.T, timeout time.Duration) context.Context {
	ctxt, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	return ctxt
}

// testCtx returns a context that gets canceled after defaultTimeout or after
// the test ends.
func testCtx(t *testing.T) context.Context {
	return timeoutCtx(t, defaultTimeout)
}

func mustRead(b []byte, r io.Reader) {
	n, err := r.Read(b)
	if err != nil {
		panic(err)
	}
	if n != len(b) {
		panic("wrong nb of bytes read")
	}
}

func randKey(rnd *rand.Rand) *secp256k1.PrivateKey {
	var k [32]byte
	_, err := rnd.Read(k[:])
	if err != nil {
		panic(err)
	}
	pk := secp256k1.PrivKeyFromBytes(k[:])
	return pk
}
