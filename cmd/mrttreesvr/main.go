package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	"decred.org/mrttree"
	"decred.org/mrttree/api"
	"decred.org/mrttree/cmd/internal/version"
	"decred.org/mrttree/server"

	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/txscript/v3"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrlnd/lnrpc"
	"github.com/decred/dcrlnd/lnrpc/signrpc"
	"github.com/decred/dcrlnd/lnrpc/walletrpc"
	"github.com/decred/dcrlnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	macaroon "gopkg.in/macaroon.v2"
)

const sampleNbLeafs = 8

var (
	testChangePriv = secp256k1.PrivKeyFromBytes([]byte{0x01, 0x02, 0x03, 0x04})
	testChangePub  = testChangePriv.PubKey()
)

type runnable interface {
	Run(ctx context.Context) error
}

func run(r runnable, ctx context.Context, wg *sync.WaitGroup, name string) {
	wg.Add(1)
	go func() {
		err := r.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Errorf("Error running %s: %v", name, err)
		}
		wg.Done()
	}()
}

func runGrpcServer(ctx context.Context, wg *sync.WaitGroup, svr *server.Server,
	lis net.Listener) {

	opts := []grpc.ServerOption{}
	grpcSvr := grpc.NewServer(opts...)
	api.RegisterMrttreeServer(grpcSvr, svr)

	wg.Add(1)
	go func() {
		log.Infof("Running gRPC server on %s", lis.Addr())
		err := grpcSvr.Serve(lis)
		if err != nil {
			log.Errorf("gRPC serve error: %v", err)
		}
		wg.Done()
	}()
	go func() {
		<-ctx.Done()
		grpcSvr.GracefulStop()
	}()
}

func connectToDcrlnd(ctx context.Context, cfg *config) (*grpc.ClientConn, error) {

	// First attempt to establish a connection to lnd's RPC sever.
	tlsCertPath := cleanAndExpandPath(cfg.DcrlndOpts.TLSCertPath)
	creds, err := credentials.NewClientTLSFromFile(tlsCertPath, "")
	if err != nil {
		return nil, fmt.Errorf("unable to read cert file: %v", err)
	}

	// Load the specified macaroon file.
	macPath := cleanAndExpandPath(cfg.DcrlndOpts.MacaroonPath)
	macBytes, err := ioutil.ReadFile(macPath)
	if err != nil {
		return nil, err
	}
	mac := &macaroon.Macaroon{}
	if err = mac.UnmarshalBinary(macBytes); err != nil {
		return nil, err
	}

	opts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithTransportCredentials(creds),
		grpc.WithPerRPCCredentials(macaroons.NewMacaroonCredential(mac)),
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	host := cfg.DcrlndOpts.Host
	conn, err := grpc.DialContext(ctx, host, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to dcrlnd '%s': %v",
			host, err)
	}

	return conn, nil
}

func setupServer(ctx context.Context, cfg *config) (*server.Server, error) {
	conn, err := connectToDcrlnd(ctx, cfg)
	if err != nil {
		return nil, err
	}

	chainParams := cfg.chainParams()
	tempPriv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	tempPub := tempPriv.PubKey()
	tempPubHash := dcrutil.Hash160(tempPub.SerializeCompressed())
	tempAddr, err := dcrutil.NewAddressPubKeyHash(tempPubHash, chainParams, dcrec.STEcdsaSecp256k1)
	if err != nil {
		return nil, err
	}
	tempScript, err := txscript.PayToAddrScript(tempAddr)
	if err != nil {
		return nil, err
	}

	lnClient := lnrpc.NewLightningClient(conn)
	walletClient := walletrpc.NewWalletKitClient(conn)

	svrCfg, err := cfg.serverConfig()
	if err != nil {
		return nil, err
	}

	// Handle the provider as if it were another user.
	user := mrttree.NewTestUser(nil, "provider", 0x99123192, sampleNbLeafs)
	svrCfg.ChangeKeySourcer = func(ctx context.Context) (*secp256k1.PublicKey, error) {
		return testChangePub, nil
	}

	svrCfg.TreeKeySourcer = func(ctx context.Context, nbLeafs int) ([]*secp256k1.PublicKey, error) {
		keys := make([]*secp256k1.PublicKey, nbLeafs)
		for i := range keys {
			keys[i], _ = secp256k1.ParsePubKey(user.Keys[i])
		}
		return keys, nil
	}

	svrCfg.TreeNoncer = func(ctx context.Context, tree *mrttree.Tree) (map[uint32][][]byte, [][]byte, error) {
		err := user.GenerateNonces(tree)
		return user.TreeNonces, user.FundNonces, err
	}

	svrCfg.TreeSigner = func(ctx context.Context, tree *mrttree.Tree, allNonces map[uint32][][]byte, allFundNonces [][]byte) (map[uint32][][]byte, [][]byte, error) {
		err := user.SignTree(allNonces, allFundNonces)
		return user.TreeSigs, user.FundSigs, err
	}

	svrCfg.InputSourcer = func(ctx context.Context, amount dcrutil.Amount) ([]*wire.TxIn, error) {
		// Send to the intermediate key so we can have an input.
		//
		// TODO: skip this step and do it directly.
		tempAmount := int64(amount) + 1e5
		sendOutReq := &walletrpc.SendOutputsRequest{
			AtomsPerKb: 1e4,
			Outputs: []*signrpc.TxOut{
				{Value: tempAmount, PkScript: tempScript},
			},
		}
		sendOutRes, err := walletClient.SendOutputs(ctx, sendOutReq)
		if err != nil {
			return nil, err
		}
		tempTx := wire.NewMsgTx()
		if err := tempTx.FromBytes(sendOutRes.RawTx); err != nil {
			return nil, err
		}

		tempTxh := tempTx.TxHash()
		outp := wire.NewOutPoint(&tempTxh, 0, 0)

		// Figure out which output is the one we want, since the wallet
		// randomizes it.
		for i, out := range tempTx.TxOut {
			if out.Value == tempAmount {
				outp.Index = uint32(i)
				break
			}
		}

		log.Infof("Creating temp output %s for prefund tx", outp)

		ins := []*wire.TxIn{
			wire.NewTxIn(outp, tempAmount, nil),
		}
		return ins, nil
	}

	svrCfg.InputReleaser = func(ctx context.Context, inputs []*wire.TxIn) error {
		return nil
	}

	svrCfg.PrefundSigner = func(ctx context.Context, prefundTx *wire.MsgTx) error {
		sigScript, err := txscript.SignatureScript(
			prefundTx, 0, tempScript,
			txscript.SigHashAll, tempPriv.Serialize(),
			dcrec.STEcdsaSecp256k1, true)
		if err != nil {
			return err
		}
		prefundTx.TxIn[0].SignatureScript = sigScript
		return nil
	}

	svrCfg.TxPublisher = func(ctx context.Context, tx *wire.MsgTx) error {
		rawtx, err := tx.Bytes()
		if err != nil {
			return err
		}
		req := &walletrpc.Transaction{
			TxHex: rawtx,
		}
		res, err := walletClient.PublishTransaction(ctx, req)
		if err != nil {
			log.Infof("XXXXXX %x", rawtx)
			return err
		}
		if res.PublishError != "" {
			return fmt.Errorf("publish error: %s", res.PublishError)
		}
		return nil
	}

	svrCfg.TreeRedeemer = func(ctx context.Context, tree *mrttree.Tree, allUserKeys [][]byte) error {
		addrRes, err := walletClient.NextAddr(ctx, &walletrpc.AddrRequest{})
		if err != nil {
			return err
		}
		addr, err := dcrutil.DecodeAddress(addrRes.Addr, chainParams)
		if err != nil {
			return err
		}
		returnScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return err
		}

		tx, err := user.RedeemNode(tree.Root, allUserKeys, returnScript)
		if err != nil {
			return err
		}

		if err = svrCfg.TxPublisher(ctx, tx); err != nil {
			return err
		}

		log.Infof("Published redeem tx %s", tx.TxHash())
		return nil
	}

	svrCfg.TxFeeRate = 1e4
	svrCfg.Rand = rand.New(rand.NewSource(0x81234567))
	svrCfg.LNClient = lnClient

	svr, err := server.NewServer(svrCfg)
	if err != nil {
		return nil, err
	}

	return svr, nil
}

func _main() error {
	cfg, _, err := loadConfig()
	if err != nil {
		return err
	}

	ctx := shutdownListener()
	wg := new(sync.WaitGroup)

	defer func() {
		<-ctx.Done()
		log.Debugf("Main context closed, waiting all goroutines to finish")
		wg.Wait()
	}()

	log.Infof("Initing mrttree server v%s", version.String())

	svr, err := setupServer(ctx, cfg)
	if err != nil {
		requestShutdown()
		return err
	}

	listeners, err := cfg.listeners()
	if err != nil {
		requestShutdown()
		return err
	}

	run(svr, ctx, wg, "server")

	for _, lis := range listeners {
		lis := lis
		runGrpcServer(ctx, wg, svr, lis)
	}

	// Initialize a sample session.
	time.Sleep(time.Second)
	leafAmount := dcrutil.Amount(1e4)
	lockTime := uint32(6)
	initialLockTime := uint32(244 * 7)
	sessID, err := svr.NewSession(sampleNbLeafs, leafAmount, lockTime,
		initialLockTime)
	if err != nil {
		requestShutdown()
		return err
	}
	sessIDHex := []byte(fmt.Sprintf("%x", sessID))
	ioutil.WriteFile("/tmp/mrttree-sample-session", sessIDHex, 0644)
	log.Infof("Sample session: %x", sessID)

	return nil
}

func main() {
	if err := _main(); err != nil && !errors.Is(err, errCmdDone) {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
