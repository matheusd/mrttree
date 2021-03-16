package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"decred.org/mrttree/api"
	"decred.org/mrttree/client"

	"github.com/decred/dcrlnd/lnrpc"
	"github.com/decred/dcrlnd/lnrpc/walletrpc"
	"github.com/decred/dcrlnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	macaroon "gopkg.in/macaroon.v2"
)

func connectToMrttreeSvr(ctx context.Context, cfg *config) (api.MrttreeClient, error) {
	opts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithInsecure(),
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, cfg.Server, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to server '%s': %v",
			cfg.Server, err)
	}

	apiClient := api.NewMrttreeClient(conn)

	return apiClient, nil
}

func connectToDcrlnd(ctx context.Context, cfg *config) (client.LNAdapter, error) {

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

	lnClient := lnrpc.NewLightningClient(conn)
	walletClient := walletrpc.NewWalletKitClient(conn)

	lnAdapter := struct {
		lnrpc.LightningClient
		walletrpc.WalletKitClient
	}{
		LightningClient: lnClient,
		WalletKitClient: walletClient,
	}

	return lnAdapter, nil
}

func _main() error {
	cfg, args, err := loadConfig()
	if err != nil {
		return err
	}

	ctx := shutdownListener()

	arg := func(i int) string {
		if len(args) > i {
			return args[i]
		}
		return ""
	}

	action := arg(0)

	switch action {
	case "join":
		sessID, err := hex.DecodeString(arg(1))
		if err != nil {
			return fmt.Errorf("invalid session ID: %v", err)
		}

		apiClient, err := connectToMrttreeSvr(ctx, cfg)
		if err != nil {
			return err
		}

		lnClient, err := connectToDcrlnd(ctx, cfg)
		if err != nil {
			return err
		}

		cliCfg := &client.JoinSessionCfg{
			APIClient: apiClient,
			LNClient:  lnClient,
			SessionID: sessID,
			SampleDir: cfg.SampleDir,
		}
		return client.JoinSession(ctx, cliCfg)
	case "redeem":
		sessID, err := hex.DecodeString(arg(1))
		if err != nil {
			return fmt.Errorf("invalid session ID: %v", err)
		}

		privKey, err := hex.DecodeString(arg(2))
		if err != nil {
			return fmt.Errorf("invalid priv key: %v", err)
		}

		apiClient, err := connectToMrttreeSvr(ctx, cfg)
		if err != nil {
			return err
		}

		lnClient, err := connectToDcrlnd(ctx, cfg)
		if err != nil {
			return err
		}

		cliCfg := &client.RedeemLeafCfg{
			APIClient:    apiClient,
			LNClient:     lnClient,
			SessionID:    sessID,
			PrivKeyBytes: privKey,
		}
		return client.RedeemLeaf(ctx, cliCfg)

	case "":
		return errors.New("No action specified (join)")
	}

	return fmt.Errorf("Unrecognized action (%s)", action)
}

func main() {
	if err := _main(); err != nil && !errors.Is(err, errCmdDone) {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
