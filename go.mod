module decred.org/mrttree

go 1.15

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd v1.2.1-0.20210121192504-91b84e06447e
	github.com/decred/dcrd/chaincfg/chainhash v1.0.2
	github.com/decred/dcrd/chaincfg/v3 v3.0.0
	github.com/decred/dcrd/crypto/blake256 v1.0.0
	github.com/decred/dcrd/dcrec v1.0.0
	github.com/decred/dcrd/dcrec/secp256k1/v3 v3.0.0
	github.com/decred/dcrd/dcrutil/v3 v3.0.0
	github.com/decred/dcrd/rpcclient/v6 v6.0.2
	github.com/decred/dcrd/txscript/v3 v3.0.0
	github.com/decred/dcrd/wire v1.4.0
	github.com/decred/dcrlnd v0.3.1
	github.com/decred/slog v1.1.0
	github.com/golang/protobuf v1.4.2
	github.com/golang/snappy v0.0.3-0.20201103224600-674baa8c7fc3 // indirect
	github.com/google/go-cmp v0.5.2 // indirect
	github.com/jessevdk/go-flags v1.4.1-0.20200711081900-c17162fe8fd7
	github.com/jrick/logrotate v1.0.0
	github.com/kr/pretty v0.2.0 // indirect
	github.com/matheusd/google-protobuf-protos v0.0.0-20200707194502-ef6ec5c2266f
	github.com/stretchr/testify v1.7.0
	google.golang.org/grpc v1.33.1
	google.golang.org/protobuf v1.25.0
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/macaroon.v2 v2.0.0
)

replace github.com/decred/dcrlnd => github.com/matheusd/dcrlnd v0.3.2-0.20210316123949-116ed688a103
