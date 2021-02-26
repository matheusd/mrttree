#!/usr/bin/env sh

build_protoc_gen_go() {

    echo "Install protoc-gen-go"
    mkdir -p bin
    export GOBIN=$PWD/bin
    go build .
    go install github.com/golang/protobuf/protoc-gen-go

}

generate() {

    PROTOSVERSION=$(go list -m all | grep "github.com/matheusd/google-protobuf-protos" | sed 's/ /@/' -)
    PROTOBUFAPIS="$GOPATH/pkg/mod/$PROTOSVERSION"

    echo "Generating root gRPC server protos"

    PROTOS="*.proto"

    # For each of the sub-servers, we then generate their protos, but a restricted
    # set as they don't yet require REST proxies, or swagger docs.
    for file in $PROTOS; do
      DIRECTORY=$(dirname "${file}")
      echo "Generating protos from ${file}, into ${DIRECTORY}"

      # Generate the protos.
      protoc -I. \
        -I$PROTOBUFAPIS \
        --go_out=plugins=grpc,paths=source_relative:. \
        "${file}"
    done
}

(cd tools && build_protoc_gen_go)
PATH=$PWD/tools/bin:$PATH generate

rm -rf tools/bin
