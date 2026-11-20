#!/bin/sh
# Regenerates the root helper's gRPC code from rootd.proto and records a
# checksum of the three files, which TestGeneratedCodeIsCurrent compares
# (make test needs no protoc). Run through `make rootd-proto`.
#
# protoc-gen-go is built from go.mod's google.golang.org/protobuf, so the
# generated code always matches the runtime library it links against;
# protoc-gen-go-grpc is pinned here.
set -eu
cd "$(dirname "$0")"
GRPC_GEN_VERSION=v1.6.2

bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT
go build -o "$bin/protoc-gen-go" google.golang.org/protobuf/cmd/protoc-gen-go
GOBIN="$bin" go install "google.golang.org/grpc/cmd/protoc-gen-go-grpc@$GRPC_GEN_VERSION"

protoc \
	--plugin=protoc-gen-go="$bin/protoc-gen-go" \
	--plugin=protoc-gen-go-grpc="$bin/protoc-gen-go-grpc" \
	--go_out=. --go_opt=paths=source_relative \
	--go-grpc_out=. --go-grpc_opt=paths=source_relative \
	rootd.proto

# The generated headers name the protoc that made them. Drop that line so
# any protoc that produces the same code passes rootd-proto-check.
for f in rootd.pb.go rootd_grpc.pb.go; do
	grep -v -E '^//[[:space:]]+(- )?protoc[[:space:]]+v[0-9]' "$f" >"$bin/$f"
	mv "$bin/$f" "$f"
done

if command -v sha256sum >/dev/null 2>&1; then
	sha256sum rootd.proto rootd.pb.go rootd_grpc.pb.go >rootd.sum
else
	shasum -a 256 rootd.proto rootd.pb.go rootd_grpc.pb.go >rootd.sum
fi
