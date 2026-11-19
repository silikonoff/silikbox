#!/usr/bin/env bash
set -euo pipefail
export GOBIND=gobind-matsuri
pushd ../third_party/gomobile
GOTOOLCHAIN=go1.25.5 go install ./cmd/gomobile ./cmd/gobind
popd
GOPATH=${GOPATH:-$(go env GOPATH)}
cp "$GOPATH/bin/gomobile" "$GOPATH/bin/gomobile-matsuri"
cp "$GOPATH/bin/gobind" "$GOPATH/bin/gobind-matsuri"
mkdir -p "$GOPATH/pkg/gomobile"
