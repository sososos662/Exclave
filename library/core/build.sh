#!/bin/bash

# fronting fork: fetch our Go modules straight from git (no proxy lag).
export GOPRIVATE=github.com/sososos662/*
# NOTE: GOFLAGS must NOT stay exported: gomobile's internal tidy breaks.
# Record missing go.sum entries explicitly, then unset.
export GOFLAGS=-mod=mod
go mod tidy
unset GOFLAGS


CGO_LDFLAGS="-Wl,-z,max-page-size=16384" gomobile bind -v -androidapi 21 -trimpath -ldflags="-s -buildid=" -tags="with_clash" "github.com/exclavenetwork/libexclavecore" || exit 1

proj=../../app/libs
if [ -d $proj ]; then
  cp -vf libexclavecore.aar $proj
fi
