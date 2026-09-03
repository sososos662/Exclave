#!/bin/bash

# fronting fork: fetch our Go modules straight from git (no proxy lag),
# allow go to record their hashes without sumdb
export GOPRIVATE=github.com/sososos662/*
export GOFLAGS=-mod=mod


CGO_LDFLAGS="-Wl,-z,max-page-size=16384" gomobile bind -v -androidapi 21 -trimpath -ldflags="-s -buildid=" -tags="with_clash" "github.com/exclavenetwork/libexclavecore" || exit 1

proj=../../app/libs
if [ -d $proj ]; then
  cp -vf libexclavecore.aar $proj
fi
