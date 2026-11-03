// SPDX-License-Identifier: AGPL-3.0-only

//go:build generate

// Package tools pins this module's code generators and holds its one generate path.
// Run it from the module root:
//
//	go generate ./tools
//
// THE PLUGINS ARE THE PINNED ONES, NEVER WHATEVER IS ON PATH. Each go:generate line below
// builds a plugin at the version go.mod requires into bin/ (git-ignored), and protoc is
// pointed at those binaries with --plugin. A protoc-gen-go found on PATH is never used: its
// version is written into every generated header, so output would differ from machine to
// machine.
//
// PROTOC ITSELF CANNOT BE PINNED THROUGH GO MODULES. The committed files were generated with
// the release named by generatedWithProtoc in pkg/keyset/keysetpb/drift_test.go, and every
// generated header records it. That test regenerates through these exact lines and compares
// the output byte for byte.
//
// CONSUMERS NEVER RUN THIS. The generated code is committed, and a consumer fetches a tag from
// the public module proxy (D26).
//
// WHY THE generate BUILD TAG. It is the tag go generate sets for itself, so the command above
// needs no flag. No build ever compiles this file, and none could, since it imports two main
// packages. go mod tidy honours every tag, so these imports keep the plugins pinned in go.mod.
package tools

import (
	_ "google.golang.org/grpc/cmd/protoc-gen-go-grpc"
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"
)

//go:generate go build -o ../bin/protoc-gen-go google.golang.org/protobuf/cmd/protoc-gen-go
//go:generate go build -o ../bin/protoc-gen-go-grpc google.golang.org/grpc/cmd/protoc-gen-go-grpc
//go:generate protoc --plugin=protoc-gen-go=../bin/protoc-gen-go --plugin=protoc-gen-go-grpc=../bin/protoc-gen-go-grpc --proto_path=../proto --go_out=.. --go_opt=module=github.com/abylora/shared --go-grpc_out=.. --go-grpc_opt=module=github.com/abylora/shared ../proto/abylora/keyset/v1/keyset.proto
