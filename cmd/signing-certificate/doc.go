// SPDX-License-Identifier: AGPL-3.0-only

// Command signing-certificate writes the relay list's signing certificate for the ceremony:
// exactly the octets github.com/abylora/shared/pkg/signingcert.Encode returns, with no trailing
// newline, to stdout or to --out. It is <workspace>/docs/contracts/relay-list.md, The ceremony
// step that logs the root's signature, step 0: the certificate body is produced only by Encode,
// never written by hand. sigsum-submit -k then signs those octets, on the same air-gapped
// machine.
//
//	signing-certificate --signing-public-key signing.pub --root-public-key root.pub \
//	  --env staging --not-before 2026-01-01T00:00:00Z --not-after 2026-04-01T00:00:00Z \
//	  --out signing-certificate.json
//
// ON SUCCESS IT WRITES THE CERTIFICATE AND NOTHING ELSE: the --out file, or the octets on stdout
// when there is no --out. stderr is empty, so nothing can be mistaken for part of the
// certificate. On a refusal it exits non-zero and stderr names the refusal by its sentinel's
// message -- a weak key as signingcert.ErrKeyWeak's.
//
// ENCODE IS THE ONLY PRODUCER, AND EVERY CERTIFICATE RULE IS ENCODE'S. The environment, the
// weak-key refusal, the self-certificate, encodable instants and a non-empty window are refused
// by Encode, by its own sentinel. This command checks input syntax only: the flags, the
// timestamps' exact text, and the key files' format. It never imports encoding/json.
//
// PUBLIC KEY FILES ONLY. Both keys are read from sigsum's own .pub files, as sigsum-key wrote
// them: "ssh-ed25519 ", the base64 key blob, an optional comment, one line, at most 4 KiB. The
// root's fingerprint is computed from root.pub with signingcert.Fingerprint, never copied by
// hand. A private key file is refused by name, and no byte of any refused file is ever echoed.
// The parser is stricter than sigsum-go's: it refuses a sigsum-policy= option, a TAB, CRLF and a
// second line.
//
// EVERY FLAG BUT --out IS REQUIRED, AND HAS NO DEFAULT. A flag given twice is refused -- --env
// staging --env prod never silently signs prod -- and so is a positional argument. --out is
// created exclusively: an existing file is never overwritten, and a failed write removes what it
// created. Nothing is written on any refusal.
//
// Exit status: 0 written, 1 refused (an input, or the output), 2 usage error.
//
// NO CLOCK: every instant comes from a flag. NO NETWORK, NO CRYPTOGRAPHY: imports_test.go
// refuses net, crypto, os/exec, syscall, unsafe, cgo and encoding/json under cmd/, and any read
// of time.Now, time.Since or time.Until.
//
// THE REPRODUCIBLE BUILD. From the repository root of a checkout of the release tag, with <goos>
// and <goarch> replaced by the ceremony machine's:
//
//	GOENV=off GOFLAGS= GOWORK=off GOEXPERIMENT= GOFIPS140=off GOTOOLCHAIN=go1.27.3 CGO_ENABLED=0 GOAMD64=v1 GOARM64=v8.0 GOOS=<goos> GOARCH=<goarch> go build -trimpath -buildvcs=false -o signing-certificate ./cmd/signing-certificate
//
// Everything but the platform is pinned. No ceremony machine is fixed, and staging and prod may
// use different ones, so there is no single published sha256: each ceremony records its own
// binary's sha256 beside its GOOS and GOARCH. Two builds of one tag for one platform give the
// same sha256.
//
// When GOARCH=amd64, GOAMD64=v1 is fixed. When GOARCH=arm64, GOARM64=v8.0 is fixed. Each is the
// go command's documented default, set explicitly because a value exported in the shell would
// otherwise change the binary; each is read only for its own GOARCH, so the one command serves
// both. The documented build is for amd64 and arm64 only. Another GOARCH first needs its
// variable pinned here. Every other GOARCH has its own such variable -- GOARM's default even
// depends on the machine the toolchain was built on -- and it is added here at its documented
// default before that GOARCH is used.
//
// GOTOOLCHAIN pins the compiler: a toolchain line in go.mod would be only a minimum, and is
// ignored where this module is a dependency. GOENV=off, because cmd/go treats an empty variable
// as unset and would read GOFLAGS from the user's go env file. GOWORK=off, GOEXPERIMENT= and
// GOFIPS140=off keep a workspace file, a toolchain experiment or a FIPS mode in the environment
// from changing the build. -buildvcs=false, because VCS stamping marks a checkout with any
// untracked file as modified and changes the binary; the release tag and each ceremony's
// recorded hash bind the binary to its commit instead. go install ...@version is not this build:
// it stamps a module version and gives a different binary.
//
// On darwin, CGO_ENABLED=0 still links libSystem dynamically, as every Go binary there does:
// "static" means "no cgo" on darwin. The binary names libSystem but does not contain it, and the
// linker's ad-hoc signature is computed from the content, so the build is still reproducible.
package main
