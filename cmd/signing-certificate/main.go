// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"io"
	"os"

	"github.com/abylora/shared/pkg/signingcert"
)

const (
	exitOK      = 0 // the certificate was written
	exitRefused = 1 // an input was refused, or the output could not be written
	exitUsage   = 2 // the command line itself is wrong
)

// usage spells the environments only through signingcert's constants: the command holds no
// copy of the env rule.
var usage = `usage: signing-certificate --signing-public-key FILE --root-public-key FILE --env ENV
                           --not-before TIME --not-after TIME [--out FILE]

Writes the relay list's signing certificate, exactly as signingcert.Encode returns it, to stdout
or to --out, which must not exist. Every flag but --out is required and has no default.

  --signing-public-key FILE  the signing key's public key file (.pub), as sigsum-key wrote it
  --root-public-key FILE     the issuing root's public key file (.pub); never the private key
  --env ENV                  ` + string(signingcert.EnvProd) + ` or ` + string(signingcert.EnvStaging) + `
  --not-before TIME          YYYY-MM-DDTHH:MM:SSZ
  --not-after TIME           YYYY-MM-DDTHH:MM:SSZ
  --out FILE                 write here instead of stdout; never overwrites

Exit status: 0 written, 1 refused, 2 usage error.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the whole command, in-process: main only binds it to the process. It writes to stderr
// only through report, and only on a non-zero exit.
func run(args []string, stdout, stderr io.Writer) int {
	in, err := parseFlags(args)
	if errors.Is(err, flag.ErrHelp) {
		io.WriteString(stderr, usage)
		return exitOK
	}
	if err != nil {
		report(stderr, err)
		return exitUsage
	}
	octets, err := certificate(in)
	if err != nil {
		report(stderr, err)
		return exitRefused
	}
	if err := emit(octets, in, stdout); err != nil {
		report(stderr, err)
		return exitRefused
	}
	return exitOK
}

// report writes one line naming the refusal. Every text it can carry is a constant sentinel, a
// flag name, or an os error naming a path: never a byte of an input file.
func report(stderr io.Writer, err error) {
	io.WriteString(stderr, "signing-certificate: "+err.Error()+"\n")
}
