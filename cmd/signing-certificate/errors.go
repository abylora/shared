// SPDX-License-Identifier: AGPL-3.0-only

package main

import "errors"

// The command's own refusals. Each is a constant: none carries a byte of an input file.
// signingcert's sentinels are never wrapped in, or duplicated by, one of these.
var (
	errFlagRepeated     = errors.New("flag given twice; each flag is given once")
	errArgument         = errors.New("unexpected argument; every input is a flag")
	errInstantSyntax    = errors.New("not a timestamp in exactly the form YYYY-MM-DDTHH:MM:SSZ")
	errKeyFileMalformed = errors.New(`not a public key file in sigsum's format: one line, "ssh-ed25519 ", ` +
		"the base64 key blob, an optional comment")
	errKeyFileIsPrivate = errors.New("this is a private key file; pass the public key file (.pub) beside it")
	errOutExists        = errors.New("the --out file already exists; a certificate is never overwritten")
)
