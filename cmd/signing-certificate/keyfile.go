// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
)

// maxKeyFileSize bounds a read. A public key line is about 100 bytes; the bound means a path
// to something else -- a device, an image -- cannot hang the ceremony.
const maxKeyFileSize = 4096

// blobPrefix is the fixed head of an Ed25519 OpenSSH public-key blob: the string "ssh-ed25519"
// and the uint32 length 32, each SSH-serialised (sigsum-go v0.14.1, internal/ssh/public.go).
var blobPrefix = []byte{0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0, 32}

// readPublicKeyFile reads one public key file. The error names the path at most, never content.
func readPublicKeyFile(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()

	b, err := io.ReadAll(io.LimitReader(f, maxKeyFileSize+1))
	if err != nil {
		return [32]byte{}, err
	}
	if len(b) > maxKeyFileSize {
		return [32]byte{}, errKeyFileMalformed
	}
	return parsePublicKey(b)
}

// parsePublicKey reads sigsum's public key file format, STRICTLY: exactly
//
//	"ssh-ed25519 " BASE64 [ " " COMMENT ] [ "\n" ]
//
// where BASE64 is canonical standard base64 of the 51-byte blob (blobPrefix, then 32 key bytes)
// and COMMENT holds no CR or LF. It accepts a strict subset of what sigsum-go's
// key.ReadPublicKeyFile accepts, and reads every file it accepts as the same key
// (TestEveryAcceptedFileIsReadAsSigsumReadsIt). It refuses what sigsum forgives: a
// sigsum-policy= option (the contract's trap: in a key file it turns sigsum-submit -k into a
// submission), a TAB separator, CRLF, and a second line, which sigsum silently ignores.
//
// sigsum-go's own parser is not used: its package links an ssh-agent dialler (net) and a
// private-key parser into what runs on the air-gapped machine.
func parsePublicKey(b []byte) ([32]byte, error) {
	var key [32]byte
	if bytes.HasPrefix(b, []byte("-----BEGIN ")) {
		return key, errKeyFileIsPrivate
	}
	line, _ := bytes.CutSuffix(b, []byte("\n"))
	if bytes.ContainsAny(line, "\r\n") {
		return key, errKeyFileMalformed
	}
	rest, ok := bytes.CutPrefix(line, []byte("ssh-ed25519 "))
	if !ok {
		return key, errKeyFileMalformed
	}
	encoded, _, _ := bytes.Cut(rest, []byte(" "))
	blob, err := base64.StdEncoding.Strict().DecodeString(string(encoded))
	if err != nil || len(blob) != len(blobPrefix)+len(key) || !bytes.HasPrefix(blob, blobPrefix) {
		return key, errKeyFileMalformed
	}
	copy(key[:], blob[len(blobPrefix):])
	return key, nil
}
