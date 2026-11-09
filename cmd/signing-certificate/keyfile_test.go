// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/base64"
	"strings"
	"testing"

	"sigsum.org/sigsum-go/pkg/key"
)

// signingB64 is TEST 2's 51-byte public-key blob, base64, as sigsum's formatter wrote it.
const signingB64 = "AAAAC3NzaC1lZDI1NTE5AAAAID1AF8PoQ4lakrcKp00bfrycmCzPLsSWjMDNVfEq9GYM"

func blobB64(prefix []byte, key []byte) string {
	return base64.StdEncoding.EncodeToString(append(append([]byte(nil), prefix...), key...))
}

// STRICTER THAN SIGSUM, NEVER LOOSER: one line, "ssh-ed25519 ", the canonical base64 blob, an
// optional comment, an optional final newline. Each row is refused on both key flags, by a
// constant that carries no byte of the file, and nothing is written.
func TestAMalformedKeyFileIsRefused(t *testing.T) {
	key32 := make([]byte, 32)
	wrongType := append([]byte{0, 0, 0, 11}, "ssh-ed25518"...)
	wrongType = append(wrongType, 0, 0, 0, 32)
	goodPrefix := append(append([]byte{0, 0, 0, 11}, "ssh-ed25519"...), 0, 0, 0, 32)

	for _, tc := range []struct{ name, content string }{
		{"empty", ""},
		{"a newline alone", "\n"},
		{"a policy option, which sigsum accepts", `sigsum-policy="x" ssh-ed25519 ` + signingB64 + "\n"},
		{"a TAB separator, which sigsum accepts", "ssh-ed25519\t" + signingB64 + "\n"},
		{"a leading space", " ssh-ed25519 " + signingB64 + "\n"},
		{"a doubled space", "ssh-ed25519  " + signingB64 + "\n"},
		{"CRLF, which sigsum accepts", "ssh-ed25519 " + signingB64 + " c\r\n"},
		{"a second line, which sigsum ignores", "ssh-ed25519 " + signingB64 + "\nssh-ed25519 " + signingB64 + "\n"},
		{"a comment line first", "# key\nssh-ed25519 " + signingB64 + "\n"},
		{"another key type", "ssh-rsa " + signingB64 + "\n"},
		{"the type alone", "ssh-ed25519\n"},
		{"a wrong blob prefix", "ssh-ed25519 " + blobB64(wrongType, key32) + "\n"},
		{"a 31-byte key", "ssh-ed25519 " + blobB64(goodPrefix, key32[:31]) + "\n"},
		{"a 33-byte key", "ssh-ed25519 " + blobB64(goodPrefix, append(key32, 0)) + "\n"},
		{"base64 that is not", "ssh-ed25519 " + strings.Repeat("!", 68) + "\n"},
		{"raw hex", testSigningPubHex + "\n"},
		{"raw hex of 64 bytes, sigsum's deprecated private form", strings.Repeat("ab", 64) + "\n"},
		{"over 4 KiB", "ssh-ed25519 " + signingB64 + " " + strings.Repeat("c", 4096) + "\n"},
	} {
		for _, flagName := range []string{"--signing-public-key", "--root-public-key"} {
			t.Run(flagName+"/"+tc.name, func(t *testing.T) {
				path := writeTemp(t, "key.pub", tc.content)
				code, stdout, stderr := runCommand(t, withFlag(vectorCArgs(), flagName, path)...)
				want := flagName + ": " + errKeyFileMalformed.Error()
				if code != exitRefused || stdout != "" || !strings.Contains(stderr, want) {
					t.Errorf("exit = %d, stdout = %q, stderr = %q; want %d, nothing, and %q", code, stdout, stderr, exitRefused, want)
				}
			})
		}
	}
}

// A PRIVATE KEY FILE IS REFUSED BY NAME, so the operator learns they passed root, not root.pub;
// and no byte of it reaches stderr. The content is a fake: no real private key is committed.
func TestAPrivateKeyFileIsRefusedByName(t *testing.T) {
	const secret = "c2VjcmV0LWJ5dGVzLW5vdC1hLXJlYWwta2V5"
	path := writeTemp(t, "root", "-----BEGIN OPENSSH PRIVATE KEY-----\n"+secret+"\n-----END OPENSSH PRIVATE KEY-----\n")

	code, stdout, stderr := runCommand(t, withFlag(vectorCArgs(), "--root-public-key", path)...)
	if code != exitRefused || stdout != "" || !strings.Contains(stderr, errKeyFileIsPrivate.Error()) {
		t.Errorf("exit = %d, stdout = %q, stderr = %q; want %d, nothing, and %q", code, stdout, stderr, exitRefused, errKeyFileIsPrivate.Error())
	}
	if strings.Contains(stderr, secret) || strings.Contains(stderr, "OPENSSH") {
		t.Errorf("stderr carries the file's content: %q", stderr)
	}
}

// ONE KEY, TWO PARSERS, THE SAME 32 BYTES. Every variant this command accepts is read by
// sigsum-go v0.14.1's own parser as the identical key, so the strict parser here can only refuse
// more, never read differently. sigsum-go is imported here only: the binary never links it.
func TestEveryAcceptedFileIsReadAsSigsumReadsIt(t *testing.T) {
	for _, content := range []string{
		"ssh-ed25519 " + signingB64 + " sigsum key\n", // as sigsum-key writes it
		"ssh-ed25519 " + signingB64 + "\n",
		"ssh-ed25519 " + signingB64,
		"ssh-ed25519 " + signingB64 + " ",
		"ssh-ed25519 " + signingB64 + " operator@ceremony\n", // as ssh-keygen writes it
		"ssh-ed25519 " + signingB64 + " a\tcomment with spaces\n",
	} {
		ours, err := parsePublicKey([]byte(content))
		if err != nil {
			t.Errorf("parsePublicKey(%q) error = %v", content, err)
			continue
		}
		theirs, err := key.ParsePublicKey(content)
		if err != nil {
			t.Errorf("sigsum-go refuses %q, which this command accepts: %v", content, err)
			continue
		}
		if ours != [32]byte(theirs) || ours != mustHex32(t, testSigningPubHex) {
			t.Errorf("%q: this command reads %x, sigsum-go reads %x", content, ours, theirs)
		}
	}
}
