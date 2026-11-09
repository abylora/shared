// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Copied from <workspace>/docs/contracts/relay-list.md, The signing certificate, Test vectors --
// never computed here. RFC 8032 section 7.1's published test keys, never a real root.
const (
	// testRootPubHex is RFC 8032 TEST 1's public key: the root in vector C.
	testRootPubHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	// testSigningPubHex is RFC 8032 TEST 2's public key: the signing key in vector C.
	testSigningPubHex = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
	// testRootFingerprint is the contract's fingerprint(root).
	testRootFingerprint = "BuP9j9opu2CrWVV95h7bCuzbIxE0vjDnW0Vfjht5L6k="

	// vectorC is the contract's vector C: 281 octets, no trailing newline.
	vectorC = `{"_type":"abylora.relay-list.signing-certificate","spec_version":1,"env":"staging",` +
		`"root":"BuP9j9opu2CrWVV95h7bCuzbIxE0vjDnW0Vfjht5L6k=",` +
		`"key":"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",` +
		`"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z"}`

	// The two .pub fixtures, written by sigsum-go v0.14.1's own formatter,
	// internal/ssh.FormatPublicEd25519 -- the function `sigsum-key from-hex` calls.
	signingFixture = "testdata/vector-c-signing.pub"
	rootFixture    = "testdata/vector-c-root.pub"
)

// vectorCArgs are vector C's inputs as flags.
func vectorCArgs() []string {
	return []string{
		"--signing-public-key", signingFixture,
		"--root-public-key", rootFixture,
		"--env", "staging",
		"--not-before", "2026-01-01T00:00:00Z",
		"--not-after", "2026-04-01T00:00:00Z",
	}
}

// withFlag returns a copy of args with name's value replaced, or with the pair appended.
func withFlag(args []string, name, value string) []string {
	out := append([]string(nil), args...)
	for i := 0; i+1 < len(out); i += 2 {
		if out[i] == name {
			out[i+1] = value
			return out
		}
	}
	return append(out, name, value)
}

// withoutFlag returns a copy of args with name and its value removed.
func withoutFlag(args []string, name string) []string {
	var out []string
	for i := 0; i+1 < len(args); i += 2 {
		if args[i] != name {
			out = append(out, args[i], args[i+1])
		}
	}
	return out
}

// runCommand runs the command in-process.
func runCommand(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("fixture %q is not 32 bytes of hex", s)
	}
	return [32]byte(b)
}

// writeTemp writes content to a new file in a fresh temporary directory and returns its path.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write %s: %v", name, err)
	}
	return p
}

// sshPublicKeyLine writes key as sigsum-key writes a .pub file (internal/ssh.FormatPublicEd25519
// at v0.14.1). TestTheLineHelperWritesWhatSigsumKeyWrote holds it to the sigsum-written fixture,
// so a file it writes is sigsum's format and a refusal of that file is Encode's, not the parser's.
func sshPublicKeyLine(key [32]byte) string {
	blob := append([]byte{0, 0, 0, 11}, "ssh-ed25519"...)
	blob = append(blob, 0, 0, 0, 32)
	blob = append(blob, key[:]...)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " sigsum key\n"
}
