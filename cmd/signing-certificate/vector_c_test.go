// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"testing"
	"time"

	"github.com/abylora/shared/pkg/signingcert"
	"sigsum.org/sigsum-go/pkg/key"
)

// THE FIRST TEST. Vector C's inputs -- TEST 2's signing.pub, TEST 1's root.pub, staging,
// 2026-01-01 to 2026-04-01 -- give vector C's 281 octets exactly: no newline, nothing else. On
// success stderr is EMPTY, so nothing can be mistaken for part of the certificate (ruled by
// abylora-master, 2026-11-09).
func TestVectorCInputsWriteVectorCOctets(t *testing.T) {
	code, stdout, stderr := runCommand(t, vectorCArgs()...)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d; stderr = %q", code, exitOK, stderr)
	}
	if len(stdout) != 281 || stdout != vectorC {
		t.Errorf("stdout (%d octets) =\n%q\nwant vector C (281 octets)\n%q", len(stdout), stdout, vectorC)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want it empty on success", stderr)
	}
}

// The command holds no env rule: prod reaches Encode as typed, and the octets are Encode's.
func TestProdIsPassedToEncodeAsIs(t *testing.T) {
	want, err := signingcert.Encode(signingcert.Opts{
		Env:       signingcert.EnvProd,
		Root:      testRootFingerprint,
		Key:       mustHex32(t, testSigningPubHex),
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	code, stdout, stderr := runCommand(t, withFlag(vectorCArgs(), "--env", "prod")...)
	if code != exitOK || stdout != string(want) || stderr != "" {
		t.Errorf("exit = %d, stdout = %q, stderr = %q; want 0, %q, and an empty stderr", code, stdout, stderr, want)
	}
}

// A guard on the fixtures: sigsum-go's own parser reads them as the contract's keys.
func TestTheFixturesAreSigsumsReadingOfTheContractKeys(t *testing.T) {
	for path, wantHex := range map[string]string{signingFixture: testSigningPubHex, rootFixture: testRootPubHex} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read %s: %v", path, err)
		}
		got, err := key.ParsePublicKey(string(b))
		if err != nil {
			t.Fatalf("sigsum-go refuses %s: %v", path, err)
		}
		if [32]byte(got) != mustHex32(t, wantHex) {
			t.Errorf("%s holds %x, want %s", path, got, wantHex)
		}
	}
}
