// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/abylora/shared/pkg/signingcert"
	"sigsum.org/sigsum-go/pkg/key"
)

// The 14 weak encodings: ed25519-speccheck's src/main.rs, EIGHT_TORSION (the first 8) and
// EIGHT_TORSION_NON_CANONICAL (the last 6), at commit 65519336fda78a3d016e947df6d82848aca0c9da,
// converted to hex -- the list pkg/signingcert/weak_key_refusal_test.go pins. Test data, not a
// rule: the rule is signingcert.IsWeakKey's, and the command never consults it.
var weakKeyEncodings = []string{
	"0100000000000000000000000000000000000000000000000000000000000000",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"0000000000000000000000000000000000000000000000000000000000000000",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"0100000000000000000000000000000000000000000000000000000000000080",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
}

// The helper writes exactly what sigsum's formatter wrote, so a weak key written by it is a
// well-formed sigsum .pub file, and its refusal is Encode's, not the parser's.
func TestTheLineHelperWritesWhatSigsumKeyWrote(t *testing.T) {
	want, err := os.ReadFile(signingFixture)
	if err != nil {
		t.Fatalf("failed to read %s: %v", signingFixture, err)
	}
	if got := sshPublicKeyLine(mustHex32(t, testSigningPubHex)); got != string(want) {
		t.Errorf("sshPublicKeyLine(TEST 2) =\n%q\nsigsum's formatter wrote\n%q", got, want)
	}
}

// EVERY REFUSAL IS ENCODE'S, BY ITS OWN SENTINEL. certificate returns it bare; run exits 1,
// names it on stderr by its own text, and writes nothing.
func TestEncodeRefusalsAreReportedBySentinel(t *testing.T) {
	type row struct {
		name string
		args func(t *testing.T) []string
		want error
	}
	var rows []row
	for _, h := range weakKeyEncodings {
		rows = append(rows, row{"weak key " + h[:8] + "..." + h[56:], func(t *testing.T) []string {
			line := sshPublicKeyLine(mustHex32(t, h))
			if k, err := key.ParsePublicKey(line); err != nil || [32]byte(k) != mustHex32(t, h) {
				t.Fatalf("sigsum-go does not read the weak .pub as %s: %v", h, err)
			}
			return withFlag(vectorCArgs(), "--signing-public-key", writeTemp(t, "signing.pub", line))
		}, signingcert.ErrKeyWeak})
	}
	for _, env := range []string{"production", "PROD", "ci", ""} {
		rows = append(rows, row{"env " + strconv.Quote(env), func(*testing.T) []string {
			return withFlag(vectorCArgs(), "--env", env)
		}, signingcert.ErrEnvUnknown})
	}
	rows = append(rows,
		row{"not_before equal to not_after", func(*testing.T) []string {
			return withFlag(vectorCArgs(), "--not-after", "2026-01-01T00:00:00Z")
		}, signingcert.ErrValidityEmpty},
		row{"not_before after not_after", func(*testing.T) []string {
			return withFlag(withFlag(vectorCArgs(), "--not-before", "2026-04-01T00:00:00Z"), "--not-after", "2026-01-01T00:00:00Z")
		}, signingcert.ErrValidityEmpty},
		row{"the root certifying itself", func(*testing.T) []string {
			return withFlag(vectorCArgs(), "--signing-public-key", rootFixture)
		}, signingcert.ErrSelfCertificate},
	)

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			args := r.args(t)

			in, err := parseFlags(args)
			if err != nil {
				t.Fatalf("parseFlags() error = %v", err)
			}
			octets, err := certificate(in)
			if !errors.Is(err, r.want) {
				t.Errorf("certificate() error = %v, want %v", err, r.want)
			}
			if octets != nil {
				t.Errorf("certificate() returned %d octets alongside its refusal", len(octets))
			}

			code, stdout, stderr := runCommand(t, args...)
			if code != exitRefused {
				t.Errorf("exit = %d, want %d", code, exitRefused)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want nothing on a refusal", stdout)
			}
			if !strings.Contains(stderr, r.want.Error()) {
				t.Errorf("stderr = %q, want it to name %q", stderr, r.want.Error())
			}
		})
	}
}
