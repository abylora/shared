// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"strings"
	"testing"

	"github.com/abylora/shared/pkg/signingcert"
)

// NO DEFAULTS. Each required flag, left out, is a usage error naming it, and nothing is written.
func TestAMissingRequiredFlagIsAUsageError(t *testing.T) {
	for _, name := range []string{"--signing-public-key", "--root-public-key", "--env", "--not-before", "--not-after"} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runCommand(t, withoutFlag(vectorCArgs(), name)...)
			if code != exitUsage || stdout != "" || !strings.Contains(stderr, name+" is required") {
				t.Errorf("exit = %d, stdout = %q, stderr = %q; want %d, nothing, and %q",
					code, stdout, stderr, exitUsage, name+" is required")
			}
		})
	}
}

func TestUsageErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		// flag would otherwise keep the last value silently: staging typed, prod signed. Singled
		// out by abylora-master (2026-11-09): exactly what a ceremony must not hit.
		{"--env staging --env prod", append(vectorCArgs(), "--env", "prod"), errFlagRepeated.Error()},
		{"--env prod --env staging", append(withFlag(vectorCArgs(), "--env", "prod"), "--env", "staging"), errFlagRepeated.Error()},
		{"--not-after twice", append(vectorCArgs(), "--not-after", "2026-05-01T00:00:00Z"), errFlagRepeated.Error()},
		{"an unknown flag", append(vectorCArgs(), "--key-hash", "x"), "key-hash"},
		{"a positional argument", append(vectorCArgs(), "signing.pub"), errArgument.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runCommand(t, tc.args...)
			if code != exitUsage || stdout != "" || !strings.Contains(stderr, tc.want) {
				t.Errorf("exit = %d, stdout = %q, stderr = %q; want %d, nothing, and %q", code, stdout, stderr, exitUsage, tc.want)
			}
		})
	}
}

func TestHelpPrintsUsageAndWritesNothing(t *testing.T) {
	code, stdout, stderr := runCommand(t, "-h")
	if code != exitOK || stdout != "" {
		t.Errorf("exit = %d, stdout = %q; want 0 and nothing", code, stdout)
	}
	for _, want := range []string{"--signing-public-key", "--root-public-key", "--not-before", "--not-after", "--out",
		string(signingcert.EnvProd), string(signingcert.EnvStaging)} {
		if !strings.Contains(stderr, want) {
			t.Errorf("usage does not mention %q:\n%s", want, stderr)
		}
	}
}

// EXACTLY YYYY-MM-DDTHH:MM:SSZ, so the text the operator typed is the text the root signs. An
// offset is refused, never converted. This is the flag's syntax: whether the instant is
// encodable and whether the window is empty stay Encode's to refuse.
func TestATimestampNotInTheContractsFormIsRefused(t *testing.T) {
	for _, s := range []string{
		"",
		"2026-01-01",
		"2026-01-01T00:00:00+03:00",
		"2026-01-01T00:00:00+00:00",
		"2026-01-01T00:00:00.5Z",
		"2026-01-01t00:00:00z",
		"2026-01-01T0:00:00Z",
		"2026-01-01 00:00:00Z",
		" 2026-01-01T00:00:00Z",
		"2026-02-30T00:00:00Z",
		"2026-12-31T23:59:60Z",
	} {
		for _, name := range []string{"--not-before", "--not-after"} {
			t.Run(name+"="+s, func(t *testing.T) {
				code, stdout, stderr := runCommand(t, withFlag(vectorCArgs(), name, s)...)
				if code != exitRefused || stdout != "" ||
					!strings.Contains(stderr, name+": "+errInstantSyntax.Error()) {
					t.Errorf("exit = %d, stdout = %q, stderr = %q; want %d, nothing, and %q",
						code, stdout, stderr, exitRefused, name+": "+errInstantSyntax.Error())
				}
			})
		}
	}
}
