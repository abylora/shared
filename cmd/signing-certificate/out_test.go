// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ON SUCCESS ONLY THE CERTIFICATE IS WRITTEN: the --out file, and nothing on stdout or stderr,
// so nothing can be mistaken for part of the certificate (ruled by abylora-master, 2026-11-09).
func TestOutWritesOnlyTheCertificate(t *testing.T) {
	out := filepath.Join(t.TempDir(), "signing-certificate.json")
	code, stdout, stderr := runCommand(t, append(vectorCArgs(), "--out", out)...)
	if code != exitOK {
		t.Fatalf("exit = %d, want 0; stderr = %q", code, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing when --out is given", stdout)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want it empty on success", stderr)
	}
	got, err := os.ReadFile(out)
	if err != nil || string(got) != vectorC {
		t.Errorf("--out holds %q (err %v), want vector C", got, err)
	}
}

// A CEREMONY NEVER OVERWRITES A CERTIFICATE.
func TestOutNeverOverwrites(t *testing.T) {
	out := writeTemp(t, "signing-certificate.json", "an earlier certificate")
	code, stdout, stderr := runCommand(t, append(vectorCArgs(), "--out", out)...)
	if code != exitRefused || stdout != "" || !strings.Contains(stderr, errOutExists.Error()) {
		t.Errorf("exit = %d, stdout = %q, stderr = %q; want %d, nothing, and %q", code, stdout, stderr, exitRefused, errOutExists.Error())
	}
	if got, _ := os.ReadFile(out); string(got) != "an earlier certificate" {
		t.Errorf("the existing file now holds %q", got)
	}
}

// NOTHING WRITTEN ON A REFUSAL: the output is opened only after Encode has succeeded.
func TestNoOutFileIsCreatedOnARefusal(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "signing-certificate.json")
	weak := writeTemp(t, "signing.pub", sshPublicKeyLine([32]byte{1})) // the identity, order 1
	code, _, _ := runCommand(t, append(withFlag(vectorCArgs(), "--signing-public-key", weak), "--out", out)...)
	if code != exitRefused {
		t.Errorf("exit = %d, want %d", code, exitRefused)
	}
	if _, err := os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("--out exists after a refusal (stat error %v)", err)
	}

	missing := filepath.Join(dir, "no-such-directory", "signing-certificate.json")
	if code, stdout, _ := runCommand(t, append(vectorCArgs(), "--out", missing)...); code != exitRefused || stdout != "" {
		t.Errorf("an unwritable --out: exit = %d, stdout = %q; want %d and nothing", code, stdout, exitRefused)
	}
}

// --out= was set, to nothing: an error, never a silent fall-back to stdout.
func TestAnEmptyOutIsNotStdout(t *testing.T) {
	code, stdout, _ := runCommand(t, append(vectorCArgs(), "--out=")...)
	if code != exitRefused || stdout != "" {
		t.Errorf("exit = %d, stdout = %q; want %d and nothing", code, stdout, exitRefused)
	}
}
