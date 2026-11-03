// SPDX-License-Identifier: AGPL-3.0-only

package keysetpb

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// generatedWithProtoc is the protoc release the committed files were generated with, exactly as
// `protoc --version` prints it. protoc cannot be pinned through Go modules, so it is named
// here, once, and every generated header records it as well (as v5.29.3, the compiler version
// this release reports to plugins). Change it only together with a regeneration.
const generatedWithProtoc = "libprotoc 29.3"

// moduleRoot is this module's root, seen from this package's directory, pkg/keyset/keysetpb.
var moduleRoot = filepath.Join("..", "..", "..")

// THE COMMITTED GENERATED CODE IS EXACTLY WHAT THE PINNED GENERATORS PRODUCE. Consumers never
// run generation (D26). Without this test, a hand edit to a .pb.go file, a .proto change
// committed without regenerating, or a generator bumped in go.mod without regenerating would
// ship silently.
//
// It regenerates through the module's own path, `go generate ./tools`, the very command a
// developer runs, in a copy of its inputs (go.mod, go.sum, tools/, proto/) under a temporary
// directory, so it never writes the work tree. It then compares every *.pb.go file byte for
// byte, header included. The header names both plugins' versions and protoc's, so a version
// drift fails too.
//
// It runs only where `protoc --version` prints generatedWithProtoc. Elsewhere it skips, naming
// both: under another protoc a difference would mean a different compiler, not drift. -short
// skips it too, because it builds the two plugins.
func TestCommittedGeneratedCodeEqualsARegeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the two pinned plugins and runs protoc; skipped under -short")
	}
	protoc, err := exec.LookPath("protoc")
	if err != nil {
		t.Skipf("protoc is not on PATH; install %s to run this check", generatedWithProtoc)
	}
	out, err := exec.Command(protoc, "--version").Output()
	if err != nil {
		t.Fatalf("failed to run protoc --version: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != generatedWithProtoc {
		t.Skipf("protoc on PATH is %q; the committed files were generated with %q", got, generatedWithProtoc)
	}

	mod, err := os.ReadFile(filepath.Join(moduleRoot, "go.mod"))
	if err != nil || !bytes.HasPrefix(mod, []byte("module github.com/abylora/shared\n")) {
		t.Fatalf("failed to find this module's go.mod at %s: %v", moduleRoot, err)
	}

	tmp := t.TempDir()
	for _, rel := range []string{"go.mod", "go.sum", filepath.Join("tools", "tools.go")} {
		copyFile(t, filepath.Join(moduleRoot, rel), filepath.Join(tmp, rel))
	}
	if err := os.CopyFS(filepath.Join(tmp, "proto"), os.DirFS(filepath.Join(moduleRoot, "proto"))); err != nil {
		t.Fatalf("failed to copy proto/: %v", err)
	}

	cmd := exec.Command("go", "generate", "./tools")
	cmd.Dir = tmp
	// GOTOOLCHAIN=local: a regeneration never downloads a Go toolchain; a pin that wanted a
	// newer one fails here instead.
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=readonly", "GOTOOLCHAIN=local")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to run go generate ./tools in a copy of the module: %v\n%s", err, out)
	}

	generatedDir := filepath.Join(tmp, "pkg", "keyset", "keysetpb")
	committed := generatedFiles(t, ".")
	regenerated := generatedFiles(t, generatedDir)
	if !slices.Equal(sortedKeys(committed), sortedKeys(regenerated)) {
		t.Fatalf("committed generated files %v, a regeneration writes %v", sortedKeys(committed), sortedKeys(regenerated))
	}
	for name, want := range committed {
		if got := regenerated[name]; !bytes.Equal(got, want) {
			line, c, r := firstDifference(want, got)
			t.Errorf("%s differs from a regeneration at line %d:\n committed:   %q\n regenerated: %q\nrun `go generate ./tools` and commit the result", name, line, c, r)
		}
	}

	err = filepath.WalkDir(tmp, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".pb.go") && filepath.Dir(path) != generatedDir {
			t.Errorf("a regeneration wrote %s, outside pkg/keyset/keysetpb", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk the regenerated copy: %v", err)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()

	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatalf("failed to read %s: %v", from, err)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		t.Fatalf("failed to create %s: %v", filepath.Dir(to), err)
	}
	if err := os.WriteFile(to, b, 0o644); err != nil {
		t.Fatalf("failed to write %s: %v", to, err)
	}
}

// generatedFiles reads every *.pb.go file in dir, by base name.
func generatedFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()

	paths, err := filepath.Glob(filepath.Join(dir, "*.pb.go"))
	if err != nil {
		t.Fatalf("failed to list %s: %v", dir, err)
	}
	files := make(map[string][]byte, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("failed to read %s: %v", p, err)
		}
		files[filepath.Base(p)] = b
	}

	return files
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	return keys
}

// firstDifference returns the 1-based number of the first line where a and b differ, and
// that line of each.
func firstDifference(a, b []byte) (int, string, string) {
	al, bl := strings.Split(string(a), "\n"), strings.Split(string(b), "\n")
	for i := range max(len(al), len(bl)) {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			return i + 1, x, y
		}
	}

	return 0, "", ""
}
