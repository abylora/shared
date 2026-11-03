// SPDX-License-Identifier: AGPL-3.0-only

package keyset

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const licenceHeader = "// SPDX-License-Identifier: AGPL-3.0-only"

type parsedFile struct {
	name    string
	imports []*ast.ImportSpec
}

// parsePackage parses every non-test Go file of this directory, and refuses to return none: a
// guard that checked nothing would pass vacuously. keysetpb's shape; test helpers cannot be
// shared across packages without exporting them.
func parsePackage(t *testing.T) []parsedFile {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("failed to read the package directory: %v", err)
	}
	fset := token.NewFileSet()
	var files []parsedFile
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", name, err)
		}
		files = append(files, parsedFile{name: name, imports: file.Imports})
	}
	if len(files) == 0 {
		t.Fatal("found no non-test Go file; this guard would pass vacuously")
	}

	return files
}

// under matches by path element, so "log" covers "log/slog" and not "logic".
func under(path, prefix string) bool { return path == prefix || strings.HasPrefix(path, prefix+"/") }

func isStandardLibrary(path string) bool {
	return !strings.Contains(strings.SplitN(path, "/", 2)[0], ".")
}

const wirePath = "github.com/abylora/shared/pkg/keyset/keysetpb"

// importRefusal returns why a non-test file of this package may not import path, or "".
//
//   - NO wireguard-go AND NO wgctrl: this module's CLAUDE.md.
//   - NO LOGGER: the held set is every device's public key and tunnel address, and rule 11 says
//     an entry is never logged.
//   - NO fmt: it is how a key reaches an error string. Every error here is a sentinel.
//   - NO os, syscall, unsafe OR net: the reference touches no file, process, kernel or network,
//     and tests addresses on raw bytes.
//   - NO time: the reference has no clock. Rule 6's timers, rule 15's epoch and valid_until
//     expiry are the consumers' and the producer's.
//   - NO testing AND NO embed: nothing test-only and no data reach a binary importing this.
//   - NOT keysetvectors: the reference never depends on the vectors that judge it.
//   - OTHERWISE THE STANDARD LIBRARY AND keysetpb ONLY.
func importRefusal(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "wireguard") || strings.Contains(lower, "wgctrl") || under(path, "golang.zx2c4.com"):
		return "no wireguard-go and no wgctrl in shared"
	case under(path, "log") || under(path, "google.golang.org/grpc/grpclog"):
		return "nothing here logs: the held set is device public keys and tunnel addresses"
	case under(path, "fmt"):
		return "fmt is how a key reaches an error string; errors here are sentinels"
	case under(path, "os"), under(path, "syscall"), under(path, "unsafe"), under(path, "net"):
		return "the reference touches no file, process, kernel or network"
	case under(path, "time"):
		return "the reference has no clock"
	case under(path, "testing"), under(path, "embed"):
		return "no test-only code and no data reach a binary importing the reference"
	case under(path, "github.com/abylora/shared/pkg/keyset/keysetvectors"):
		return "the reference never depends on the vectors that judge it"
	case path == wirePath, isStandardLibrary(path):
		return ""
	}

	return "the standard library and keysetpb only"
}

// nameRefusal returns why an import may not carry the name name, or "". A dot import hides a
// package's selectors from every selector-based check; a blank import runs code for its side
// effects, which nothing here has a use for.
func nameRefusal(name string) string {
	switch name {
	case ".":
		return "a dot import hides its selectors"
	case "_":
		return "a blank import runs code for its side effects"
	}

	return ""
}

// Every refusal of importRefusal is driven here, and so is every permission it grants, so a
// branch that stopped firing fails this test.
func TestImportRefusalRefusesEachForbiddenImport(t *testing.T) {
	for _, tc := range []struct {
		path    string
		refused bool
	}{
		{"golang.zx2c4.com/wireguard/device", true}, {"github.com/WireGuard/wgctrl-go", true},
		{"log", true}, {"log/slog", true}, {"google.golang.org/grpc/grpclog", true},
		{"fmt", true}, {"os", true}, {"os/exec", true}, {"syscall", true}, {"unsafe", true},
		{"net", true}, {"net/netip", true}, {"time", true}, {"testing", true}, {"testing/fstest", true},
		{"embed", true}, {"github.com/abylora/shared/pkg/keyset/keysetvectors", true},
		{"google.golang.org/protobuf/proto", true}, {"github.com/example/other", true},
		{wirePath, false}, {"bytes", false}, {"errors", false}, {"maps", false}, {"slices", false},
		{"logic", false}, {"timeline", false},
	} {
		if got := importRefusal(tc.path) != ""; got != tc.refused {
			t.Errorf("importRefusal(%q) refused = %v, want %v", tc.path, got, tc.refused)
		}
	}
}

func TestNameRefusalRefusesDotAndBlank(t *testing.T) {
	for name, refused := range map[string]bool{".": true, "_": true, "kpb": false} {
		if got := nameRefusal(name) != ""; got != refused {
			t.Errorf("nameRefusal(%q) refused = %v, want %v", name, got, refused)
		}
	}
}

func TestNoNonTestFileImportsAnythingRefused(t *testing.T) {
	for _, f := range parsePackage(t) {
		for _, spec := range f.imports {
			p, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("failed to unquote an import path in %s: %v", f.name, err)
			}
			if why := importRefusal(p); why != "" {
				t.Errorf("%s imports %q: %s", f.name, p, why)
			}
			if spec.Name != nil {
				if why := nameRefusal(spec.Name.Name); why != "" {
					t.Errorf("%s imports %q as %s: %s", f.name, p, spec.Name.Name, why)
				}
			}
		}
	}
}

// EVERY GO FILE HERE CARRIES THE LICENCE HEADER as its first line (AGPL-3, D12), tests included.
func TestEveryGoFileCarriesTheLicenceHeader(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil || len(paths) == 0 {
		t.Fatalf("failed to list the package: %v (%d files)", err, len(paths))
	}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			t.Fatalf("failed to open %s: %v", p, err)
		}
		first, _ := bufio.NewReader(f).ReadString('\n')
		f.Close()
		if got := strings.TrimRight(first, "\n"); got != licenceHeader {
			t.Errorf("%s starts %q, want %q", p, got, licenceHeader)
		}
	}
}
