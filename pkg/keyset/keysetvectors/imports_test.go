// SPDX-License-Identifier: AGPL-3.0-only

package keysetvectors

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

const (
	wirePath      = "github.com/abylora/shared/pkg/keyset/keysetpb"
	protoPath     = "google.golang.org/protobuf/proto"
	referencePath = "github.com/abylora/shared/pkg/keyset"
	schemaHeader  = "<!-- SPDX-License-Identifier: AGPL-3.0-only -->"
)

// importRefusal returns why a non-test file of this package may not import path, or "".
//
//   - NO wireguard-go AND NO wgctrl, and NO LOGGER: as in the reference.
//   - NO fmt, os, syscall, unsafe, net OR time: the files are embedded and the loader reads
//     nothing else; the vectors have no clock.
//   - NO testing: a non-test file importing it hands test-only code to every importer.
//   - NOT THE REFERENCE: a data package never depends on the code it judges. (Matched exactly:
//     keysetpb sits under the same path.)
//   - OTHERWISE THE STANDARD LIBRARY, keysetpb, AND protobuf's proto FOR THE wire FORM ONLY.
func importRefusal(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "wireguard") || strings.Contains(lower, "wgctrl") || under(path, "golang.zx2c4.com"):
		return "no wireguard-go and no wgctrl in shared"
	case under(path, "log") || under(path, "google.golang.org/grpc/grpclog"):
		return "nothing here logs"
	case under(path, "fmt"), under(path, "os"), under(path, "syscall"), under(path, "unsafe"), under(path, "net"), under(path, "time"):
		return "the loader reads only its embedded files and has no clock"
	case under(path, "testing"):
		return "no test-only code reaches an importer"
	case path == referencePath:
		return "the vectors never depend on the reference they judge"
	case path == wirePath, path == protoPath, isStandardLibrary(path):
		return ""
	}

	return "the standard library, keysetpb and protobuf's proto package only"
}

func TestImportRefusalRefusesEachForbiddenImport(t *testing.T) {
	for _, tc := range []struct {
		path    string
		refused bool
	}{
		{"golang.zx2c4.com/wireguard/device", true}, {"log/slog", true}, {"fmt", true}, {"os", true},
		{"net/netip", true}, {"time", true}, {"testing", true}, {"unsafe", true},
		{referencePath, true}, {"google.golang.org/protobuf/encoding/protojson", true}, {"github.com/example/other", true},
		{wirePath, false}, {protoPath, false}, {"embed", false}, {"io/fs", false}, {"encoding/json", false},
	} {
		if got := importRefusal(tc.path) != ""; got != tc.refused {
			t.Errorf("importRefusal(%q) refused = %v, want %v", tc.path, got, tc.refused)
		}
	}
}

// Every Go file carries the licence header, and so does SCHEMA.md, as an HTML comment. The JSON
// files cannot carry a comment; the repository's LICENSE covers them.
func TestEveryHandwrittenFileCarriesTheLicenceHeader(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil || len(paths) == 0 {
		t.Fatalf("failed to list the package: %v (%d files)", err, len(paths))
	}
	want := map[string]string{"SCHEMA.md": schemaHeader}
	for _, p := range paths {
		want[p] = licenceHeader
	}
	for p, header := range want {
		f, err := os.Open(p)
		if err != nil {
			t.Fatalf("failed to open %s: %v", p, err)
		}
		first, _ := bufio.NewReader(f).ReadString('\n')
		f.Close()
		if got := strings.TrimRight(first, "\n"); got != header {
			t.Errorf("%s starts %q, want %q", p, got, header)
		}
	}
}
