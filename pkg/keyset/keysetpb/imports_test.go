// SPDX-License-Identifier: AGPL-3.0-only

package keysetpb

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

// licenceHeader is the first line of every handwritten file of this package, of the .proto it
// is generated from, and of tools/tools.go.
const licenceHeader = "// SPDX-License-Identifier: AGPL-3.0-only"

// parsedFile is one non-test Go file of this package, with its imports resolved to paths, and
// whether it carries a generator's "Code generated ... DO NOT EDIT." header.
type parsedFile struct {
	name      string
	generated bool
	imports   []string
}

// parsePackage parses every non-test Go file in the package directory, with comments, which
// is what ast.IsGenerated needs. It refuses to return no handwritten file or no generated
// file: a guard that checked none of either would pass vacuously. Copied in shape from
// relaylist's, because test helpers cannot be shared across packages without exporting them.
func parsePackage(t *testing.T) []parsedFile {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("failed to read the package directory: %v", err)
	}

	fset := token.NewFileSet()
	var files []parsedFile
	var handwritten, generated int

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, err := parser.ParseFile(fset, name, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", name, err)
		}

		pf := parsedFile{name: name, generated: ast.IsGenerated(file)}
		for _, spec := range file.Imports {
			p, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("failed to unquote an import path in %s: %v", name, err)
			}
			pf.imports = append(pf.imports, p)
		}
		if pf.generated {
			generated++
		} else {
			handwritten++
		}
		files = append(files, pf)
	}

	if handwritten == 0 {
		t.Fatal("found no handwritten non-test Go file; this guard would pass vacuously")
	}
	if generated == 0 {
		t.Fatal("found no generated Go file; this guard would pass vacuously")
	}

	return files
}

func isStandardLibrary(path string) bool {
	// A standard library path has no dot in its first element.
	return !strings.Contains(strings.SplitN(path, "/", 2)[0], ".")
}

func under(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// importRefusal returns why a file of this package may not import path, or "" if it may.
//
//   - NO wireguard-go AND NO wgctrl, IN ANY FILE. This module's CLAUDE.md: the node agent
//     drives the kernel module through wgctrl, and a wire library must not hand any consumer a
//     WireGuard implementation it will never use. Any path naming either is refused, mirrors
//     included.
//   - NO LOGGER, IN ANY FILE, generated included. These messages carry every device's public
//     key and tunnel addresses, and rule 11 says a malformed entry is never logged.
//   - GENERATED FILES: THE STANDARD LIBRARY, PROTOBUF AND GRPC, AND NOTHING ELSE. These are this
//     module's first third-party dependencies. A new import from a regenerated file changes
//     every consumer's go.mod, so it fails here until someone has looked at it.
//   - HANDWRITTEN FILES: THE STANDARD LIBRARY ONLY, AND NO fmt, which is how a key or an
//     address reaches a string.
func importRefusal(path string, generated bool) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "wireguard") || strings.Contains(lower, "wgctrl") || under(path, "golang.zx2c4.com"):
		return "no wireguard-go and no wgctrl in shared"
	case under(path, "log") || under(path, "google.golang.org/grpc/grpclog"):
		return "nothing here logs: these messages carry device public keys and tunnel addresses"
	case generated:
		if isStandardLibrary(path) || under(path, "google.golang.org/protobuf") || under(path, "google.golang.org/grpc") {
			return ""
		}
		return "generated code may import only the standard library, protobuf and grpc; a new import changes every consumer's go.mod"
	case !isStandardLibrary(path):
		return "handwritten code here imports the standard library only"
	case path == "fmt":
		return "fmt is how a key or an address reaches a string"
	}

	return ""
}

// Every refusal of importRefusal is driven here, and so is every permission it grants, so a
// branch that stopped firing would fail this test.
func TestImportRefusalRefusesEachForbiddenImport(t *testing.T) {
	for _, tc := range []struct {
		path      string
		generated bool
		refused   bool
	}{
		{"golang.zx2c4.com/wireguard/device", false, true},
		{"golang.zx2c4.com/wireguard/wgctrl", true, true},
		{"github.com/WireGuard/wgctrl-go", true, true},
		{"log", false, true},
		{"log/slog", true, true},
		{"google.golang.org/grpc/grpclog", true, true},
		{"fmt", false, true},
		{"google.golang.org/protobuf/proto", false, true},
		{"github.com/example/other", true, true},
		{"google.golang.org/protobuf/reflect/protoreflect", true, false},
		{"google.golang.org/grpc/codes", true, false},
		{"reflect", true, false},
		{"fmt", true, false},
		{"strings", false, false},
	} {
		if got := importRefusal(tc.path, tc.generated) != ""; got != tc.refused {
			t.Errorf("importRefusal(%q, generated=%v) refused = %v, want %v", tc.path, tc.generated, got, tc.refused)
		}
	}
}

// No file of this package, handwritten or generated, imports anything importRefusal refuses.
func TestNoFileHereImportsWireGuardWgctrlOrALoggerAndEachKindStaysInItsLane(t *testing.T) {
	for _, f := range parsePackage(t) {
		for _, p := range f.imports {
			if why := importRefusal(p, f.generated); why != "" {
				t.Errorf("%s imports %q: %s", f.name, p, why)
			}
		}
	}
}

// GENERATED FILES KEEP THEIR GENERATOR HEADER. The two files below are the generated ones, and
// both are recognised as generated by the standard rule (go.dev/s/generatedcode), which is
// what keeps them out of the handwritten checks and tells a reader not to edit them.
func TestGeneratedFilesKeepTheirGeneratorHeader(t *testing.T) {
	want := map[string]bool{"keyset.pb.go": true, "keyset_grpc.pb.go": true}
	for _, f := range parsePackage(t) {
		if f.generated != want[f.name] {
			t.Errorf("%s generated = %v, want %v", f.name, f.generated, want[f.name])
		}
		delete(want, f.name)
	}
	for name := range want {
		t.Errorf("%s is missing", name)
	}
}

// EVERY HANDWRITTEN FILE CARRIES THE LICENCE HEADER as its first line (AGPL-3, D12): each
// handwritten .go file here, tests included, the .proto, and tools/tools.go. Generated files
// inherit the line from the .proto, and the drift test holds that.
func TestEveryHandwrittenFileCarriesTheLicenceHeader(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("failed to list the package: %v", err)
	}
	paths = append(paths,
		filepath.Join(moduleRoot, "proto", "abylora", "keyset", "v1", "keyset.proto"),
		filepath.Join(moduleRoot, "tools", "tools.go"),
	)

	for _, p := range paths {
		if strings.HasSuffix(p, ".pb.go") {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			t.Fatalf("failed to open %s: %v", p, err)
		}
		first, _ := bufio.NewReader(f).ReadString('\n')
		f.Close()
		if strings.TrimRight(first, "\n") != licenceHeader {
			t.Errorf("%s starts %q, want %q", p, strings.TrimRight(first, "\n"), licenceHeader)
		}
	}
}
