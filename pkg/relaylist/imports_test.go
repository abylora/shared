package relaylist

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
)

// parsedFile is one non-test Go file of this package, parsed with its imports resolved to
// paths.
type parsedFile struct {
	name    string
	file    *ast.File
	imports []string
}

// parsePackage parses every non-test Go file in the package directory, and refuses to return
// nothing: a guard that parsed zero files would pass vacuously.
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

		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", name, err)
		}

		pf := parsedFile{name: name, file: file}
		for _, spec := range file.Imports {
			p, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("failed to unquote an import path in %s: %v", name, err)
			}
			pf.imports = append(pf.imports, p)
		}
		files = append(files, pf)
	}

	if len(files) == 0 {
		t.Fatal("found no non-test Go files to check; this guard would pass vacuously")
	}

	return files
}

// THREE RULES, ONE GUARD, and each is a ruling rather than a taste.
//
//   - THE STANDARD LIBRARY PLUS shared/pkg/transport, AND NOTHING ELSE. Every consumer --
//     the producer and all four clients -- inherits this package's imports, so a third-party
//     require here is one in every one of them. transport is permitted because
//     endpoints[].kind IS transport.Kind (D26). FetchTransport still is not, and must never
//     be merged with it: TestNoFetchTransportIsADataPlaneKind holds that half.
//   - NO fmt AND NO log. A Relay holds a node's hostname, addresses and provider, which D19
//     keeps out of a log line even though the list publishes them -- internal/entities/node's
//     reason for the same ban. Every error here is a constant string or names a node_id.
//     log/slog is permitted: the package imports it solely so its types can refuse to render
//     themselves.
//   - NO KEY MATERIAL. No crypto package and no os: nothing here signs, loads a key, or reads
//     a file. Signing is the producer's, in its own package.
func TestThePackageImportsOnlyTheStandardLibraryAndTransportAndNoLoggerOrKeyMaterial(t *testing.T) {
	const transportPath = "github.com/abylora/shared/pkg/transport"

	forbiddenExact := map[string]string{
		"fmt": "fmt is how a hostname or an address reaches an error string (D19)",
		"log": "a Relay holds a hostname, addresses and a provider (D19)",
		"os":  "nothing here reads a file -- in particular, no key file",
	}
	forbiddenPrefix := map[string]string{
		"crypto/": "no key material in the wire types; signing is the producer's",
	}

	for _, f := range parsePackage(t) {
		for _, p := range f.imports {
			// A standard library path has no dot in its first element.
			if p != transportPath && strings.Contains(strings.SplitN(p, "/", 2)[0], ".") {
				t.Errorf("%s imports %q: only the standard library and %s are permitted", f.name, p, transportPath)
			}
			if why, ok := forbiddenExact[p]; ok {
				t.Errorf("%s imports %q: %s", f.name, p, why)
			}
			for prefix, why := range forbiddenPrefix {
				if p == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(p, prefix) {
					t.Errorf("%s imports %q: %s", f.name, p, why)
				}
			}
		}
	}
}

// NO CLOCK. generated_at and expires_at are passed in, which is what makes the golden-byte
// test possible at all; the command that builds a document owns the clock. A call of
// time.Now, time.Since or time.Until anywhere here fails this test, whatever the import is
// called locally.
func TestThePackageReadsNoClock(t *testing.T) {
	clockReads := map[string]bool{"Now": true, "Since": true, "Until": true}

	for _, f := range parsePackage(t) {
		timeName := ""
		for _, spec := range f.file.Imports {
			p, _ := strconv.Unquote(spec.Path.Value)
			if p != "time" {
				continue
			}
			timeName = path.Base(p)
			if spec.Name != nil {
				timeName = spec.Name.Name
			}
		}
		if timeName == "" {
			continue
		}

		ast.Inspect(f.file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == timeName && clockReads[sel.Sel.Name] {
				t.Errorf("%s reads the clock through time.%s; the instants are passed in", f.name, sel.Sel.Name)
			}

			return true
		})
	}
}
