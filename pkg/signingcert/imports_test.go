package signingcert

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
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
// nothing: a guard that parsed zero files would pass vacuously. A copy of relaylist's: test
// helpers cannot be shared across packages without exporting them.
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

// localName returns the name under which f imports path, or "" if it does not.
func localName(f parsedFile, path string) string {
	for _, spec := range f.file.Imports {
		p, _ := strconv.Unquote(spec.Path.Value)
		if p != path {
			continue
		}
		if spec.Name != nil {
			return spec.Name.Name
		}

		return path[strings.LastIndex(path, "/")+1:]
	}

	return ""
}

// selectorsOf calls fn for every pkg.Name selector in f, where pkg is the local name of path.
func selectorsOf(f parsedFile, path string, fn func(name string)) {
	local := localName(f, path)
	if local == "" {
		return
	}

	ast.Inspect(f.file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok && x.Name == local {
			fn(sel.Sel.Name)
		}

		return true
	})
}

// THE STANDARD LIBRARY ONLY, and within it:
//
//   - crypto/sha256 and crypto/ed25519 are the only crypto packages. Fingerprint needs both;
//     nothing else here has any use for cryptography.
//   - NO fmt AND NO log, relaylist's rule: every error is a constant string. log/slog is
//     permitted solely so the type can refuse to render itself.
//   - NO os: nothing here reads a file, in particular no key file.
//   - NOT relaylist, in either direction. The standard-library-only rule holds this side;
//     relaylist's own guard, which permits only transport, holds the other.
func TestThePackageImportsOnlyTheStandardLibraryWithNoLoggerAndOnlyTwoCryptoPackages(t *testing.T) {
	permittedCrypto := map[string]bool{"crypto/sha256": true, "crypto/ed25519": true}
	forbiddenExact := map[string]string{
		"fmt": "fmt is how input reaches an error string",
		"log": "nothing here logs",
		"os":  "nothing here reads a file -- in particular, no key file",
	}

	for _, f := range parsePackage(t) {
		for _, p := range f.imports {
			// A standard library path has no dot in its first element.
			if strings.Contains(strings.SplitN(p, "/", 2)[0], ".") {
				t.Errorf("%s imports %q: only the standard library is permitted", f.name, p)
			}
			if why, ok := forbiddenExact[p]; ok {
				t.Errorf("%s imports %q: %s", f.name, p, why)
			}
			if (p == "crypto" || strings.HasPrefix(p, "crypto/")) && !permittedCrypto[p] {
				t.Errorf("%s imports %q: only crypto/sha256 and crypto/ed25519 are permitted", f.name, p)
			}
		}
	}
}

// crypto/ed25519 FOR ITS PUBLIC-KEY TYPE ONLY. Nothing here holds, derives or uses a private
// key: signing is the producer's, and the root signs only on an air-gapped machine.
func TestThePackageTouchesNoPrivateKey(t *testing.T) {
	signingSide := map[string]bool{
		"Sign": true, "GenerateKey": true, "NewKeyFromSeed": true,
		"PrivateKey": true, "PrivateKeySize": true, "SeedSize": true,
	}

	for _, f := range parsePackage(t) {
		selectorsOf(f, "crypto/ed25519", func(name string) {
			if signingSide[name] {
				t.Errorf("%s uses ed25519.%s; this package holds public keys only", f.name, name)
			}
		})
	}
}

// NO CLOCK. Whether a certificate is in its window is judged against the witnesses' clock,
// never the local one (contract, Validity), and that judgement is not this package's. A call
// of time.Now, time.Since or time.Until anywhere here fails this test.
func TestThePackageReadsNoClock(t *testing.T) {
	clockReads := map[string]bool{"Now": true, "Since": true, "Until": true}

	for _, f := range parsePackage(t) {
		selectorsOf(f, "time", func(name string) {
			if clockReads[name] {
				t.Errorf("%s reads the clock through time.%s", f.name, name)
			}
		})
	}
}
