// SPDX-License-Identifier: AGPL-3.0-only

package relayverify

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
// nothing: a guard that parsed zero files would pass vacuously. A copy of signingcert's: test
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

// THE ALLOW-LIST, and each entry is a ruling:
//
//   - The standard library, minus each of these trees, BY PREFIX, so a subpackage cannot slip
//     past: fmt and log/... (every error is a constant sentinel, and nothing here logs; log/slog
//     alone is permitted, solely so the types can refuse to render themselves); os/... (no file,
//     in particular no key file, no environment and no process: os/exec included); net/...
//     (nothing resolves or dials: hostname is a label, never resolved, and verification needs no
//     outbound connection); syscall and unsafe (no way around any of the above); and every
//     crypto package but crypto/ed25519 and crypto/sha256.
//   - shared's relaylist and signingcert.
//   - Exactly sigsum-go's pkg/crypto, pkg/policy, pkg/proof and pkg/types: never pkg/client,
//     pkg/submit, pkg/key or pkg/log.
func TestThePackageImportsOnlyTheAllowList(t *testing.T) {
	allowed := map[string]bool{
		"github.com/abylora/shared/pkg/relaylist":   true,
		"github.com/abylora/shared/pkg/signingcert": true,
		"sigsum.org/sigsum-go/pkg/crypto":           true,
		"sigsum.org/sigsum-go/pkg/policy":           true,
		"sigsum.org/sigsum-go/pkg/proof":            true,
		"sigsum.org/sigsum-go/pkg/types":            true,
	}
	permittedCrypto := map[string]bool{"crypto/ed25519": true, "crypto/sha256": true}
	forbiddenTrees := []string{"fmt", "log", "os", "net", "syscall", "unsafe"}
	permittedInForbiddenTrees := map[string]bool{"log/slog": true}
	inForbiddenTree := func(p string) bool {
		for _, root := range forbiddenTrees {
			if p == root || strings.HasPrefix(p, root+"/") {
				return !permittedInForbiddenTrees[p]
			}
		}

		return false
	}

	for _, f := range parsePackage(t) {
		for _, p := range f.imports {
			thirdParty := strings.Contains(strings.SplitN(p, "/", 2)[0], ".")
			switch {
			case thirdParty && !allowed[p]:
				t.Errorf("%s imports %q: not on the allow-list", f.name, p)
			case inForbiddenTree(p):
				t.Errorf("%s imports %q: forbidden", f.name, p)
			case (p == "crypto" || strings.HasPrefix(p, "crypto/")) && !permittedCrypto[p]:
				t.Errorf("%s imports %q: only crypto/ed25519 and crypto/sha256 are permitted", f.name, p)
			}
		}
	}
}

// NO DOT IMPORT AND NO BLANK IMPORT. A dot import makes time.Now callable as plain Now, which
// the selector-based guards below cannot see; a blank import runs a package's init for its side
// effects alone. Neither has a use here, so neither is permitted in a non-test file.
func TestThePackageHasNoDotOrBlankImport(t *testing.T) {
	for _, f := range parsePackage(t) {
		for _, spec := range f.file.Imports {
			if spec.Name != nil && (spec.Name.Name == "." || spec.Name.Name == "_") {
				t.Errorf("%s imports %s as %q: dot and blank imports are refused", f.name, spec.Path.Value, spec.Name.Name)
			}
		}
	}
}

// NO CLOCK. Certificate validity is judged against the witnesses' clock, never the local one
// (contract, Validity), and asOf -- used only for the advisory Expired flag -- is passed in.
func TestThePackageReadsNoClock(t *testing.T) {
	for _, f := range parsePackage(t) {
		selectorsOf(f, "time", func(name string) {
			if name == "Now" || name == "Since" || name == "Until" {
				t.Errorf("%s reads the clock through time.%s; asOf is passed in", f.name, name)
			}
		})
	}
}

// PUBLIC KEYS ONLY (invariant 3), and leaf signatures are verified by verifyEd25519, never by
// sigsum-go's crypto.Verify or types.VerifyLeaf*, so the Ed25519 rule cannot change with a
// dependency upgrade. Method calls (Leaf.Verify, SigsumProof.Verify) cannot be resolved
// syntactically; this package does not call them, and doc.go says why.
func TestThePackageTouchesNoPrivateKeyAndUsesOnlyItsOwnLeafVerifier(t *testing.T) {
	banned := map[string]map[string]bool{
		"crypto/ed25519": {
			"Sign": true, "GenerateKey": true, "NewKeyFromSeed": true,
			"PrivateKey": true, "SeedSize": true, "PrivateKeySize": true,
		},
		"sigsum.org/sigsum-go/pkg/crypto": {
			"NewEd25519Signer": true, "NewKeyPair": true, "SignerFromHex": true,
			"Ed25519Signer": true, "PrivateKey": true, "Verify": true,
		},
		"sigsum.org/sigsum-go/pkg/types": {
			"SignLeafMessage": true, "SignLeafChecksum": true, "VerifyLeafMessage": true, "VerifyLeafChecksum": true,
		},
	}

	for _, f := range parsePackage(t) {
		for path, names := range banned {
			selectorsOf(f, path, func(name string) {
				if names[name] {
					t.Errorf("%s uses %s.%s", f.name, path, name)
				}
			})
		}
	}
}

// Pinned policies are the text the client injects. ByName and its relatives read
// /etc/sigsum/policy and $SIGSUM_POLICY_DIR -- an environment override of a trust anchor -- and
// reach sigsum-go's own logger.
func TestThePackageNeverLooksUpANamedPolicy(t *testing.T) {
	banned := map[string]bool{
		"ByName": true, "ReadByName": true, "BuiltinByName": true, "ReadBuiltinByName": true,
		"ReadPolicyFile": true, "List": true, "BuiltinList": true,
	}

	for _, f := range parsePackage(t) {
		selectorsOf(f, "sigsum.org/sigsum-go/pkg/policy", func(name string) {
			if banned[name] {
				t.Errorf("%s calls policy.%s", f.name, name)
			}
		})
	}
}
