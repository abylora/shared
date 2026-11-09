// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// parsedFile is one non-test Go file under cmd/.
type parsedFile struct {
	path string
	file *ast.File
}

// parseCmdTree parses every non-test Go file under cmd/ -- this package's parent -- so a future
// command is held to the same rules until someone deliberately changes this guard. It refuses to
// pass vacuously, and fails unless this package's own main.go was among the files parsed. The
// approach is pkg/relayverify's and pkg/signingcert's imports_test.go.
func parseCmdTree(t *testing.T) []parsedFile {
	t.Helper()

	fset := token.NewFileSet()
	var files []parsedFile
	sawMain := false
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "testdata" {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		if filepath.ToSlash(path) == "../signing-certificate/main.go" {
			sawMain = true
		}
		files = append(files, parsedFile{path: path, file: f})
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk cmd/: %v", err)
	}
	if len(files) == 0 || !sawMain {
		t.Fatalf("parsed %d files and main.go was %v; this guard would pass vacuously", len(files), sawMain)
	}
	return files
}

func importPaths(f *ast.File) []string {
	var paths []string
	for _, spec := range f.Imports {
		p, _ := strconv.Unquote(spec.Path.Value)
		paths = append(paths, p)
	}
	return paths
}

// The one third-party import a command may have.
var permittedThirdParty = map[string]bool{"github.com/abylora/shared/pkg/signingcert": true}

// forbiddenTrees are refused by prefix, so a subpackage cannot slip past. Each entry is a ruling.
var forbiddenTrees = []struct{ root, why string }{
	{"net", "no network: the command runs on the air-gapped machine"},
	{"crypto", "no cryptography: the command signs nothing and reads no private key; Fingerprint is signingcert's"},
	{"encoding/json", "the certificate's JSON is signingcert.Encode's alone"},
	{"syscall", "no way around the rules here"},
	{"unsafe", "no way around the rules here"},
	{"plugin", "no code loaded at run time"},
	{"C", "the build is CGO_ENABLED=0"},
	{"runtime/cgo", "the build is CGO_ENABLED=0"},
	{"log", "nothing logs: stderr carries one refusal line"},
}

// forbiddenImports returns "path: reason" for every import f may not have.
func forbiddenImports(f *ast.File) []string {
	var out []string
	for _, p := range importPaths(f) {
		if strings.Contains(strings.SplitN(p, "/", 2)[0], ".") {
			if !permittedThirdParty[p] {
				out = append(out, p+": only signingcert is permitted outside the standard library")
			}
			continue
		}
		if strings.HasPrefix(p, "os/") {
			out = append(out, p+": no process, signal or user lookup; os itself is permitted")
			continue
		}
		for _, tr := range forbiddenTrees {
			if p == tr.root || strings.HasPrefix(p, tr.root+"/") {
				out = append(out, p+": "+tr.why)
			}
		}
	}
	return out
}

// localName returns the name under which f imports path, or "" if it does not.
func localName(f *ast.File, path string) string {
	for _, spec := range f.Imports {
		if p, _ := strconv.Unquote(spec.Path.Value); p != path {
			continue
		}
		if spec.Name != nil {
			return spec.Name.Name
		}
		return path[strings.LastIndex(path, "/")+1:]
	}
	return ""
}

// clockReads finds every selector X.Sel where X is the local name of "time" (an alias
// included) and Sel is Now, Since or Until -- a call and a method value alike.
func clockReads(f *ast.File) []string {
	local := localName(f, "time")
	if local == "" || local == "_" || local == "." {
		return nil
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok && x.Name == local {
			switch sel.Sel.Name {
			case "Now", "Since", "Until":
				out = append(out, "time."+sel.Sel.Name)
			}
		}
		return true
	})
	return out
}

// dotOrBlankImports returns every dot or blank import in f.
func dotOrBlankImports(f *ast.File) []string {
	var out []string
	for _, spec := range f.Imports {
		if spec.Name != nil && (spec.Name.Name == "." || spec.Name.Name == "_") {
			out = append(out, spec.Path.Value+" imported as "+strconv.Quote(spec.Name.Name))
		}
	}
	return out
}

func parseSource(t *testing.T, src string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "synthetic.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("failed to parse the synthetic source: %v", err)
	}
	return f
}

// THE DETECTORS BITE. Every forbidden path, the three clock reads through an alias, and both a
// dot and a blank import are reported. This is how the guards below are shown to work without
// a mutation loop.
func TestTheGuardsSeeWhatTheyForbid(t *testing.T) {
	f := parseSource(t, `package p

import (
	"C"
	"crypto/ed25519"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os/exec"
	"plugin"
	"runtime/cgo"
	"syscall"
	"unsafe"
	"sigsum.org/sigsum-go/pkg/key"
	"github.com/abylora/shared/pkg/relayverify"
	clock "time"
	. "strings"
	_ "embed"
)

var _ = clock.Now
var _ = clock.Since
var _ = clock.Until
`)
	wantImports := []string{"C", "crypto/ed25519", "encoding/json", "log/slog", "net", "net/http", "os/exec",
		"plugin", "runtime/cgo", "syscall", "unsafe", "sigsum.org/sigsum-go/pkg/key",
		"github.com/abylora/shared/pkg/relayverify"}
	reported := map[string]bool{}
	for _, msg := range forbiddenImports(f) {
		path, _, _ := strings.Cut(msg, ": ")
		reported[path] = true
	}
	for _, p := range wantImports {
		if !reported[p] {
			t.Errorf("forbiddenImports missed %q", p)
		}
	}
	if n := len(clockReads(f)); n != 3 {
		t.Errorf("clockReads found %d reads through the alias, want 3", n)
	}
	if n := len(dotOrBlankImports(f)); n != 2 {
		t.Errorf("dotOrBlankImports found %d, want 2 (one dot, one blank)", n)
	}
}

// THE DETECTORS ARE NOT OVER-BROAD: the command's real import set and time.Parse pass.
func TestTheGuardsPermitWhatTheCommandNeeds(t *testing.T) {
	f := parseSource(t, `package p

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/abylora/shared/pkg/signingcert"
)

var _ = time.Parse
`)
	if got := forbiddenImports(f); len(got) != 0 {
		t.Errorf("forbiddenImports refused a permitted import: %v", got)
	}
	if got := clockReads(f); len(got) != 0 {
		t.Errorf("clockReads reported %v for time.Parse", got)
	}
}

// NO NETWORK, NO CRYPTOGRAPHY, NO JSON OF ITS OWN. The command runs on the air-gapped machine,
// signs nothing, reads no private key, and its certificate octets are signingcert.Encode's alone.
func TestCmdImportsNothingForbidden(t *testing.T) {
	for _, pf := range parseCmdTree(t) {
		for _, msg := range forbiddenImports(pf.file) {
			t.Errorf("%s imports %s", pf.path, msg)
		}
	}
}

// NO CLOCK. Every instant comes from a flag.
func TestCmdReadsNoClock(t *testing.T) {
	for _, pf := range parseCmdTree(t) {
		for _, read := range clockReads(pf.file) {
			t.Errorf("%s reads the clock through %s; every instant comes from a flag", pf.path, read)
		}
	}
}

// NO DOT AND NO BLANK IMPORT: a dot import of time makes Now invisible to the guard above.
func TestCmdHasNoDotOrBlankImport(t *testing.T) {
	for _, pf := range parseCmdTree(t) {
		for _, imp := range dotOrBlankImports(pf.file) {
			t.Errorf("%s: %s", pf.path, imp)
		}
	}
}
