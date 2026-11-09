// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// buildToolchain is the ruled toolchain (abylora-master, 2026-11-09): go1.27.3, or the newer 1.27
// patch the build used, which the handoff then records beside the sha256. It is the one place Go
// code names it.
const buildToolchain = "go1.27.3"

// reproducibleBuild is the documented build command. It pins everything EXCEPT the platform: no
// ceremony machine has been chosen, and staging and prod may use different ones, so GOOS and
// GOARCH are placeholders the operator replaces, and each ceremony records its platform beside
// its binary's hash (ruled 2026-11-09). GOAMD64 and GOARM64 are both set, because each is read
// only for its own GOARCH, and an exported value in the operator's shell would otherwise change
// the binary.
const reproducibleBuild = "GOENV=off GOFLAGS= GOWORK=off GOEXPERIMENT= GOFIPS140=off GOTOOLCHAIN=" + buildToolchain +
	" CGO_ENABLED=0 GOAMD64=v1 GOARM64=v8.0 GOOS=<goos> GOARCH=<goarch>" +
	" go build -trimpath -buildvcs=false -o signing-certificate ./cmd/signing-certificate"

// The rule sentences the doc must state, verbatim.
const (
	amd64Rule     = "When GOARCH=amd64, GOAMD64=v1 is fixed."
	arm64Rule     = "When GOARCH=arm64, GOARM64=v8.0 is fixed."
	otherArchRule = "The documented build is for amd64 and arm64 only."
	// Ruled 2026-11-09 by abylora-master: the scope is a stated limit, never a silent gap.
	otherArchLimit = "Another GOARCH first needs its variable pinned here."
)

func packageDoc(t *testing.T) string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "doc.go", nil, parser.ParseComments|parser.PackageClauseOnly)
	if err != nil {
		t.Fatalf("failed to parse doc.go: %v", err)
	}
	if f.Doc == nil {
		t.Fatal("doc.go has no package comment")
	}
	return strings.Join(strings.Fields(f.Doc.Text()), " ")
}

func TestThePackageDocStatesTheReproducibleBuild(t *testing.T) {
	doc := packageDoc(t)
	for _, want := range []string{reproducibleBuild, amd64Rule, arm64Rule, otherArchRule, otherArchLimit} {
		if !strings.Contains(doc, want) {
			t.Errorf("the package doc does not state, verbatim:\n%s", want)
		}
	}
}

// EVERY PIN, ONCE, AND NO PLATFORM. Dropping a pin, or writing a concrete GOOS or GOARCH into
// the documented command, fails here by name.
func TestTheBuildCommandPinsNoPlatform(t *testing.T) {
	fields := strings.Fields(reproducibleBuild)
	count := map[string]int{}
	for _, f := range fields {
		count[f]++
	}
	for _, pin := range []string{"GOENV=off", "GOFLAGS=", "GOWORK=off", "GOEXPERIMENT=", "GOFIPS140=off",
		"GOTOOLCHAIN=" + buildToolchain, "CGO_ENABLED=0", "GOAMD64=v1", "GOARM64=v8.0", "-trimpath", "-buildvcs=false"} {
		if count[pin] != 1 {
			t.Errorf("%q appears %d times in the build command, want exactly 1", pin, count[pin])
		}
	}
	for _, f := range fields {
		if (strings.HasPrefix(f, "GOOS=") && f != "GOOS=<goos>") || (strings.HasPrefix(f, "GOARCH=") && f != "GOARCH=<goarch>") {
			t.Errorf("the build command pins a platform (%s); GOOS and GOARCH are parameters", f)
		}
	}
	if count["GOOS=<goos>"] != 1 || count["GOARCH=<goarch>"] != 1 {
		t.Error("the build command must carry GOOS=<goos> and GOARCH=<goarch> exactly once each")
	}
}
