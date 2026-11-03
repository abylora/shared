// SPDX-License-Identifier: AGPL-3.0-only

package relayverify

import (
	"encoding/hex"
	"strings"
	"testing"
)

func hexKey(b byte) string { return strings.Repeat(hex.EncodeToString([]byte{b}), 32) }

// A well-formed one-witness policy over throwaway keys; ParseConfig checks syntax, not points.
var oneWitnessPolicy = []byte("log " + hexKey(0x11) + "\nwitness w1 " + hexKey(0x22) + "\nquorum w1\n")

func validPins(t *testing.T) Pins {
	return Pins{CurrentRoot: mustHex32(t, testRootPubHex), NextRoot: mustHex32(t, hexKey(0x33)), CurrentPolicy: oneWitnessPolicy}
}

func TestNewVerifierRefuses(t *testing.T) {
	// Witnesses are listed, but the quorum needs none of them: under a filtered cosignature set
	// it would accept a list cosigned entirely outside the certificate's window.
	noWitness := []byte("log " + hexKey(0x11) + "\nwitness w1 " + hexKey(0x22) + "\nquorum none\n")

	cases := []struct {
		name   string
		mutate func(*Pins)
		want   error
	}{
		{"no current root", func(p *Pins) { p.CurrentRoot = [32]byte{} }, ErrPinnedRootMissing},
		{"no next root", func(p *Pins) { p.NextRoot = [32]byte{} }, ErrPinnedRootMissing},
		{"identical roots", func(p *Pins) { p.NextRoot = p.CurrentRoot }, ErrPinnedRootsIdentical},
		{"no current policy", func(p *Pins) { p.CurrentPolicy = nil }, ErrPinnedPolicyMissing},
		{"a malformed current policy", func(p *Pins) { p.CurrentPolicy = []byte("log nothex\nquorum none\n") }, ErrPinnedPolicyMalformed},
		{"a malformed next policy", func(p *Pins) { p.NextPolicy = []byte("witness\n") }, ErrPinnedPolicyMalformed},
		{"a current policy with no quorum line", func(p *Pins) { p.CurrentPolicy = []byte("log " + hexKey(0x11) + "\n") }, ErrPinnedPolicyMalformed},
		{"a current policy requiring no witness", func(p *Pins) { p.CurrentPolicy = noWitness }, ErrPinnedPolicyRequiresNoWitness},
		{"a next policy requiring no witness", func(p *Pins) { p.NextPolicy = noWitness }, ErrPinnedPolicyRequiresNoWitness},
	}

	for _, tc := range cases {
		p := validPins(t)
		tc.mutate(&p)
		if v, err := NewVerifier(p); err != tc.want || v != nil {
			t.Errorf("%s: NewVerifier() = %v, %v; want nil, %v", tc.name, v, err, tc.want)
		}
	}
}

func TestNewVerifierAcceptsAOneWitnessPolicyAndNoNextPolicy(t *testing.T) {
	if v, err := NewVerifier(validPins(t)); err != nil || v == nil {
		t.Errorf("NewVerifier() = %v, %v; want a verifier, nil", v, err)
	}
}
