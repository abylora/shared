// SPDX-License-Identifier: AGPL-3.0-only

package relayverify

import (
	"bytes"
	"crypto/sha256"
	"log/slog"

	sigcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/policy"
)

// Pins is what a client build injects per environment (contract, Verifier inputs). shared/ ships
// no roots: production roots do not exist until the first ceremony, and staging overrides every
// value with staging's own, so a staging artifact fails closed in a production client.
type Pins struct {
	// CurrentRoot and NextRoot are the two root public keys, raw 32 bytes. Both are required
	// and they must differ: a root rotation must not need a flag day.
	CurrentRoot, NextRoot [32]byte
	// CurrentPolicy is a sigsum policy file, as text; required. NextPolicy is the policy a
	// client update ships BEFORE the producer starts submitting under it; nil or empty means
	// none is pinned. A proof is valid if it satisfies either (contract, Validity).
	CurrentPolicy, NextPolicy []byte
}

// LogValue makes Pins render as a placeholder, this package's rule for every type.
func (Pins) LogValue() slog.Value { return slog.StringValue(redacted) }

// Verifier verifies bundles against one set of pins. Immutable after NewVerifier, and safe for
// concurrent use.
type Verifier struct {
	currentRoot, nextRoot [32]byte
	// roots maps each pinned root's sigsum key_hash to the root.
	roots map[sigcrypto.Hash][32]byte
	// policies holds the current policy, then the next one if pinned.
	policies []*policy.Policy
}

// LogValue makes a Verifier render as a placeholder.
func (*Verifier) LogValue() slog.Value { return slog.StringValue(redacted) }

// redacted is what every type in this package renders as through slog.LogValuer.
const redacted = "REDACTED"

// NewVerifier checks the pins and parses the policies once. It refuses a zero root, identical
// roots, a missing current policy, a policy that does not parse, and a policy whose quorum holds
// with no witness at all.
func NewVerifier(p Pins) (*Verifier, error) {
	if p.CurrentRoot == ([32]byte{}) || p.NextRoot == ([32]byte{}) {
		return nil, ErrPinnedRootMissing
	}
	if p.CurrentRoot == p.NextRoot {
		return nil, ErrPinnedRootsIdentical
	}
	if len(p.CurrentPolicy) == 0 {
		return nil, ErrPinnedPolicyMissing
	}

	current, err := parsePolicy(p.CurrentPolicy)
	if err != nil {
		return nil, err
	}
	policies := []*policy.Policy{current}
	if len(p.NextPolicy) > 0 {
		next, err := parsePolicy(p.NextPolicy)
		if err != nil {
			return nil, err
		}
		policies = append(policies, next)
	}

	return &Verifier{
		currentRoot: p.CurrentRoot,
		nextRoot:    p.NextRoot,
		roots:       map[sigcrypto.Hash][32]byte{keyHash(p.CurrentRoot): p.CurrentRoot, keyHash(p.NextRoot): p.NextRoot},
		policies:    policies,
	}, nil
}

// keyHash is sigsum's key_hash: SHA-256 over the raw 32-byte key (contract, The signing
// certificate).
func keyHash(k [32]byte) sigcrypto.Hash { return sigcrypto.Hash(sha256.Sum256(k[:])) }

// parsePolicy parses sigsum policy text and refuses one that requires no witness. sigsum-go's
// error, which quotes the offending line, is discarded.
func parsePolicy(text []byte) (*policy.Policy, error) {
	pol, err := policy.ParseConfig(bytes.NewReader(text))
	if err != nil {
		return nil, ErrPinnedPolicyMalformed
	}
	// LOAD-BEARING. This package counts only the cosignatures inside the certificate's window,
	// and a quorum that holds with no witness would then accept a list cosigned entirely
	// outside it.
	if pol.ProcessQuorum(noWitnessCosigned{}).(bool) {
		return nil, ErrPinnedPolicyRequiresNoWitness
	}

	return pol, nil
}

// noWitnessCosigned evaluates a quorum as if no witness had cosigned. If the quorum still holds,
// the policy requires no witness: sigsum's "quorum none" is a 0-of-0 group, which holds.
type noWitnessCosigned struct{}

func (noWitnessCosigned) ProcessWitness(sigcrypto.Hash) any { return false }

func (noWitnessCosigned) ProcessGroup(k int, members []any) any {
	n := 0
	for _, m := range members {
		if m.(bool) {
			n++
		}
	}

	return n >= k
}
