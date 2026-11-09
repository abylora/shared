// SPDX-License-Identifier: AGPL-3.0-only

package relayverify

import (
	"bytes"
	"testing"
)

func TestTheBaseBundleVerifiesAndYieldsVectorL(t *testing.T) {
	got := requireAccepted(t, baseBundle(t))

	d := got.Document()
	if d.Version() != 1 || len(d.Relays()) != 1 || d.Relays()[0].NodeID() != "00000000-0000-4000-8000-000000000001" {
		t.Error("the verified document is not vector L")
	}
	if got.Expired() {
		t.Error("vector L is marked expired within its own validity")
	}
}

// Clients must REQUIRE a transparency inclusion proof, not check one when present (contract,
// Rules); both signatures are logged.
func TestABundleWithNoCertificateProofIsRefused(t *testing.T) {
	b := baseBundle(t)
	b.SigningCertificateProof = nil
	requireRefused(t, b, ErrCertificateProofMissing)
}

func TestACertificateProofThatIsNotASigsumProofIsRefused(t *testing.T) {
	b := baseBundle(t)
	b.SigningCertificateProof = []byte("version=2\nlog=zz\n")
	requireRefused(t, b, ErrCertificateProofMalformed)
}

// A certificate verifies only against a pinned root. The list's proof carries the signing key's
// leaf, and the signing key is no pinned root.
func TestACertificateSignedByNoPinnedRootIsRefused(t *testing.T) {
	requireRefused(t, certBundle(t, "certificate/vector-c.json", "list/vector-l.proof"), ErrCertificateNotSignedByRoot)
}

func TestACertificateWhoseOctetsWereAlteredIsRefused(t *testing.T) {
	b := baseBundle(t)
	b.SigningCertificate = bytes.Replace(b.SigningCertificate, []byte(`"staging"`), []byte(`"prod"`), 1)
	requireRefused(t, b, ErrCertificateSignatureInvalid)
}

// Logged on the current policy's log, but cosigned only by a witness neither policy names.
func TestACertificateProofValidUnderNeitherPolicyIsRefused(t *testing.T) {
	requireRefused(t, certBundle(t, "certificate/vector-c.json", "certificate/vector-c.neither.proof"), ErrCertificateProofInvalid)
}

// alterFirstNodeHash flips the last hex digit of the first node_hash line: only the inclusion
// path changes, so every signature still verifies and only inclusion can refuse it.
func alterFirstNodeHash(t *testing.T, p []byte) []byte {
	t.Helper()
	i := bytes.Index(p, []byte("node_hash="))
	if i < 0 {
		t.Fatal("the proof has no node_hash line")
	}
	j := i + bytes.IndexByte(p[i:], '\n') - 1

	out := bytes.Clone(p)
	if out[j] == '0' {
		out[j] = '1'
	} else {
		out[j] = '0'
	}

	return out
}

func TestACertificateProofWhoseInclusionPathWasAlteredIsRefused(t *testing.T) {
	b := baseBundle(t)
	b.SigningCertificateProof = alterFirstNodeHash(t, b.SigningCertificateProof)
	requireRefused(t, b, ErrCertificateProofInvalid)
}

// A proof is valid if it satisfies either pinned policy (contract, Validity).
func TestACertificateProofValidOnlyUnderTheNextPolicyIsAccepted(t *testing.T) {
	requireAccepted(t, certBundle(t, "certificate/vector-c.json", "certificate/vector-c.next.proof"))
}

// Contract, Strict parsing: in both documents a duplicate key is refused. The certificate is
// decoded strictly by signingcert, after its signature and proof verified.
func TestACertificateWithADuplicateKeyIsRefused(t *testing.T) {
	requireRefused(t, certBundle(t, "certificate/duplicate-key.json", "certificate/duplicate-key.current.proof"), ErrCertificateMalformed)
}

// Its root must equal the fingerprint of the key that signed it: signed by the current root,
// this one names the next root.
func TestACertificateWhoseRootNamesAnotherKeyIsRefused(t *testing.T) {
	requireRefused(t, certBundle(t, "certificate/root-names-the-other-root.json",
		"certificate/root-names-the-other-root.current.proof"), ErrCertificateRootMismatch)
}

// A certificate whose key equals EITHER pinned root is refused.
func TestACertificateWhoseKeyIsAPinnedRootIsRefused(t *testing.T) {
	for _, name := range []string{"key-is-next-root", "next-root-certifies-current-root"} {
		t.Run(name, func(t *testing.T) {
			requireRefused(t, certBundle(t, "certificate/"+name+".json", "certificate/"+name+".current.proof"), ErrCertificateKeyIsRoot)
		})
	}
}

// GUARD. The certificate's proof was cosigned 17 days before its not_before -- a certificate is
// issued ahead of use -- and the witness window applies to the LIST's own proof only (contract,
// Validity). Red only if a change applies the window to the certificate's proof.
func TestTheCertificatesOwnProofIsNotHeldToItsWindow(t *testing.T) {
	requireAccepted(t, baseBundle(t))
}
