// SPDX-License-Identifier: AGPL-3.0-only

package relayverify

import (
	"log/slog"
	"time"

	"github.com/abylora/shared/pkg/relaylist"
	"github.com/abylora/shared/pkg/signingcert"
	"sigsum.org/sigsum-go/pkg/types"
)

// The contract's four bundle files, named the way sigsum's own tools name them (contract, The
// signing certificate). There is no separate signature file: a proof's leaf= line holds it.
const (
	FileRelayList               = "relay-list.json"
	FileRelayListProof          = "relay-list.json.proof"
	FileSigningCertificate      = "signing-certificate.json"
	FileSigningCertificateProof = "signing-certificate.json.proof"
)

// Bundle is the four files exactly as received. Nothing in it is trusted until Verify returns.
// The verifier bounds no size; a client bounds what it fetches.
type Bundle struct {
	RelayList               []byte
	RelayListProof          []byte
	SigningCertificate      []byte
	SigningCertificateProof []byte
}

// LogValue makes a Bundle render as a placeholder: its list octets hold every published node's
// hostname, addresses and provider (D19).
func (Bundle) LogValue() slog.Value { return slog.StringValue(redacted) }

// Verified is a relay list that verified, and whether it has expired.
type Verified struct {
	document relaylist.Document
	expired  bool
}

// Document returns the verified relay list.
func (v Verified) Document() relaylist.Document { return v.document }

// Expired reports whether asOf was at or after the list's expires_at. ADVISORY: it raises refresh
// urgency and never refuses, because a client offline past expiry keeps using its last valid list
// (contract, Freshness).
func (v Verified) Expired() bool { return v.expired }

// LogValue makes a Verified render as a placeholder, for Bundle's reason.
func (Verified) LogValue() slog.Value { return slog.StringValue(redacted) }

// Verify verifies a bundle as a client must, in the order doc.go gives: the certificate, then
// the list, each on its exact octets before any parse, and only then the list's decode, the
// rollback check and the Expired flag.
//
// highestAccepted is the highest version the caller has accepted so far, 0 before the first; a
// lower version is refused and an equal one accepted. The verifier stores nothing: persisting the
// high-water mark is the caller's.
//
// asOf is used ONLY to compute Expired. Certificate validity is never judged against it, nor
// against any local clock: it is enforced against the witnesses' clock (contract, Validity).
//
// Every error is one of this package's sentinels, bare.
func (v *Verifier) Verify(b Bundle, highestAccepted int64, asOf time.Time) (Verified, error) {
	cert, err := v.certificate(b.SigningCertificate, b.SigningCertificateProof)
	if err != nil {
		return Verified{}, err
	}
	if err := v.list(cert, b.RelayList, b.RelayListProof); err != nil {
		return Verified{}, err
	}

	doc, err := relaylist.Decode(b.RelayList)
	switch {
	case err == relaylist.ErrDecodeDuplicateKey:
		return Verified{}, ErrListDuplicateKey
	case err == relaylist.ErrNoPickableRelay:
		return Verified{}, ErrListHasNoPickableRelay
	case err != nil:
		return Verified{}, ErrListMalformed
	}
	if doc.Version() < highestAccepted {
		return Verified{}, ErrListRolledBack
	}

	return Verified{document: doc, expired: !asOf.Before(doc.ExpiresAt())}, nil
}

// certificate verifies the signing certificate and its proof, then decodes it strictly.
func (v *Verifier) certificate(x, proofOctets []byte) (signingcert.Certificate, error) {
	if len(proofOctets) == 0 {
		return signingcert.Certificate{}, ErrCertificateProofMissing
	}
	sp, ok := parseProof(proofOctets)
	if !ok {
		return signingcert.Certificate{}, ErrCertificateProofMalformed
	}
	// Roles are bound by key, never by _type alone: the leaf must name a pinned root.
	root, ok := v.roots[sp.Leaf.KeyHash]
	if !ok {
		return signingcert.Certificate{}, ErrCertificateNotSignedByRoot
	}
	if !verifyLeaf(root, x, [64]byte(sp.Leaf.Signature)) {
		return signingcert.Certificate{}, ErrCertificateSignatureInvalid
	}
	// Every cosignature counts here: the window applies to the list's own proof only, and a
	// certificate's proof is typically cosigned before its not_before.
	if !included(&sp, x) || !v.quorum(&sp, everyCosignature) {
		return signingcert.Certificate{}, ErrCertificateProofInvalid
	}

	// Only now, on octets that verified.
	cert, err := signingcert.Decode(x)
	switch {
	case err == signingcert.ErrKeyWeak:
		// Returned as-is: ErrCertificateKeyWeak is the same value.
		return signingcert.Certificate{}, err
	case err != nil:
		return signingcert.Certificate{}, ErrCertificateMalformed
	}
	if cert.Root() != signingcert.Fingerprint(root[:]) {
		return signingcert.Certificate{}, ErrCertificateRootMismatch
	}
	if k := cert.Key(); k == v.currentRoot || k == v.nextRoot {
		return signingcert.Certificate{}, ErrCertificateKeyIsRoot
	}
	// DEFENCE IN DEPTH, kept on purpose: unreachable while signingcert.Decode refuses a weak key
	// itself, it holds the verdict if that ever changed.
	if signingcert.IsWeakKey(cert.Key()) {
		return signingcert.Certificate{}, ErrCertificateKeyWeak
	}

	return cert, nil
}

// list verifies the list's signature and proof under the certificate that verified.
func (v *Verifier) list(cert signingcert.Certificate, x, proofOctets []byte) error {
	if len(proofOctets) == 0 {
		return ErrListProofMissing
	}
	sp, ok := parseProof(proofOctets)
	if !ok {
		return ErrListProofMalformed
	}
	key := cert.Key()
	if sp.Leaf.KeyHash != keyHash(key) {
		return ErrListNotSignedByCertificate
	}
	if !verifyLeaf(key, x, [64]byte(sp.Leaf.Signature)) {
		return ErrListSignatureInvalid
	}
	if !included(&sp, x) || !v.quorum(&sp, everyCosignature) {
		return ErrListProofInvalid
	}
	// Quorum is monotone in the set of verified cosignatures, so this passing under a policy
	// implies the check above did; that check exists only to tell the two refusals apart.
	if !v.quorum(&sp, withinValidity(cert)) {
		return ErrListOutsideCertificateValidity
	}

	return nil
}

// witnessClockSkew is the contract's allowance: 10 minutes, symmetric, and on the client only
// (Validity).
const witnessClockSkew = 10 * time.Minute

// withinValidity admits a cosignature whose T lies in [not_before - 10m, not_after + 10m],
// inclusive. T is the cosignature's own signed timestamp, in seconds; sigsum-go parses it as at
// most 2^63-1, so the conversion to int64 is exact. This is the package's only time comparison
// for validity, and it reads no clock: the witnesses' clock, never the client's.
func withinValidity(cert signingcert.Certificate) func(types.Cosignature) bool {
	skew := int64(witnessClockSkew / time.Second)
	lo, hi := cert.NotBefore().Unix()-skew, cert.NotAfter().Unix()+skew

	return func(cs types.Cosignature) bool {
		t := int64(cs.Timestamp)

		return lo <= t && t <= hi
	}
}
