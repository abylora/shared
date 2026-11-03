// SPDX-License-Identifier: AGPL-3.0-only

package relayverify

import "errors"

// EVERY ERROR THIS PACKAGE RETURNS IS ONE OF THESE SENTINELS, BARE. Nothing wraps them, and none
// carries a byte of the input: an error value is the easiest thing in the world to log, and a
// Relay holds hostnames, addresses and providers that D19 keeps out of every log line and error.
// sigsum-go's own errors quote their input and are always discarded. A caller tells refusals
// apart with ==, or errors.Is.
var (
	// ErrPinnedRootMissing: a pinned root is the zero key. Clients ship two root public keys,
	// current and next (contract, Signing and trust).
	ErrPinnedRootMissing = errors.New("relayverify: a pinned root is missing")

	// ErrPinnedRootsIdentical: the current and next roots are one key, which leaves no second
	// root to rotate to.
	ErrPinnedRootsIdentical = errors.New("relayverify: the pinned roots are identical")

	// ErrPinnedPolicyMissing: no current sigsum policy. A proof is required, so a policy is.
	ErrPinnedPolicyMissing = errors.New("relayverify: the current policy is missing")

	// ErrPinnedPolicyMalformed: a pinned policy is not sigsum policy text with a quorum.
	ErrPinnedPolicyMalformed = errors.New("relayverify: a pinned policy is malformed")

	// ErrPinnedPolicyRequiresNoWitness: a pinned policy's quorum holds with no witness at all.
	// "The pinned policy must require at least one witness; with none there is no T"
	// (contract, Validity).
	ErrPinnedPolicyRequiresNoWitness = errors.New("relayverify: a pinned policy requires no witness")

	// ErrCertificateProofMissing: no certificate proof. Clients must REQUIRE a transparency
	// inclusion proof, not check one when present (contract, Rules): a copied root that simply
	// omits the proof must not be accepted.
	ErrCertificateProofMissing = errors.New("relayverify: the signing certificate has no proof")

	// ErrCertificateProofMalformed: the certificate proof is not a sigsum proof.
	ErrCertificateProofMalformed = errors.New("relayverify: the signing certificate proof is malformed")

	// ErrCertificateNotSignedByRoot: the proof's leaf names a key that is neither pinned root.
	// A certificate verifies only against a pinned root.
	ErrCertificateNotSignedByRoot = errors.New("relayverify: the signing certificate is not signed by a pinned root")

	// ErrCertificateSignatureInvalid: the root's leaf signature does not verify over the
	// certificate's exact octets.
	ErrCertificateSignatureInvalid = errors.New("relayverify: the signing certificate's signature is invalid")

	// ErrCertificateProofInvalid: the certificate's leaf is not included in the proof's tree
	// head, or that tree head's log signature or witness quorum holds under neither pinned
	// policy.
	ErrCertificateProofInvalid = errors.New("relayverify: the signing certificate proof is invalid")

	// ErrCertificateMalformed: signingcert.Decode refuses the verified certificate octets -- a
	// duplicate key, an unknown field, a self-certificate, and the rest of its strict rules.
	ErrCertificateMalformed = errors.New("relayverify: the signing certificate does not decode")

	// ErrCertificateRootMismatch: the certificate's root is not the fingerprint of the pinned
	// root that signed it.
	ErrCertificateRootMismatch = errors.New("relayverify: the signing certificate names another root")

	// ErrCertificateKeyIsRoot: the certificate's key is a pinned root. Root keys sign nothing
	// but certificates, so roles stay bound by key.
	ErrCertificateKeyIsRoot = errors.New("relayverify: the signing certificate's key is a pinned root")

	// ErrCertificateKeyWeak: the certificate's key is one of the 8 small-order Ed25519 encodings,
	// or not a canonical point encoding (contract, Roles are bound by key). crypto/ed25519
	// accepts a signature by the identity key over any message, so a certified small-order key
	// would let anyone sign lists. This checks the certified key; it does not change the
	// verification rule.
	ErrCertificateKeyWeak = errors.New("relayverify: the signing certificate's key is a weak point")

	// ErrListProofMissing: no list proof. A list arriving without a valid proof is invalid,
	// exactly as an unsigned one is (contract, Rules).
	ErrListProofMissing = errors.New("relayverify: the relay list has no proof")

	// ErrListProofMalformed: the list proof is not a sigsum proof.
	ErrListProofMalformed = errors.New("relayverify: the relay list proof is malformed")

	// ErrListNotSignedByCertificate: the proof's leaf names a key other than the certificate's.
	// A list verifies only against the key of a certificate that verified -- never a root's.
	ErrListNotSignedByCertificate = errors.New("relayverify: the relay list is not signed by the certificate's key")

	// ErrListSignatureInvalid: the signing key's leaf signature does not verify over the list's
	// exact octets.
	ErrListSignatureInvalid = errors.New("relayverify: the relay list's signature is invalid")

	// ErrListProofInvalid: the list's leaf is not included in the proof's tree head, or that tree
	// head's log signature or witness quorum, counting every cosignature, holds under neither
	// pinned policy.
	ErrListProofInvalid = errors.New("relayverify: the relay list proof is invalid")

	// ErrListOutsideCertificateValidity: the list's proof has a quorum, but not one counting only
	// cosignatures with not_before - 10m <= T <= not_after + 10m (contract, Validity). The
	// certificate's lifetime is enforced against the witnesses' clock, never the client's.
	ErrListOutsideCertificateValidity = errors.New("relayverify: the relay list was not cosigned within the certificate's validity")

	// ErrListMalformed: the verified list octets are not a relay list relaylist.Decode accepts
	// -- the certificate's octets signed as a list land here, which is the point of each
	// document carrying its own _type.
	ErrListMalformed = errors.New("relayverify: the relay list does not decode")

	// ErrListDuplicateKey: the verified list octets repeat a key in some object. Refused in
	// both documents (contract, Strict parsing), however lenient the list's other rules are.
	ErrListDuplicateKey = errors.New("relayverify: the relay list repeats a key")

	// ErrListHasNoPickableRelay: the verified list leaves no pickable relay once non-object
	// elements are skipped and unpickable relays set aside (contract, Rules). Adopting it would
	// strand the client exactly as an empty list would, so the client keeps its last-known-good
	// list. Distinct from ErrListMalformed: this list decodes, and is genuinely signed and logged.
	ErrListHasNoPickableRelay = errors.New("relayverify: the relay list has no pickable relay")

	// ErrListRolledBack: the list's version is lower than the highest the caller has accepted.
	// Rollback refusal is what makes removing a compromised relay stick (contract, Freshness).
	ErrListRolledBack = errors.New("relayverify: the relay list's version is below the highest accepted")
)
