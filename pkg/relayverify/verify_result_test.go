// SPDX-License-Identifier: AGPL-3.0-only

package relayverify

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abylora/shared/pkg/relaylist"
	"github.com/abylora/shared/pkg/transport"
)

// Contract, Strict parsing: in both documents a duplicate key is refused. The list's octets are
// signed and logged, so only the decoder can refuse it.
func TestAListWithADuplicateKeyIsRefused(t *testing.T) {
	requireRefused(t, listBundle(t, "list/duplicate-key.json", "list/duplicate-key.proof"), ErrListDuplicateKey)
}

// The certificate's octets, signed by the signing key and logged: verified as a list, they can
// never parse as one -- the point of each document carrying its own _type.
func TestCertificateOctetsSignedAsAListAreRefused(t *testing.T) {
	requireRefused(t, listBundle(t, "list/certificate-octets.json", "list/certificate-octets.proof"), ErrListMalformed)
}

// Contract, Rules: refuse a list whose version is lower than the last accepted version. Equal
// is accepted, and 0 is the caller's high-water mark before its first list.
func TestRollback(t *testing.T) {
	v := fixtureVerifier(t)
	if _, err := v.Verify(baseBundle(t), 2, asOfWithinTheList); err != ErrListRolledBack {
		t.Errorf("version 1 under high-water mark 2: error = %v, want ErrListRolledBack", err)
	}
	for _, highest := range []int64{0, 1} {
		if _, err := v.Verify(baseBundle(t), highest, asOfWithinTheList); err != nil {
			t.Errorf("version 1 under high-water mark %d: error = %v, want nil", highest, err)
		}
	}
}

// Freshness: expires_at is advisory and must not brick a client. It sets Expired and never
// refuses, at expires_at itself and long after.
func TestAnExpiredListIsAcceptedWithExpiredSet(t *testing.T) {
	for _, asOf := range []time.Time{time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 3, 0, 0, 0, 0, time.UTC)} {
		got, err := fixtureVerifier(t).Verify(baseBundle(t), 0, asOf)
		if err != nil || !got.Expired() {
			t.Errorf("as of %v: Expired() = %v, error = %v; want true, nil", asOf, got.Expired(), err)
		}
	}
}

func TestAListBeforeItsExpiryIsNotExpired(t *testing.T) {
	if got := requireAccepted(t, baseBundle(t)); got.Expired() {
		t.Error("Expired() = true before expires_at")
	}
}

// GUARD. Certificate validity is judged against the witnesses' clock, never the client's: an
// asOf years outside the certificate's window changes nothing but Expired.
func TestCertificateValidityIgnoresTheReferenceInstant(t *testing.T) {
	for _, asOf := range []time.Time{time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if _, err := fixtureVerifier(t).Verify(baseBundle(t), 0, asOf); err != nil {
			t.Errorf("as of %v: error = %v, want nil", asOf, err)
		}
	}
}

func verifiedDocument(t *testing.T, name string) relaylist.Document {
	t.Helper()

	return requireAccepted(t, listBundle(t, "list/"+name+".json", "list/"+name+".proof")).Document()
}

// Contract, Strict parsing: an unknown field is ignored at every level, and the list stays
// valid. GUARD at this level; the red was relaylist.Decode's.
func TestAnUnknownFieldStillVerifiesAndDecodes(t *testing.T) {
	for _, name := range []string{"unknown-top-level-field", "unknown-relay-field"} {
		r := verifiedDocument(t, name).Relays()
		if len(r) != 1 || r[0].NodeID() != "00000000-0000-4000-8000-000000000001" || !r[0].Pickable() {
			t.Errorf("%s: decoded wrongly", name)
		}
	}
}

// An endpoint of unknown kind is skipped: it is absent from the relay's usable endpoints, and the
// relay stays pickable on the endpoint it knows. GUARD at this level.
func TestAnUnknownEndpointKindStillVerifiesAndIsSkipped(t *testing.T) {
	r := verifiedDocument(t, "unknown-endpoint-kind").Relays()[0]
	eps := r.Endpoints()
	if len(eps) != 1 || eps[0].Kind() != transport.KindPlain || eps[0].Port() != 51820 {
		t.Errorf("Endpoints() = %v, want only plain/51820", eps)
	}
	if !r.Pickable() {
		t.Error("the relay is not pickable on its known endpoint")
	}
}

// A relay whose status is unknown is decoded as not pickable; its sibling keeps the list valid.
// GUARD at this level.
func TestAnUnknownStatusStillVerifiesAndIsNotPickable(t *testing.T) {
	relays := verifiedDocument(t, "unknown-status").Relays()
	if len(relays) != 2 || relays[0].Pickable() || relays[0].Status() != "future-status" || !relays[1].Pickable() {
		t.Error("want the unknown-status relay kept and not pickable, and its sibling pickable")
	}
}

// Contract, Rules (ruled 2026-11-01): a signed, logged list that leaves no pickable relay is
// refused, and the client keeps its last-known-good list. Here vector L's only relay is draining.
// Its own sentinel, not ErrListMalformed: the list is well formed and genuinely signed.
func TestAListThatLeavesNoPickableRelayIsRefused(t *testing.T) {
	requireRefused(t, listBundle(t, "list/no-pickable-relay.json", "list/no-pickable-relay.proof"), ErrListHasNoPickableRelay)
}

// Contract, Strict parsing (ruled 2026-11-01): a node_id on more than one relay makes every
// relay carrying it unpickable, and the rest are kept; the list stays valid. GUARD at this level.
func TestARepeatedNodeIDStillVerifiesAndOnlyItsRelaysAreUnpickable(t *testing.T) {
	relays := verifiedDocument(t, "repeated-node-id").Relays()
	if len(relays) != 3 {
		t.Fatalf("decoded %d relays, want 3", len(relays))
	}
	if relays[0].Pickable() || relays[1].Pickable() {
		t.Error("a relay carrying the repeated node_id is pickable")
	}
	if relays[2].NodeID() != "00000000-0000-4000-8000-000000000002" || !relays[2].Pickable() {
		t.Error("the relay with its own node_id is not pickable")
	}
}

var allSentinels = []error{
	ErrPinnedRootMissing, ErrPinnedRootsIdentical, ErrPinnedPolicyMissing, ErrPinnedPolicyMalformed,
	ErrPinnedPolicyRequiresNoWitness, ErrCertificateProofMissing, ErrCertificateProofMalformed,
	ErrCertificateNotSignedByRoot, ErrCertificateSignatureInvalid, ErrCertificateProofInvalid,
	ErrCertificateMalformed, ErrCertificateRootMismatch, ErrCertificateKeyIsRoot, ErrCertificateKeyWeak, ErrListProofMissing,
	ErrListProofMalformed, ErrListNotSignedByCertificate, ErrListSignatureInvalid, ErrListProofInvalid,
	ErrListOutsideCertificateValidity, ErrListDuplicateKey, ErrListMalformed, ErrListHasNoPickableRelay,
	ErrListRolledBack,
}

// Every error is a constant sentinel carrying no hostname, address, node_id or provider.
func TestEverySentinelIsDistinctAndCarriesNoFixtureValue(t *testing.T) {
	if len(allSentinels) != 24 {
		t.Errorf("%d sentinels, want 24", len(allSentinels))
	}
	forbidden := []string{"test-1.example", "192.0.2", "00000000-0000-4000-8000-000000000001", "Example", "Stockholm"}

	for i, a := range allSentinels {
		for j, b := range allSentinels {
			if i != j && (a == b || a.Error() == b.Error()) {
				t.Errorf("%v and %v are not distinct", a, b)
			}
		}
		for _, f := range forbidden {
			if strings.Contains(a.Error(), f) {
				t.Errorf("%v carries %q", a, f)
			}
		}
	}
}

// Every refusal Verify makes is one of this package's sentinels, BARE: == rather than errors.Is,
// which is what keeps sigsum-go's and the decoders' errors -- some of which quote their input --
// out of every error a client might log.
func TestEveryRefusalIsABareSentinel(t *testing.T) {
	noCertProof, noListProof := baseBundle(t), baseBundle(t)
	noCertProof.SigningCertificateProof, noListProof.RelayListProof = nil, nil

	cases := []struct {
		name string
		b    Bundle
		want error
	}{
		{"no certificate proof", noCertProof, ErrCertificateProofMissing},
		{"not signed by a root", certBundle(t, "certificate/vector-c.json", "list/vector-l.proof"), ErrCertificateNotSignedByRoot},
		{"neither policy", certBundle(t, "certificate/vector-c.json", "certificate/vector-c.neither.proof"), ErrCertificateProofInvalid},
		{"certificate duplicate key", certBundle(t, "certificate/duplicate-key.json", "certificate/duplicate-key.current.proof"), ErrCertificateMalformed},
		{"root mismatch", certBundle(t, "certificate/root-names-the-other-root.json", "certificate/root-names-the-other-root.current.proof"), ErrCertificateRootMismatch},
		{"key is a root", certBundle(t, "certificate/key-is-next-root.json", "certificate/key-is-next-root.current.proof"), ErrCertificateKeyIsRoot},
		{"no list proof", noListProof, ErrListProofMissing},
		{"list signed by a root", listBundle(t, "list/vector-l.json", "list/vector-l.signed-by-root.proof"), ErrListNotSignedByCertificate},
		{"outside the window", listBundle(t, "list/vector-l.json", "list/vector-l.t-not-after-plus-11m.proof"), ErrListOutsideCertificateValidity},
		{"list duplicate key", listBundle(t, "list/duplicate-key.json", "list/duplicate-key.proof"), ErrListDuplicateKey},
		{"not a list", listBundle(t, "list/certificate-octets.json", "list/certificate-octets.proof"), ErrListMalformed},
		{"no pickable relay", listBundle(t, "list/no-pickable-relay.json", "list/no-pickable-relay.proof"), ErrListHasNoPickableRelay},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireRefused(t, tc.b, tc.want)
			if _, err := fixtureVerifier(t).Verify(tc.b, 0, asOfWithinTheList); !slices.Contains(allSentinels, err) {
				t.Errorf("error %v is not one of this package's sentinels", err)
			}
		})
	}
}

func TestTheBundleFileNamesAreTheContracts(t *testing.T) {
	got := []string{FileRelayList, FileRelayListProof, FileSigningCertificate, FileSigningCertificateProof}
	want := []string{"relay-list.json", "relay-list.json.proof", "signing-certificate.json", "signing-certificate.json.proof"}
	if !slices.Equal(got, want) {
		t.Errorf("bundle file names = %v, want %v", got, want)
	}
}

// Contract, Strict parsing (ruled 2026-11-01): a relay-level violation makes that relay
// unpickable and keeps the rest, and the list stays valid -- one bad relay is a producer defect,
// and refusing the list would strand every client on its last-known-good list for it. Here the
// second relay's ipv4 is an IPv6 address.
func TestARelayLevelViolationStillVerifiesAndOnlyThatRelayIsUnpickable(t *testing.T) {
	relays := verifiedDocument(t, "relay-level-violation").Relays()
	if len(relays) != 2 {
		t.Fatalf("decoded %d relays, want 2", len(relays))
	}
	if !relays[0].Pickable() {
		t.Error("the relay without a violation is not pickable")
	}
	if relays[1].Pickable() || relays[1].IPv4().IsValid() {
		t.Error("the relay whose ipv4 is not IPv4 is pickable, or kept its address")
	}
}
