// SPDX-License-Identifier: AGPL-3.0-only

package relayverify

import (
	"bytes"
	"strconv"
	"testing"
	"time"
)

// The list's own proof is required, exactly as the certificate's is.
func TestABundleWithNoListProofIsRefused(t *testing.T) {
	b := baseBundle(t)
	b.RelayListProof = nil
	requireRefused(t, b, ErrListProofMissing)
}

func TestAListProofThatIsNotASigsumProofIsRefused(t *testing.T) {
	b := baseBundle(t)
	b.RelayListProof = []byte("not a proof\n")
	requireRefused(t, b, ErrListProofMalformed)
}

// Roles are bound by key: a list verifies only under the key of a certificate that verified,
// never under a root.
func TestAListSignedByARootDirectlyIsRefused(t *testing.T) {
	requireRefused(t, listBundle(t, "list/vector-l.json", "list/vector-l.signed-by-root.proof"), ErrListNotSignedByCertificate)
}

func TestAListWhoseOctetsWereAlteredIsRefused(t *testing.T) {
	b := baseBundle(t)
	b.RelayList = bytes.Replace(b.RelayList, []byte("Stockholm"), []byte("Stockholn"), 1)
	requireRefused(t, b, ErrListSignatureInvalid)
}

func TestAListProofWhoseInclusionPathWasAlteredIsRefused(t *testing.T) {
	b := baseBundle(t)
	b.RelayListProof = alterFirstNodeHash(t, b.RelayListProof)
	requireRefused(t, b, ErrListProofInvalid)
}

// The list's own proof must satisfy a pinned policy, exactly as the certificate's must: logged
// on the current policy's log, but cosigned only by a witness neither policy names.
func TestAListProofValidUnderNeitherPolicyIsRefused(t *testing.T) {
	requireRefused(t, listBundle(t, "list/vector-l.json", "list/vector-l.neither.proof"), ErrListProofInvalid)
}

// A proof is valid if it satisfies either pinned policy (contract, Validity): the list's own
// proof, logged and cosigned under the next policy only, is accepted.
func TestAListProofValidOnlyUnderTheNextPolicyIsAccepted(t *testing.T) {
	requireAccepted(t, listBundle(t, "list/vector-l.json", "list/vector-l.next.proof"))
}

// Contract, Validity: a list is accepted under a certificate only if its OWN proof has a witness
// quorum counting only cosignatures with not_before - 10m <= T <= not_after + 10m. The bounds are
// inclusive. The fixture policy is 2 of 2, so the split row refuses an implementation that admits
// the proof when ANY cosignature lies in the window.
func TestTheWitnessWindow(t *testing.T) {
	cases := []struct {
		proof string
		want  error
	}{
		{"t-not-before-minus-11m", ErrListOutsideCertificateValidity},
		{"t-not-before-minus-10m", nil},
		{"t-not-after-plus-9m", nil},
		{"t-not-after-plus-10m", nil},
		{"t-not-after-plus-11m", ErrListOutsideCertificateValidity},
		{"t-split", ErrListOutsideCertificateValidity},
	}

	for _, tc := range cases {
		t.Run(tc.proof, func(t *testing.T) {
			b := listBundle(t, "list/vector-l.json", "list/vector-l."+tc.proof+".proof")
			if _, err := fixtureVerifier(t).Verify(b, 0, asOfWithinTheList); err != tc.want {
				t.Errorf("Verify() error = %v, want %v", err, tc.want)
			}
		})
	}
}

// GUARD over the dependency's behaviour, and what makes filtering by T sound: each cosignature
// signs its own timestamp ("cosignature/v1\ntime %d\n" + checkpoint, sigsum-go pkg/types), so a T
// edited into the window no longer verifies and the quorum fails outright.
func TestAListProofWithAnEditedWitnessTimestampIsRefused(t *testing.T) {
	b := listBundle(t, "list/vector-l.json", "list/vector-l.t-not-after-plus-11m.proof")
	late := " " + strconv.FormatInt(time.Date(2026, 4, 1, 0, 11, 0, 0, time.UTC).Unix(), 10) + " "
	inside := " " + strconv.FormatInt(time.Date(2026, 1, 2, 0, 5, 0, 0, time.UTC).Unix(), 10) + " "
	if n := bytes.Count(b.RelayListProof, []byte(late)); n != 2 {
		t.Fatalf("%d cosignature lines carry the late T, want 2", n)
	}

	b.RelayListProof = bytes.ReplaceAll(b.RelayListProof, []byte(late), []byte(inside))
	requireRefused(t, b, ErrListProofInvalid)
}
