// SPDX-License-Identifier: AGPL-3.0-only

package relayverify

import (
	"bytes"

	sigcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/types"
)

// parseProof parses a sigsum proof. sigsum-go's error quotes input lines, so it is discarded.
func parseProof(octets []byte) (proof.SigsumProof, bool) {
	var sp proof.SigsumProof
	if err := sp.FromASCII(bytes.NewReader(octets)); err != nil {
		return proof.SigsumProof{}, false
	}

	return sp, true
}

// included reports whether the leaf for the octets x, with the proof's signature and key hash,
// is in the proof's tree head: RFC 6962 inclusion, through sigsum-go's merkle.VerifyInclusion.
func included(sp *proof.SigsumProof, x []byte) bool {
	leaf := types.Leaf{Checksum: sigcrypto.Hash(leafChecksum(x)), Signature: sp.Leaf.Signature, KeyHash: sp.Leaf.KeyHash}
	h := leaf.ToHash()

	return sp.Inclusion.Verify(&h, &sp.TreeHead.TreeHead) == nil
}

// everyCosignature counts every cosignature.
func everyCosignature(types.Cosignature) bool { return true }

// quorum reports whether the proof's log signature and witness quorum hold under EITHER pinned
// policy, counting only the cosignatures counts admits. sigsum-go's VerifyCosignedTreeHead reads
// a cosignature's timestamp only as signed data, so handing it a copy of the tree head with a
// filtered cosignature map IS a filtered quorum evaluation (read at v0.14.1, pkg/policy). The
// log's and witnesses' Ed25519 signatures are verified there, with crypto/ed25519 at that
// version, which is the contract's rule for every signature a client verifies.
func (v *Verifier) quorum(sp *proof.SigsumProof, counts func(types.Cosignature) bool) bool {
	cth := sp.TreeHead
	cth.Cosignatures = make(map[sigcrypto.Hash]types.Cosignature, len(sp.TreeHead.Cosignatures))
	for kh, cs := range sp.TreeHead.Cosignatures {
		if counts(cs) {
			cth.Cosignatures[kh] = cs
		}
	}
	for _, p := range v.policies {
		if p.VerifyCosignedTreeHead(&sp.LogKeyHash, &cth) == nil {
			return true
		}
	}

	return false
}
