// SPDX-License-Identifier: AGPL-3.0-only

package keyset

import (
	"bytes"

	"github.com/abylora/shared/pkg/keyset/keysetpb"
)

// CheckDelta is the producer's conformance check (key-set.md, the vectors paragraph). The
// Delta d, emitted to move old at oldVersion to new at newVersion, conforms when nil is
// returned. Otherwise the first failure is returned, found in this order:
//
//  1. d's shape violates rule 13 or rule 9 (the applier's own checks);
//  2. d's versions are not oldVersion and newVersion (ErrDeltaVersionsMismatch);
//  3. then each op in received order, and for each op: a Remove after an Upsert
//     (ErrDeltaUpsertBeforeRemove, rule 10); a key an earlier op already named, compared as
//     raw bytes of any length (ErrDeltaKeyRepeated, rule 10); a key not strictly above the
//     previous key of its group, removes or upserts, under bytes.Compare and never the base64
//     text (ErrDeltaNotSorted, rule 15);
//  4. conformance covers entries as well as ops (rule 11): ErrDeltaEntryRefused when a consumer
//     would refuse an entry under rule 11 or 12, or when the resulting set has two entries
//     sharing a non-empty tunnel_ip6. The consumer checks tunnel_ip only, but the producer's
//     guarantee covers both addresses (rule 12); entries with an empty tunnel_ip6 never collide;
//  5. applying d to old, by the consumer's semantics, does not give new (ErrDeltaResultDiffers).
//
// CheckDelta takes no node key, and applies d with no own key. Rule 11's "a key equal to the
// receiving node's own key" is outside conformance: it depends on which node receives the
// Delta, and the control plane's registration refusal (no device key equal to a node's key)
// is what guarantees it.
func CheckDelta(oldVersion uint64, old Set, newVersion uint64, new Set, d *keysetpb.Delta) error {
	if err := deltaShape(d); err != nil {
		return err
	}
	if d.GetFromVersion() != oldVersion || d.GetToVersion() != newVersion {
		return ErrDeltaVersionsMismatch
	}

	seen := make(map[string]struct{}, len(d.GetOps()))
	upserting := false
	var previous []byte
	havePrevious := false
	for _, op := range d.GetOps() {
		var raw []byte
		switch o := op.GetOp().(type) {
		case *keysetpb.DeltaOp_Remove:
			if upserting {
				return ErrDeltaUpsertBeforeRemove
			}
			raw = o.Remove.GetPublicKey()
		case *keysetpb.DeltaOp_Upsert:
			if !upserting {
				upserting, havePrevious = true, false
			}
			raw = o.Upsert.GetEntry().GetPublicKey()
		}
		if _, dup := seen[string(raw)]; dup {
			return ErrDeltaKeyRepeated
		}
		seen[string(raw)] = struct{}{}
		if havePrevious && bytes.Compare(previous, raw) >= 0 {
			return ErrDeltaNotSorted
		}
		previous, havePrevious = raw, true
	}

	got, refused := applyOps(old, nil, d.GetOps(), nil)
	if len(refused) != 0 || tunnelIP6Repeated(got) {
		return ErrDeltaEntryRefused
	}
	if !got.Equal(new) {
		return ErrDeltaResultDiffers
	}

	return nil
}

// tunnelIP6Repeated reports whether two entries of s share a non-empty tunnel_ip6. An empty
// tunnel_ip6 is absence, so it never collides.
func tunnelIP6Repeated(s Set) bool {
	seen := make(map[[16]byte]struct{}, len(s.entries))
	for _, e := range s.entries {
		if !e.hasTunnelIP6 {
			continue
		}
		if _, dup := seen[e.tunnelIP6]; dup {
			return true
		}
		seen[e.tunnelIP6] = struct{}{}
	}

	return false
}
