// SPDX-License-Identifier: AGPL-3.0-only

package keyset

import (
	"maps"

	"github.com/abylora/shared/pkg/keyset/keysetpb"
)

// deltaShape is rule 13 and rule 9 for one Delta, checked before any op applies: from_version
// is at least 1, to_version is above it, every op has a known arm, and every Upsert carries an
// entry. The applier and CheckDelta share it.
func deltaShape(d *keysetpb.Delta) error {
	from, to := d.GetFromVersion(), d.GetToVersion()
	if from == 0 {
		return ErrDeltaFromVersionZero
	}
	if to <= from {
		return ErrDeltaVersionsNotIncreasing
	}
	for _, op := range d.GetOps() {
		switch o := op.GetOp().(type) {
		case *keysetpb.DeltaOp_Upsert:
			if o.Upsert.GetEntry() == nil {
				return ErrUpsertNoEntry
			}
		case *keysetpb.DeltaOp_Remove:
		default:
			return ErrOpNoArm
		}
	}

	return nil
}

// applyOps applies ops in received order (rule 10) to copies of held and refused, and returns
// the copies; neither input changes. The applier and CheckDelta share it, so a producer is
// judged by exactly the consumer's semantics.
//
//   - Remove clears the key's refusal and removes its entry; a Remove of an unknown key is a
//     no-op (rule 2).
//   - Upsert of a malformed entry (rule 11), or of one whose tunnel_ip is held at that point by
//     a different key (rule 12), is refused: the key is recorded as refused and any entry it
//     already holds is removed.
//   - Any other Upsert replaces the key's entry (rule 2), frees its previous address, and
//     clears its refusal.
func applyOps(held Set, refused map[string]struct{}, ops []*keysetpb.DeltaOp, own *[32]byte) (Set, map[string]struct{}) {
	entries := cloneOrMake(held.entries)
	byAddr := cloneOrMake(held.byAddr)
	out := cloneOrMake(refused)
	drop := func(key [32]byte) {
		if e, ok := entries[key]; ok {
			delete(byAddr, e.tunnelIP)
			delete(entries, key)
		}
	}

	for _, op := range ops {
		switch o := op.GetOp().(type) {
		case *keysetpb.DeltaOp_Remove:
			raw := o.Remove.GetPublicKey()
			delete(out, string(raw))
			if key, ok := keyOf(raw); ok {
				drop(key)
			}
		case *keysetpb.DeltaOp_Upsert:
			m := o.Upsert.GetEntry()
			raw := m.GetPublicKey()
			e, ok := wellFormed(m, own)
			if ok {
				if owner, taken := byAddr[e.tunnelIP]; taken && owner != e.publicKey {
					ok = false
				}
			}
			if key, isKey := keyOf(raw); isKey {
				drop(key)
			}
			if !ok {
				out[string(raw)] = struct{}{}

				continue
			}
			entries[e.publicKey] = e
			byAddr[e.tunnelIP] = e.publicKey
			delete(out, string(raw))
		}
	}

	return Set{entries: entries, byAddr: byAddr}, out
}

func cloneOrMake[K comparable, V any](m map[K]V) map[K]V {
	if m == nil {
		return make(map[K]V)
	}

	return maps.Clone(m)
}
