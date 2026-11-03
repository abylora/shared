// SPDX-License-Identifier: AGPL-3.0-only

// Package keyset is the reference semantics of the key set stream,
// /abylora.keyset.v1.KeySet/Stream, over the wire types in keysetpb. Its rules come from
// <workspace>/docs/contracts/key-set.md, Delivery rules 1 to 16 and Readiness, and from nowhere
// else. Where the contract is silent, this comment says what the reference does, and the
// vectors never assert it.
//
// A REFERENCE, NOT A NODE AGENT. Nothing here touches a kernel, reads a clock, opens a stream
// or logs. Rule 4 (apply as a diff against live state), rule 6 (heartbeat timers), rule 8
// (removing expired entries on stream loss), rule 14 (a live read that resets the cursor), rule
// 15's 60-second epoch and valid_until expiry belong to node-agent and control-plane, and are
// tested there. imports_test.go refuses time, os, net and every logger.
//
// THE CONSUMER: Applier. It holds the cursor, the held Set, the keys it currently refuses, and
// an open snapshot. Hello opens a stream, discards any open snapshot (a snapshot never spans
// streams; rule 8 keeps the last applied set) and returns Hello{held_version: cursor}. Receive
// takes one control-plane message and returns exactly one Outcome:
//
//   - accumulating: a SnapshotBegin or an Upsert inside a snapshot;
//   - unchanged: a legal Heartbeat. One whose current_version is above the cursor is not acted
//     on here: rule 6's reconnect waits for a delta that does not arrive, which is a timer;
//   - applied: a SnapshotEnd or a legal Delta was applied. Send Outcome.Applied(). Every advance
//     is reported (rule 5), a zero-op Delta, a snapshot equal to the held set and a snapshot
//     below the cursor (the answer to a held_version above the published version) included;
//   - apply failed: the ApplyFunc returned false. The cursor is 0, the stream closes, and the
//     node reconnects with Hello{held_version: 0} (rule 5);
//   - violation: rule 13, rule 5's gap, or rule 9's version 0. The stream closes, the cursor and
//     held set are unchanged, and the node reconnects with Hello{held_version: cursor};
//   - misuse: the driver received with no stream open, or with a nil apply. Nothing changes,
//     and the driver opens a new stream with Hello.
//
// The node's apply enters through ApplyFunc, a callback Receive calls once for every SnapshotEnd
// and every legal Delta, with the whole target set. It returns a bool, never an error, so no
// kernel error text reaches this package. A Delta is checked whole (rules 9 and 13) before any
// op applies, and applied to copies, so a violation or a failed apply never leaves a
// half-applied set, and a Set returned earlier never changes.
//
// After a failed apply Cursor() is 0 and Held() is the last set applied successfully, unchanged
// (rule 5, as ruled): the interface may lie anywhere between Held() and the target, which is why
// the cursor no longer names it. A node relies on Held() for rule 8 and rule 14.
//
// DRIVER MISUSE IS NOT A VIOLATION. Receive with no stream open, or with a nil apply, returns
// OutcomeMisuse. OutcomeViolation means only that the control plane sent something outside the
// state machine, so a count of violations points at a producer defect.
//
// RULE 11, A MALFORMED ENTRY IS SKIPPED. Malformed is a key that is not 32 bytes, a key equal to
// the node's own interface key (passed to New), a tunnel_ip that is not exactly 4 bytes, outside
// 10.64.0.0/10 or inside the reserved 10.64.0.0/24, a tunnel_ip6 of any length but 0 (absent)
// or 16 (kept, nothing installed), or a valid_until that is not a multiple of 86400. The entry
// is not applied, any entry already held under its key is removed, the rest of the message
// applies and the cursor advances.
//
// RULE 12, NO TWO ENTRIES SHARE A TUNNEL ADDRESS. In a snapshot, every entry whose tunnel_ip
// another accumulated entry also claims is skipped. In a Delta, applied in received order, an
// Upsert claiming a tunnel_ip held at that point by a different key is skipped, and treated like
// rule 11: any entry already held under its key is removed. So Remove(old) then Upsert(new)
// reuses an address, and Upsert(new) then Remove(old) skips new. The consumer checks tunnel_ip
// only, as rule 12 says: nothing is installed for tunnel_ip6 yet, so a collision there cannot
// reach the kernel. Rule 11 applies first (key-set.md, workspace root fc9a77b): an entry it
// refuses is never installed, cannot claim an address, and takes no part in rule 12.
//
// THE SKIPPED GAUGE. Applied.skipped is the number of keys the node currently refuses under
// rules 11 and 12, not a count of skips on this stream. A refused key is held in memory, by its
// raw bytes so that a key of any length can be cleared. A Remove of it, or a later well-formed
// and unclaimed Upsert of it, clears it, and a snapshot replaces the whole refused set. The gauge
// survives a resume by deltas, during which the refused entry is never resent.
//
// THE PRODUCER: producer conformance covers entries as well as ops (rule 11). SetOf builds a
// producer's set, and so checks a snapshot: it refuses a malformed entry, a repeated key, a
// repeated tunnel_ip and a repeated non-empty tunnel_ip6, since the producer's guarantee covers
// both addresses (rule 12). CheckDelta judges an emitted Delta by the consumer's own op
// semantics, plus rule 10 (one op per key, every Remove before every Upsert), rule 15 (each
// group sorted by bytes.Compare, never the base64 text), and the same entry rules. Neither takes
// a node key: rule 11's own-key check depends on which node receives the entry, and the control
// plane's registration refusal guarantees it. PlanResume is rule 3: deltas from a version the
// log can resume from, compared with the published version and never a live counter, otherwise a
// snapshot. NodeStreamChecker is rule 16, the node's direction, for the control plane's side of
// one stream.
//
// EVERY ERROR IS A SENTINEL, returned unwrapped. None carries a public key or a tunnel address;
// the package has no fmt to put one there.
//
// THE VECTORS live in keysetvectors, a separate package so that importing this one embeds no
// test data. This package never imports it, and keysetvectors never imports this one.
//
// NOTHING HERE LOGS, AND NOTHING MAY. The held set is every device's public key and tunnel
// address, and rule 11 says the consumer never logs an entry. Entry, Set, Outcome and Applier
// render as a placeholder.
package keyset
