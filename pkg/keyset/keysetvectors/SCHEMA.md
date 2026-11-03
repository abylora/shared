<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Key set vectors, schema `abylora.keyset.vectors.v1`

These files are the test vectors of the key set stream, `/abylora.keyset.v1.KeySet/Stream`,
defined by `<workspace>/docs/contracts/key-set.md` (*Delivery*, rules 1 to 16, and
*Readiness*). Rule numbers below are that document's. The wire messages are those of
`proto/abylora/keyset/v1/keyset.proto` in this repository.

This document is enough to read and run every file in any language.

## How the expectations were made

Every expected value was derived by hand from the contract. None was copied from an
implementation's output. The Go reference, `pkg/keyset`, runs every file in its tests.

## Files

Each file is one JSON object:

| Key | Value |
|---|---|
| `schema` | always `"abylora.keyset.vectors.v1"` |
| `kind` | `"consumer"`, `"producer.conformance"`, `"producer.resume"` or `"producer.node_direction"` |
| `rules` | non-empty array of strings: the contract rule numbers the file tests |
| `cases` | non-empty array of cases of that kind |

A file is named `<group>-<number>-<name>.json`, where `group` is `consumer` for kind
`consumer` and `producer` otherwise, and `number` is the vector's number (`07`, `09a`,
`11b1`). Every case has an `id` that starts with `<number>-` and is unique across all files,
and a `description`, one English sentence.

## Encodings and strictness

- **Bytes** are lowercase hexadecimal, even length, possibly empty (`""`). Hex is used because
  its text sorts exactly as the bytes do, which rule 15's order needs, and base64 text does
  not. Bytes compare as **unsigned** values (0x80 is above 0x7f). Java and Kotlin `byte` is
  signed: compare with `Byte.toUnsignedInt`, or `Arrays.compareUnsigned`, never with `<`.
- **64-bit integers** (versions, `valid_until`, `skipped`) are decimal **strings** in canonical
  form: no `+`, no leading zero (`"0"` itself is allowed), never `"-0"`. Only `valid_until`
  may be negative. Strings, because many JSON parsers lose precision above 2^53, and vector 06
  uses `9007199254740993` (2^53 + 1) on purpose.
- Booleans are JSON booleans.
- Every key shown is **required** unless marked *optional*. An unknown key, a repeated key
  within one object, and `null` anywhere are errors.
- **No version in any file is `1`.** The control plane seeds the counter at a random value of
  at least 1 (rule 9), so every case starts from a non-trivial version; an implementation that
  assumes the first version is 1 fails. `"0"` appears only where 0 means "holds nothing" or is
  itself the violation.

## Entry

```json
{"public_key": "<hex>", "tunnel_ip": "<hex>", "tunnel_ip6": "<hex>", "valid_until": "<int64>"}
```

The four fields of `KeySetEntry`, raw bytes in hex. An empty `tunnel_ip6` is absence. Entries in
a vector may be malformed on purpose (rule 11). A **set** is a JSON array of entries; its order
carries no meaning.

## Control-plane message

A `ControlPlaneMessage` is a JSON object with **at most one key**, naming its arm:

| JSON | Message |
|---|---|
| `{"snapshot_begin": {"version": "<u64>"}}` | `SnapshotBegin` |
| `{"upsert": {"entry": <entry>}}` | `Upsert` |
| `{"upsert": {}}` | `Upsert` with no entry |
| `{"snapshot_end": {"version": "<u64>"}}` | `SnapshotEnd` |
| `{"delta": {"from_version": "<u64>", "to_version": "<u64>", "ops": [<op>, ...]}}` | `Delta`; `ops` may be `[]` |
| `{"heartbeat": {"current_version": "<u64>"}}` | `Heartbeat` |
| `{}` | a message with no arm |
| `{"wire": "<hex>"}` | the message given as its protobuf binary encoding |

An **op** is `{"upsert": {"entry": <entry>}}`, `{"upsert": {}}` (no entry),
`{"remove": {"public_key": "<hex>"}}`, or `{}` (an op with no arm).

The `wire` form exists for what JSON cannot spell: an arm this schema version does not know. Two
vectors use it: `"3200"` is a `ControlPlaneMessage` carrying only field 6, empty (an unknown
arm), and `"220a0892211093211a021a00"` is a `Delta` from 4242 to 4243 whose one op carries only
field 3, empty (an unknown op arm). Decode the bytes with the generated types.

## Node message

A `NodeMessage` is `{"hello": {"held_version": "<u64>"}}`,
`{"applied": {"version": "<u64>", "skipped": "<u64>"}}`, `{}` (no arm) or
`{"wire": "<hex>"}`. `"1a00"` is a `NodeMessage` carrying only field 3, empty (an unknown arm).

## Consumer vectors (`"kind": "consumer"`)

```json
{
  "id": "...", "description": "...",
  "own_public_key": "<hex, 32 bytes>",
  "initial": {"cursor": "<u64>", "set": [<entry>, ...]},
  "steps": [<step>, ...],
  "final": {"cursor": "<u64>", "set": [<entry>, ...], "skipped": "<u64>"}
}
```

**To run a case:** start the node's state with cursor `initial.cursor`, holding
`initial.set` (always well-formed, with no two entries sharing a key or a tunnel address),
refusing no key, with no stream open. `own_public_key` is the receiving node's own interface
key (rule 11). Then take the steps in order:

- `{"hello": {"held_version": "<u64>"}}`: the node opens a stream. It must send exactly this
  `held_version`, its cursor. Any snapshot left open is discarded: a snapshot never spans
  streams, and on stream loss the node keeps its last applied set (rule 8). Every case starts
  with a `hello`, and after an outcome that closes the stream the next message follows a new
  `hello`.
- `{"receive": <message>, "apply_succeeds": <bool, optional, default true>, "expect": <expect>}`:
  the message arrives. If handling it attempts an apply (a `SnapshotEnd`, or a `Delta` that is
  not a violation), that apply succeeds exactly when `apply_succeeds` is true. `apply_succeeds`
  is `false` exactly when the expected outcome is `apply_failed`.

**`expect`** is `{"outcome": "<word>"}` plus one more key for two of the words:

| `outcome` | Meaning |
|---|---|
| `accumulating` | inside a snapshot: a `SnapshotBegin` or an `Upsert` was taken; nothing is sent |
| `unchanged` | a legal `Heartbeat`, one whose `current_version` equals the cursor: nothing changes, nothing is sent |
| `applied` | with `"applied": {"version": "<u64>", "skipped": "<u64>"}`: the set was applied and the node sends exactly this `Applied`. Every cursor advance is reported (rule 5), including a zero-op `Delta`, a snapshot equal to the held set, and a snapshot below the cursor |
| `apply_failed` | the apply failed: the cursor becomes 0 and the stream closes (rule 5) |
| `violation` | with `"violation": "<word>"`: the stream closes, the cursor and set are unchanged, and the node reconnects with `Hello{held_version: cursor}` |

**`final`** is the state after the last step. `set` is always present, and it is compared with
the node's held set entry by entry, on all four fields; order carries no meaning. After an
`apply_failed` the cursor is 0 and the held set is the **last set applied successfully**,
unchanged (rule 5, as ruled): the interface may lie anywhere between that set and the target,
which is why the cursor no longer names it. `skipped` may be omitted only when the last received
message's outcome was `apply_failed`.

**`skipped` is a gauge** (rules 11 and 12): how many entries the node currently refuses, not how
many it skipped on this stream. A refused key stays refused across a resume by deltas, and
leaves on a `Remove` of it, on a later well-formed and unclaimed `Upsert` of it, or when a
snapshot replaces the whole set.

**Rule 11 (malformed):** a `public_key` not 32 bytes, or equal to `own_public_key`; a
`tunnel_ip` not exactly 4 bytes, outside `10.64.0.0/10` or inside `10.64.0.0/24`; a `tunnel_ip6`
of a length other than 0 or 16; a `valid_until` not a multiple of 86400. A malformed entry is
not applied, any entry held under its key is removed, the rest applies and the cursor advances.

**Rule 12 (shared tunnel address)** applies to `tunnel_ip` only; two entries sharing a non-empty
`tunnel_ip6` are both kept. Rule 11 applies first (key-set.md at workspace root `fc9a77b`): an
entry it refuses is never installed, cannot claim an address and takes no part in rule 12, in a
snapshot or in a `Delta`, so a valid entry sharing an address only with malformed ones is kept.
In a snapshot every entry sharing a `tunnel_ip` with another is skipped. In a `Delta`,
applied in received order, an `Upsert` claiming a `tunnel_ip` held at that point by a different
key is skipped, and any entry held under its own key is removed.

**Violation words** (consumer). Every consumer vector that expects a violation is built so that
exactly one of these applies. A consumer must produce the outcome `violation`; it may ignore the
word, as a producer may compare `conforms` only:

| Word | Rule | The message |
|---|---|---|
| `message_no_arm` | 13 | has no arm, or an unknown arm |
| `op_no_arm` | 13 | is a `Delta` with an op that has no arm, or an unknown arm |
| `upsert_no_entry` | 13 | is, or carries, an `Upsert` with no entry |
| `snapshot_begin_version_zero` | 13 | is `SnapshotBegin{0}` |
| `snapshot_nested` | 13 | is a `SnapshotBegin` inside a snapshot |
| `snapshot_end_without_begin` | 13 | is a `SnapshotEnd` with no snapshot open |
| `snapshot_end_version_mismatch` | 13 | is a `SnapshotEnd` whose version differs from its `SnapshotBegin` |
| `upsert_outside_snapshot` | 13 | is an `Upsert` outside a snapshot |
| `delta_inside_snapshot` | 13 | is a `Delta` inside a snapshot |
| `heartbeat_inside_snapshot` | 13 | is a `Heartbeat` inside a snapshot |
| `delta_from_version_zero` | 9 | is a `Delta` with `from_version` 0 |
| `delta_versions_not_increasing` | 13 | is a `Delta` with `to_version` ≤ `from_version` |
| `delta_gap` | 5 | is a `Delta` whose `from_version` is not the cursor |
| `heartbeat_below_cursor` | 13 | is a `Heartbeat` whose `current_version` is below the cursor |
| `heartbeat_above_cursor` | 6, 13 | is a `Heartbeat` whose `current_version` is above the cursor: the node reconnects at once, with no timer and no grace period. Every version up to `current_version` was delivered before it, and on a stream resumed at the published version the ceiling is the resumed `held_version` |

A `Delta` is judged whole before any op applies: a violation anywhere in it applies none of it.

## Conformance vectors (`"kind": "producer.conformance"`)

```json
{
  "id": "...", "description": "...",
  "old": {"version": "<u64>", "set": [<entry>, ...]},
  "new": {"version": "<u64>", "set": [<entry>, ...]},
  "delta": {"from_version": "<u64>", "to_version": "<u64>", "ops": [<op>, ...]},
  "expect": {"conforms": <bool>, "failure": "<word, only when conforms is false>"}
}
```

`delta` is a `Delta` a producer emitted to move from `old` to `new`. Both sets are well-formed
(rule 11, without the own-key check), with no shared key, no shared `tunnel_ip` and no shared
non-empty `tunnel_ip6`; any number of entries may have an empty `tunnel_ip6`. It conforms when
all of these hold:

1. its shape is legal, as for a consumer (`delta_shape`: a `from_version` of 0 (rule 9), a
   `to_version` not above it, an op with no arm, or an `Upsert` with no entry (rule 13));
2. `from_version` and `to_version` are `old.version` and `new.version` (`versions_mismatch`);
3. taking each op in order: no `Remove` follows an `Upsert` (`upsert_before_remove`, rule 10);
   no key, as raw bytes, appears in two ops (`key_repeated`, rule 10); within the removes, and
   within the upserts, each key is strictly greater than the one before it as raw bytes,
   compared lexicographically, never as base64 text (`not_sorted`, rule 15);
4. a consumer applying it to `old` in order skips no entry under rule 11 or 12, and the set it
   ends holding has no two entries sharing a non-empty `tunnel_ip6` (`entry_refused`: rule 11,
   "the producer validates every entry before emitting it"; rule 12, "producer conformance
   covers both"). The own-key check of rule 11 is not part of conformance: it depends on which
   node receives the entry, and the control plane's registration refusal guarantees it;
5. that consumer ends holding exactly `new` (`result_differs`).

`failure` names the first check that fails, in that order, and op by op within check 3. A
producer may compare `conforms` only.

## Resume vectors (`"kind": "producer.resume"`)

```json
{
  "id": "...", "description": "...",
  "held_version": "<u64>",
  "log": [{"from_version": "<u64>", "to_version": "<u64>"}, ...],
  "published": "<u64>",
  "expect": {"send": "snapshot", "snapshot_version": "<u64>"}
}
```

or `"expect": {"send": "deltas", "deltas": [{"from_version": "<u64>", "to_version": "<u64>"}, ...]}`.

`log` is the producer's change log, oldest first: contiguous deltas whose last `to_version` is
`published`, the last published version (rule 15), never a live counter. It is `[]` after a
restart (rule 7). The node said `Hello{held_version}`. Rule 3: the log can resume from the
version it starts from and from the `to_version` of each logged delta, and from nothing else;
a number between two of those is never published. When `held_version` is one of them, the
producer sends every logged delta after it and no snapshot: none at all (`"deltas": []`) when
`held_version` is `published`. Otherwise (0, below the log, between two logged versions, above
`published`, or any `held_version` when the log is empty) it sends a snapshot at `published`,
then the deltas published after it as they come.

## Node-direction vectors (`"kind": "producer.node_direction"`)

```json
{
  "id": "...", "description": "...",
  "steps": [{"sent": <control-plane message>} | {"received": <node message>, "expect": <expect>}, ...],
  "records": [<record>, ...]
}
```

Rule 16, for the control plane's side of **one** stream. A `sent` step is a message the control
plane sends; a `SnapshotEnd`'s `version` and a `Delta`'s `to_version` are then **delivered** on
this stream. A `SnapshotBegin`, a `Heartbeat` and the `Hello`'s own `held_version` deliver
nothing. A `received`
step is a message the node sends, and `expect` is one of three outcomes, `record`, `violation`
or `closed`:

- `{"outcome": "record", "record": <record>}`: the control plane may record it. A record is
  `{"applied_version": "<u64>", "skipped": "<u64>, optional"}`. A `Hello` records its
  `held_version` as the applied version at once (*Readiness*) and has no `skipped`; an `Applied`
  records its `version` and `skipped`.
- `{"outcome": "violation", "violation": "<word>"}`: the stream closes. Checked in this order:
  `node_message_no_arm` (no arm or an unknown arm), `applied_before_hello`, `hello_repeated`,
  `applied_decreasing` (below the previous `Applied` on this stream; equal is legal),
  `applied_not_delivered` (the version was not delivered on this stream). "No lower" compares
  with the previous `Applied` only, never with the `Hello`: a snapshot answering a
  `held_version` above the published version is legitimately lower.
- `{"outcome": "closed"}`: a message after a violation. Nothing is recorded from the violating
  message onward.

`records` lists every record in order. A record made before a violation, a `Hello`'s included,
stands.

## What these vectors do not cover

Rule 4 (applying as a diff against the live interface), rule 6 (heartbeat timers), rule 8
(removing expired entries on stream loss), rule 14 (a live read that resets the cursor), rule
15's 60-second epoch and its "a snapshot carries the set as of the last published boundary",
and `valid_until` expiry. Each needs a clock or a kernel; the consumer and the producer test them
in their own repositories.
