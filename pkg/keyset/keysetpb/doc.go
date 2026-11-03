// SPDX-License-Identifier: AGPL-3.0-only

// Package keysetpb holds the key set stream's wire types: the Go that protoc generates from
// proto/abylora/keyset/v1/keyset.proto for the one bidirectional stream
// /abylora.keyset.v1.KeySet/Stream. Messages, fields and their meaning come from
// <workspace>/docs/contracts/key-set.md, Record, Delivery and Readiness, and from nowhere
// else.
//
// THIS IS THE HOME OF THESE DECLARATIONS (D26). control-plane, which streams the key set, and
// node-agent, which applies it, both import them from here, so the producer and the consumer
// share one definition. A second .proto or a copy of these types anywhere else is exactly the
// drift D26 removed.
//
// TYPES ONLY, NO RULES. Nothing here validates an entry, tracks a snapshot or compares
// versions. The stream's state machine, the skipping of malformed entries and the
// one-op-per-key rule bind the producer and the consumer. A reference applier, planned beside
// the delta vectors in pkg/keyset, is where they will be written as code. The .proto quotes
// each rule on the field it governs, for the reader. Quoting is not enforcing.
//
// THE ENTRY IS EXACTLY FOUR FIELDS, and it is the only per-device record that reaches every
// node: public_key, tunnel_ip, tunnel_ip6 and valid_until. It has no account id, which keeps
// the account a device belongs to off the nodes (invariant 2), and no secret, which keeps the
// key set a channel that carries no secret (key-set.md, No secrets; D16). entry_test.go pins
// the four, and a fifth fails it.
//
// A NODE SAYS VERSIONS AND ONE GAUGE, NEVER KEYS. Hello and Applied carry versions and an
// aggregate count of the entries the node currently refuses. There is no per-key
// acknowledgement, because one would be a per-device, per-node record (D34).
//
// THE NAMES AND NUMBERS ARE WIRE CONTRACT. The proto package abylora.keyset.v1 and the service
// KeySet form the gRPC method path, and the field numbers form the encoding. Renaming or
// renumbering either breaks every deployed node, the same rule as transport.Kind's strings. A
// change of meaning is a new v2 package beside this one, never an edit to it.
//
// VERSIONS ARE uint64, AND 0 MEANS "HOLDS NOTHING". Every version is at least 1, and the
// counter's start is seeded at random so that a version does not publish how many changes there
// have been. So proto3 encoding 0 as an absent field loses nothing: absent and zero mean the
// same.
//
// AN UNSET OR UNKNOWN ARM DECODES AS NO BODY. Every envelope is a oneof, so GetBody() == nil
// covers both cases, and the contract makes both a violation. The same holds for the DeltaOp
// oneof, where GetOp() == nil covers an op with neither upsert nor remove. An Upsert with no
// entry is a violation too: it has no key, so the malformed-entry skip cannot apply to it. The
// nil check detects a message with no known arm, and only that. A message carrying a known arm
// plus an unknown field, or two known arms (the decoder keeps the last), decodes with a body; a
// consumer cannot detect those, and the contract does not ask it to. A new arm is therefore a
// breaking change: a consumer that has not been redeployed closes the stream on it.
//
// THE GENERATED FILES ARE COMMITTED, and consumers never run generation: they fetch a tag from
// the public module proxy (D26). Regenerate with `go generate ./tools` from the module root.
// tools/tools.go pins the plugins, and drift_test.go proves that the committed files equal a
// regeneration under the protoc release it names.
//
// NOTHING HERE LOGS, and nothing may: every message carries device public keys and tunnel
// addresses. imports_test.go holds that, and keeps wireguard-go and wgctrl out of the package.
package keysetpb
