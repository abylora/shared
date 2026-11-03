// Package relaylist holds the relay list's wire types -- Document, Relay, Endpoint,
// APIEndpoint and FetchTransport -- and Document.Encode, which produces the exact octets that
// are stored, later signed, and served. Field names and nesting come from
// <workspace>/docs/contracts/relay-list.md, Shape, and from nowhere else.
//
// THIS IS THE HOME OF THESE DECLARATIONS (D26). The producer, control-plane, and every client
// import them from here, so the encoder and the decoder share one spelling of every field
// name. A copy declared anywhere else is exactly the drift D26 removed.
//
// READING A GOVERNS THE ENCODING, AND IT REMOVES WORK. What gets signed is the exact octet
// sequence served, not a re-derivation of it, so there is no canonicalisation scheme and no
// field-ordering rule to honour. The artifact is stored and served byte-for-byte;
// regenerating yields a new version, never the same bytes twice, so byte-determinism across
// runs is not an obligation of this package.
//
// DECODE IS LENIENT WHERE NO CLIENT ACTS AND STRICT WHERE ONE DOES, and it verifies nothing
// (ruled 2026-11-01, contract, Strict parsing). An unknown field is ignored at every level; an
// endpoint of unknown kind and an api_endpoints transport of unknown value are skipped; a relay of
// unknown status is kept and is not Pickable; an unknown ownership is kept verbatim; a relay left
// with no known endpoint stays; a node_id on more than one relay makes each of them unpickable.
// Acted-on values stay strict, and WHERE A VIOLATION IS FOUND DECIDES ITS SCOPE: a list-level one
// (_type, version, the timestamps, invalid UTF-8 or a lone-surrogate escape) refuses the list; a
// relay-level one (a relay field missing or of the wrong JSON type, an empty node_id or endpoints
// list, ipv4, ipv6, wg_public_key, capacity_weight, a duplicate (kind, port), a repeated node_id)
// makes that relay unpickable and keeps the rest; an endpoint-level one (a bad port, params, host
// or transports, or a field missing inside one endpoint) skips that endpoint, and a skipped
// endpoint counts for nothing. Encode refuses the same relay-level rules through the same
// classifier, classifyRelay, so the producer cannot publish a relay a client would set aside. "One bad relay is a producer defect, and
// refusing the list would strand every client on its last-known-good list for it." A list that
// leaves no Pickable relay after scoping is refused with ErrNoPickableRelay. A duplicate key at
// any depth is refused. The octets are verified
// BEFORE they are parsed, by pkg/relayverify, which sits above this package because this package
// may not import crypto; so leniency opens no signature differential. A decoded document need not
// re-encode; clients never re-sign.
//
// NO CLOCK AND NO KEY MATERIAL. generated_at and expires_at are passed in, which is what
// makes a golden-byte test possible at all; the command composing a document owns the clock.
// Nothing here signs or loads a key. imports_test.go holds both.
//
// NOTHING HERE LOGS, and nothing may: a Relay holds a node's hostname, addresses and
// provider, which D19 keeps out of a log line. Every type renders itself as a placeholder
// through slog.LogValuer, and every error names a node_id at most.
//
// The document enumerates NODES. It carries no account, no device and no peer, and nothing
// here may ever associate one with a node (invariant 2, D22).
package relaylist
