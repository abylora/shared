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
// THERE IS NO DECODE YET. It arrives with the first client, in this package and on the same
// wire structs. Its forward-compatibility rule -- what an old client does on meeting an
// endpoint kind it does not know -- is ruled then, not now, and nothing here pre-empts it.
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
