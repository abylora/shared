// Package signingcert holds the relay list's signing certificate: its wire type, Encode,
// a strict Decode, and Fingerprint. The certificate is the root's statement that a signing
// key may sign relay lists for a window; its format is
// <workspace>/docs/contracts/relay-list.md, The signing certificate, and nothing else.
//
// A SIBLING OF relaylist, NOT PART OF IT. Fingerprint needs crypto/sha256 and an Ed25519
// public key, and relaylist's guard forbids crypto for good reason. Neither package imports
// the other.
//
// NO SIGNATURE IS VERIFIED HERE, and no private key is held. Decoding a certificate says what
// it claims, not that the root claimed it. Verification arrives with the first client that
// needs it.
//
// NO CLOCK. Whether a certificate's window holds is judged against the witnesses' clock, never
// the local one (contract, Validity), and that judgement is not this package's.
//
// NOTHING HERE LOGS, and every error is a bare constant sentinel that carries no input.
// imports_test.go holds the import, key and clock rules.
package signingcert
