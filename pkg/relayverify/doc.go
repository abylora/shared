// SPDX-License-Identifier: AGPL-3.0-only

// Package relayverify verifies a relay list bundle as a client must, and only then decodes it:
// <workspace>/docs/contracts/relay-list.md, Rules, Signing and trust, The signing certificate and
// Freshness, and nothing else.
//
// A SIBLING OF relaylist AND signingcert, ABOVE BOTH. relaylist's guard forbids crypto and
// signingcert deliberately verifies nothing, so verification sits here, and neither guard is
// relaxed.
//
// THE ORDER, on the exact octets before any parse. The certificate: its proof is REQUIRED; the
// proof's leaf names a pinned root by key hash; that root's leaf signature verifies over the
// certificate octets; the leaf is included in the proof's tree head, whose log signature and
// witness quorum hold under either pinned policy; only then is it decoded strictly by
// signingcert; its root must be the signing root's fingerprint; its key must be neither pinned
// root; and its key must not be weak -- one of the 8 small-order encodings or a non-canonical one
// -- because crypto/ed25519 accepts the signature R = identity, S = 0 under the identity key over
// any message, so a certified small-order key would let anyone sign lists. That checks the
// certified key and does not change the verification rule. The list: its proof is REQUIRED; the leaf names the certificate's key by key
// hash; that key's leaf signature verifies over the list octets; inclusion and quorum as above;
// and the quorum must also hold counting ONLY the cosignatures whose T lies in
// [not_before - 10m, not_after + 10m], inclusive -- on the list's own proof, never the
// certificate's. Then relaylist.Decode, the rollback check, and the advisory Expired flag.
//
// DECODE DECIDES SCOPE WHERE A VIOLATION IS FOUND (contract, Strict parsing): a list-level one
// refuses the list, and Verify returns ErrListMalformed or ErrListDuplicateKey -- or
// ErrListHasNoPickableRelay when scoping leaves no pickable relay; a relay-level one
// makes that relay unpickable and an endpoint-level one skips that endpoint, and the list still
// verifies. One bad relay is a producer defect, and refusing the list would strand every client
// on its last-known-good list for it.
//
// THE LEAF CONSTRUCTION, pinned exactly: message = SHA-256(x), checksum = SHA-256(message), and
// the signature is Ed25519 over "sigsum.org/v1/tree-leaf" || 0x00 || checksum. Never Ed25519 over
// x directly.
//
// THE Ed25519 RULE IS Go's crypto/ed25519, and it covers every Ed25519 signature a client
// verifies: the leaf signatures, verified here by verifyEd25519, and the log's and witnesses'
// signatures inside a sigsum proof, verified by sigsum-go. That holds only because sigsum-go is
// PINNED AT v0.14.1, which verifies those with crypto/ed25519 itself. v1.0.0 requires go 1.27,
// raising every consumer's floor, and its stricter check refuses non-canonical and low-order
// keys and low-order R, which changes the rule for log and witness signatures. So upgrading
// sigsum-go is a contract amendment, not a dependency bump: before it, re-read sigsum-go's
// pkg/crypto, pkg/policy, pkg/proof and pkg/types at the new version, because this package also
// relies on behaviour read at v0.14.1 -- VerifyCosignedTreeHead reads a cosignature's timestamp
// only as signed data, so a filtered cosignature set is a filtered quorum; "quorum none" holds
// with no witness; and proof versions 1 and 2 both parse. dependency_test.go fails on any
// version change.
//
// A PINNED POLICY MUST REQUIRE A WITNESS. With none there is no T, and under the filtered
// cosignature set a policy whose quorum holds with no witness would accept a list cosigned
// entirely outside the certificate's window. NewVerifier refuses one. Policies are sigsum policy
// text, parsed by policy.ParseConfig; a named policy is never looked up, because that reads the
// filesystem and the environment.
//
// NO CLOCK. Certificate validity is enforced against the witnesses' clock, never the client's.
// Verify's asOf is used for one thing, the advisory Expired flag. imports_test.go refuses
// time.Now, time.Since and time.Until.
//
// NOTHING HERE LOGS, and every error is a bare constant sentinel carrying no input: a Relay holds
// hostnames, addresses and providers, which D19 keeps out of every log line and error.
// sigsum-go's own errors quote their input and are discarded. Every type renders as a
// placeholder through slog.LogValuer. sigsum-go's pkg/policy links its own logger, reached only by
// named-policy lookup, which imports_test.go forbids.
//
// shared/ SHIPS NO ROOTS AND NO POLICIES. Production roots do not exist until the first
// ceremony; each client build injects its environment's values through Pins.
//
// THE PROOF FIXTURES under testdata are generated here, offline, by testdata/generate, with
// throwaway keys. They are UNCONFIRMED UNTIL control-plane RECOMPUTES THEM INDEPENDENTLY; only
// then do they enter the contract beside vectors C and L. The ed25519-speccheck cases are
// third-party (Apache-2.0) and checked by SHA-256 before use; see
// testdata/ed25519-speccheck-cases.README.
package relayverify
