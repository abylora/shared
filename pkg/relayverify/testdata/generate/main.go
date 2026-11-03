// SPDX-License-Identifier: AGPL-3.0-only

// Command generate writes pkg/relayverify's proof fixtures, OFFLINE: throwaway keys, sigsum-go's
// own signing and tree code, nothing submitted to any log, and no network. It lives under
// testdata, so ./... never builds it. Run it from the repository root:
//
//	go run ./pkg/relayverify/testdata/generate -out pkg/relayverify/testdata
//
// THESE FIXTURES ARE UNCONFIRMED UNTIL control-plane RECOMPUTES THEM INDEPENDENTLY. Only then do
// they enter <workspace>/docs/contracts/relay-list.md beside vectors C and L.
//
// How to recompute them:
//
//   - Keys. The current root is RFC 8032 TEST 1 and the signing key RFC 8032 TEST 2, the
//     contract's own test keys, so the base bundle is exactly vectors C and L. Every other Ed25519
//     seed is SHA-256("abylora/shared relayverify fixture key: " + label), for the labels
//     next-root, log-current, log-next, witness-current-1, witness-current-2, witness-next-1 and
//     witness-unlisted. public-keys.txt lists every public key by label.
//   - Policies. current: log-current; witnesses current-witness-1 and current-witness-2; quorum
//     2 of those 2. next: log-next; witness next-witness-1; quorum that witness.
//   - Trees. Every proof is its own 5-leaf tree, the target leaf at index 2; the other leaf
//     hashes are SHA-256("abylora/shared relayverify fixture filler " + i) for i = 0, 1, 3, 4.
//     The log signs the tree head; each witness cosigns it at a chosen time T.
//   - Times. Vector C's window is 2026-01-01T00:00:00Z .. 2026-04-01T00:00:00Z. Certificate
//     proofs are cosigned at 2025-12-15T00:00:00Z (a certificate is issued ahead of use, and its
//     own proof is held to no window); list proofs at 2026-01-02T00:05:00Z, except the window
//     cases, cosigned at not_before - 11m and - 10m, and not_after + 9m, + 10m and + 11m, and the
//     split case: witness 1 at not_after + 9m, witness 2 at not_after + 11m.
//   - The identity-key attack. certificate/identity-key.json certifies the identity point as a
//     signing key -- vector C with its key replaced by hand, because signingcert.Encode refuses a
//     weak key -- and list/vector-l.identity-key.proof logs vector L with the "signature"
//     R = identity, S = 0, which crypto/ed25519 accepts for that key over any message.
//   - Policies per proof. Every proof is logged on log-current and cosigned by both current
//     witnesses, except the *.next.proof files (log-next, cosigned by next-witness-1) and the
//     *.neither.proof files (log-current, cosigned only by witness-unlisted, which no policy
//     names).
//   - Format. sigsum proof version 2, written line by line in sigsum's format with cosignature
//     lines sorted by witness key hash -- sigsum-go's CosignedTreeHead.ToASCII writes them in map
//     order -- and re-parsed with proof.SigsumProof.FromASCII before it is written.
//
// Ed25519 is deterministic and every input above is fixed, so two runs write identical files.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/abylora/shared/pkg/signingcert"
	"sigsum.org/sigsum-go/pkg/ascii"
	sigcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/types"
)

// The contract's test keys and vectors, copied verbatim from
// <workspace>/docs/contracts/relay-list.md, Test vectors.
const (
	test1Seed        = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	test2Seed        = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
	vectorC          = `{"_type":"abylora.relay-list.signing-certificate","spec_version":1,"env":"staging","root":"BuP9j9opu2CrWVV95h7bCuzbIxE0vjDnW0Vfjht5L6k=","key":"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z"}`
	vectorCSignature = "3eb6da331115c752f6f321c10d34300ba6cc345d4fbe894bbd5200c1f401c633da6d4acd4f5087ce54096aafa2d2a2d0b5f1c0dcfd680357a87e965a309adb0b"
	vectorL          = `{"_type":"abylora.relay-list","version":1,"generated_at":"2026-01-02T00:00:00Z","expires_at":"2026-01-03T00:00:00Z","api_endpoints":[{"host":"192.0.2.1","port":443,"transports":["https"]}],"relays":[{"node_id":"00000000-0000-4000-8000-000000000001","hostname":"test-1.example","ipv4":"192.0.2.10","ipv6":null,"wg_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","country":"SE","city":"Stockholm","capacity_weight":100,"status":"active","ownership":"owned","provider":"Example","endpoints":[{"kind":"plain","port":51820,"params":{}}]}]}`
	vectorLSignature = "7356ab3758093a66f3556c76cf8a631df715933bb03d33360b5d2d44e9140b073db6c3bdbb645bb63f6daed61f5ab35fe6be8e4a5505baf5f20b49a9d4298205"
)

// identityKey is the Ed25519 identity point's encoding, (0, 1): the first of the 8 small-order
// encodings in ed25519-speccheck's src/main.rs (EIGHT_TORSION) at commit
// 65519336fda78a3d016e947df6d82848aca0c9da.
var identityKey = sigcrypto.PublicKey{1}

var (
	notBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	certT     = time.Date(2025, 12, 15, 0, 0, 0, 0, time.UTC)
	listT     = time.Date(2026, 1, 2, 0, 5, 0, 0, time.UTC)
)

func check(err error) {
	if err != nil {
		log.Fatalf("failed to generate the fixtures: %v", err)
	}
}

func seedSigner(hexSeed string) *sigcrypto.Ed25519Signer {
	s, err := sigcrypto.SignerFromHex(hexSeed)
	check(err)

	return s
}

func labelSigner(label string) *sigcrypto.Ed25519Signer {
	seed := sha256.Sum256([]byte("abylora/shared relayverify fixture key: " + label))

	return seedSigner(hex.EncodeToString(seed[:]))
}

func publicHex(s *sigcrypto.Ed25519Signer) string {
	pub := s.Public()

	return hex.EncodeToString(pub[:])
}

type cosigner struct {
	signer *sigcrypto.Ed25519Signer
	at     time.Time
}

// leafSignature is leafKey's sigsum leaf signature over the octets x: Ed25519 over
// "sigsum.org/v1/tree-leaf" || 0x00 || SHA-256(SHA-256(x)).
func leafSignature(x []byte, leafKey *sigcrypto.Ed25519Signer) sigcrypto.Signature {
	message := sha256.Sum256(x)
	sig, err := types.SignLeafMessage(leafKey, message[:])
	check(err)

	return sig
}

// logged returns a version-2 sigsum proof of the octets x, signed by leafKey, logged by logKey
// and cosigned as given.
func logged(x []byte, leafKey, logKey *sigcrypto.Ed25519Signer, cosigners ...cosigner) []byte {
	return loggedLeaf(x, leafKey.Public(), leafSignature(x, leafKey), logKey, cosigners...)
}

// loggedLeaf is logged for a leaf whose signature is given rather than made: the identity-key
// fixture's forged signature, which no private key produced.
func loggedLeaf(x []byte, leafPub sigcrypto.PublicKey, sig sigcrypto.Signature, logKey *sigcrypto.Ed25519Signer,
	cosigners ...cosigner,
) []byte {
	message := sha256.Sum256(x)
	leaf := types.Leaf{
		Checksum:  sigcrypto.HashBytes(message[:]),
		Signature: sig,
		KeyHash:   sigcrypto.HashBytes(leafPub[:]),
	}

	tree := merkle.NewTree()
	for i := range 5 {
		h := sigcrypto.HashBytes([]byte("abylora/shared relayverify fixture filler " + strconv.Itoa(i)))
		if i == 2 {
			h = leaf.ToHash()
		}
		if !tree.AddLeafHash(&h) {
			log.Fatal("failed to generate the fixtures: a duplicate leaf")
		}
	}
	th := types.TreeHead{Size: tree.Size(), RootHash: tree.GetRootHash()}
	sth, err := th.Sign(logKey)
	check(err)

	logPub := logKey.Public()
	origin := types.SigsumCheckpointOrigin(&logPub)
	cosignatures := map[sigcrypto.Hash]types.Cosignature{}
	for _, c := range cosigners {
		cs, err := th.Cosign(c.signer, origin, uint64(c.at.Unix()))
		check(err)
		pub := c.signer.Public()
		cosignatures[sigcrypto.HashBytes(pub[:])] = cs
	}
	path, err := tree.ProveInclusion(2, th.Size)
	check(err)

	var b bytes.Buffer
	logKeyHash := sigcrypto.HashBytes(logPub[:])
	short := proof.NewShortLeaf(&leaf)
	check(ascii.WriteInt(&b, "version", proof.SigsumProofVersion))
	check(ascii.WriteHash(&b, "log", &logKeyHash))
	check(short.ToASCII(&b))
	b.WriteString("\n")
	check(sth.ToASCII(&b))
	byKeyHash := func(a, c sigcrypto.Hash) int { return bytes.Compare(a[:], c[:]) }
	for _, kh := range slices.SortedFunc(maps.Keys(cosignatures), byKeyHash) {
		cs := cosignatures[kh]
		check(cs.ToASCII(&b, &kh))
	}
	b.WriteString("\n")
	inclusion := types.InclusionProof{LeafIndex: 2, Path: path}
	check(inclusion.ToASCII(&b))

	// Self-check: sigsum-go must parse exactly what was written.
	var reparsed proof.SigsumProof
	check(reparsed.FromASCII(bytes.NewReader(b.Bytes())))

	return b.Bytes()
}

// replaceOnce replaces old, which must occur exactly once.
func replaceOnce(s, old, new string) string {
	if n := strings.Count(s, old); n != 1 {
		log.Fatalf("failed to generate the fixtures: %q occurs %d times, want 1", old, n)
	}

	return strings.Replace(s, old, new, 1)
}

func certificate(root string, key [32]byte) []byte {
	octets, err := signingcert.Encode(signingcert.Opts{
		Env: signingcert.EnvStaging, Root: root, Key: key, NotBefore: notBefore, NotAfter: notAfter,
	})
	check(err)

	return octets
}

func raw(s *sigcrypto.Ed25519Signer) [32]byte { return [32]byte(s.Public()) }

func main() {
	out := flag.String("out", "", "the directory to write the fixtures into")
	flag.Parse()
	if *out == "" {
		log.Fatal("failed to generate the fixtures: -out is required")
	}

	root := seedSigner(test1Seed)
	signing := seedSigner(test2Seed)
	nextRoot := labelSigner("next-root")
	logCurrent := labelSigner("log-current")
	logNext := labelSigner("log-next")
	witnessCurrent1 := labelSigner("witness-current-1")
	witnessCurrent2 := labelSigner("witness-current-2")
	witnessNext1 := labelSigner("witness-next-1")
	witnessUnlisted := labelSigner("witness-unlisted")

	files := map[string][]byte{}
	write := func(name string, octets []byte) { files[name] = octets }

	write("public-keys.txt", []byte(strings.Join([]string{
		"current-root " + publicHex(root),
		"signing " + publicHex(signing),
		"next-root " + publicHex(nextRoot),
		"log-current " + publicHex(logCurrent),
		"log-next " + publicHex(logNext),
		"witness-current-1 " + publicHex(witnessCurrent1),
		"witness-current-2 " + publicHex(witnessCurrent2),
		"witness-next-1 " + publicHex(witnessNext1),
		"witness-unlisted " + publicHex(witnessUnlisted),
	}, "\n")+"\n"))
	write("policy/current.sigsum-policy", []byte(strings.Join([]string{
		`# relayverify fixture policy "current": throwaway keys, never a real log.`,
		"log " + publicHex(logCurrent),
		"witness current-witness-1 " + publicHex(witnessCurrent1),
		"witness current-witness-2 " + publicHex(witnessCurrent2),
		"group current-quorum 2 current-witness-1 current-witness-2",
		"quorum current-quorum",
	}, "\n")+"\n"))
	write("policy/next.sigsum-policy", []byte(strings.Join([]string{
		`# relayverify fixture policy "next": throwaway keys, never a real log.`,
		"log " + publicHex(logNext),
		"witness next-witness-1 " + publicHex(witnessNext1),
		"quorum next-witness-1",
	}, "\n")+"\n"))

	// The certificates. The base one must be the contract's vector C, signed as the contract
	// prints, or every fixture below is built on the wrong octets.
	rootPub, nextRootPub := root.Public(), nextRoot.Public()
	c := certificate(signingcert.Fingerprint(rootPub[:]), raw(signing))
	if string(c) != vectorC {
		log.Fatal("failed to generate the fixtures: the base certificate is not vector C")
	}
	if sig := leafSignature(c, root); hex.EncodeToString(sig[:]) != vectorCSignature {
		log.Fatal("failed to generate the fixtures: vector C's signature is not the contract's")
	}
	currentAtCertT := []cosigner{{witnessCurrent1, certT}, {witnessCurrent2, certT}}

	write("certificate/vector-c.json", c)
	write("certificate/vector-c.current.proof", logged(c, root, logCurrent, currentAtCertT...))
	write("certificate/vector-c.next.proof", logged(c, root, logNext, cosigner{witnessNext1, certT}))
	write("certificate/vector-c.neither.proof", logged(c, root, logCurrent, cosigner{witnessUnlisted, certT}))

	for _, f := range []struct {
		name   string
		octets []byte
		signer *sigcrypto.Ed25519Signer
	}{
		{"key-is-next-root", certificate(signingcert.Fingerprint(rootPub[:]), raw(nextRoot)), root},
		{"next-root-certifies-current-root", certificate(signingcert.Fingerprint(nextRootPub[:]), raw(root)), nextRoot},
		{"root-names-the-other-root", certificate(signingcert.Fingerprint(nextRootPub[:]), raw(signing)), root},
		{"duplicate-key", []byte(replaceOnce(vectorC, `"env":"staging"`, `"env":"staging","env":"staging"`)), root},
		// Written by hand, as an attacker would: Encode refuses a weak key.
		{"identity-key", []byte(replaceOnce(vectorC, `"key":"`+publicHex(signing)+`"`, `"key":"`+hex.EncodeToString(identityKey[:])+`"`)), root},
	} {
		write("certificate/"+f.name+".json", f.octets)
		write("certificate/"+f.name+".current.proof", logged(f.octets, f.signer, logCurrent, currentAtCertT...))
	}

	// The lists. The base one is the contract's vector L, signed as the contract prints.
	l := []byte(vectorL)
	if sig := leafSignature(l, signing); hex.EncodeToString(sig[:]) != vectorLSignature {
		log.Fatal("failed to generate the fixtures: vector L's signature is not the contract's")
	}
	at := func(t1, t2 time.Time) []cosigner { return []cosigner{{witnessCurrent1, t1}, {witnessCurrent2, t2}} }

	write("list/vector-l.json", l)
	write("list/vector-l.proof", logged(l, signing, logCurrent, at(listT, listT)...))
	for _, w := range []struct {
		name string
		t    time.Time
	}{
		{"t-not-before-minus-11m", notBefore.Add(-11 * time.Minute)},
		{"t-not-before-minus-10m", notBefore.Add(-10 * time.Minute)},
		{"t-not-after-plus-9m", notAfter.Add(9 * time.Minute)},
		{"t-not-after-plus-10m", notAfter.Add(10 * time.Minute)},
		{"t-not-after-plus-11m", notAfter.Add(11 * time.Minute)},
	} {
		write("list/vector-l."+w.name+".proof", logged(l, signing, logCurrent, at(w.t, w.t)...))
	}
	write("list/vector-l.t-split.proof", logged(l, signing, logCurrent, at(notAfter.Add(9*time.Minute), notAfter.Add(11*time.Minute))...))
	write("list/vector-l.signed-by-root.proof", logged(l, root, logCurrent, at(listT, listT)...))
	// The identity key's attack: R = the identity encoding and S = 0 satisfy [S]B = R + [k]A for
	// A = the identity and any message, so this "signature" verifies under crypto/ed25519 over
	// vector L -- and over anything. No private key produced it.
	var forged sigcrypto.Signature
	copy(forged[:32], identityKey[:])
	write("list/vector-l.identity-key.proof", loggedLeaf(l, identityKey, forged, logCurrent, at(listT, listT)...))
	write("list/vector-l.next.proof", logged(l, signing, logNext, cosigner{witnessNext1, listT}))
	write("list/vector-l.neither.proof", logged(l, signing, logCurrent, cosigner{witnessUnlisted, listT}))

	firstRelay := vectorL[strings.Index(vectorL, `{"node_id"`) : len(vectorL)-2]
	sameNodeID := replaceOnce(firstRelay, `"ipv4":"192.0.2.10"`, `"ipv4":"192.0.2.11"`)
	ownNodeID := replaceOnce(replaceOnce(firstRelay, `"ipv4":"192.0.2.10"`, `"ipv4":"192.0.2.12"`),
		`"node_id":"00000000-0000-4000-8000-000000000001"`, `"node_id":"00000000-0000-4000-8000-000000000002"`)
	// A relay-level violation: ipv4 is not a plain IPv4 address, so this relay is not pickable
	// while the first stays pickable, and the list stays valid.
	ipv4NotIPv4 := replaceOnce(replaceOnce(firstRelay, `"ipv4":"192.0.2.10"`, `"ipv4":"2001:db8::99"`),
		`"node_id":"00000000-0000-4000-8000-000000000001"`, `"node_id":"00000000-0000-4000-8000-000000000003"`)

	for _, v := range []struct{ name, octets string }{
		{"unknown-top-level-field", replaceOnce(vectorL, `"version":1,`, `"version":1,"future_field":"ignored",`)},
		{"unknown-relay-field", replaceOnce(vectorL, `"city":"Stockholm",`, `"city":"Stockholm","future_relay_field":1,`)},
		{"unknown-endpoint-kind", replaceOnce(vectorL, `{"kind":"plain","port":51820,"params":{}}]`,
			`{"kind":"plain","port":51820,"params":{}},{"kind":"future-kind","port":443,"params":{}}]`)},
		// A pickable sibling, because a list that leaves no pickable relay is refused.
		{"unknown-status", replaceOnce(vectorL, firstRelay,
			replaceOnce(firstRelay, `"status":"active"`, `"status":"future-status"`)+","+ownNodeID)},
		{"no-pickable-relay", replaceOnce(vectorL, `"status":"active"`, `"status":"draining"`)},
		{"duplicate-key", replaceOnce(vectorL, `"ipv4":"192.0.2.10",`, `"ipv4":"192.0.2.10","ipv4":"192.0.2.66",`)},
		{"repeated-node-id", replaceOnce(vectorL, firstRelay, firstRelay+","+sameNodeID+","+ownNodeID)},
		{"relay-level-violation", replaceOnce(vectorL, firstRelay, firstRelay+","+ipv4NotIPv4)},
		{"certificate-octets", vectorC},
	} {
		write("list/"+v.name+".json", []byte(v.octets))
		write("list/"+v.name+".proof", logged([]byte(v.octets), signing, logCurrent, at(listT, listT)...))
	}

	for _, name := range slices.Sorted(maps.Keys(files)) {
		path := filepath.Join(*out, filepath.FromSlash(name))
		check(os.MkdirAll(filepath.Dir(path), 0o755))
		check(os.WriteFile(path, files[name], 0o644))
	}
}
