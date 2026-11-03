// SPDX-License-Identifier: AGPL-3.0-only

package relayverify

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Copied from <workspace>/docs/contracts/relay-list.md, The signing certificate, Test vectors --
// never recomputed here. RFC 8032 section 7.1's published test keys; never a real root.
const (
	testRootPubHex    = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" // TEST 1
	testSigningPubHex = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c" // TEST 2

	vectorC             = `{"_type":"abylora.relay-list.signing-certificate","spec_version":1,"env":"staging","root":"BuP9j9opu2CrWVV95h7bCuzbIxE0vjDnW0Vfjht5L6k=","key":"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z"}`
	vectorCMessageHex   = "d471f8c2da9390ef84e4d79371a3e0d79ca520d7eb926c05597f9ebf5be69487"
	vectorCChecksumHex  = "e05cf630720198af9ce8807511e111a86bdfea629862e1834fb24ddbc4b94245"
	vectorCSignedHex    = "73696773756d2e6f72672f76312f747265652d6c65616600e05cf630720198af9ce8807511e111a86bdfea629862e1834fb24ddbc4b94245"
	vectorCSignatureHex = "3eb6da331115c752f6f321c10d34300ba6cc345d4fbe894bbd5200c1f401c633da6d4acd4f5087ce54096aafa2d2a2d0b5f1c0dcfd680357a87e965a309adb0b"

	vectorL             = `{"_type":"abylora.relay-list","version":1,"generated_at":"2026-01-02T00:00:00Z","expires_at":"2026-01-03T00:00:00Z","api_endpoints":[{"host":"192.0.2.1","port":443,"transports":["https"]}],"relays":[{"node_id":"00000000-0000-4000-8000-000000000001","hostname":"test-1.example","ipv4":"192.0.2.10","ipv6":null,"wg_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","country":"SE","city":"Stockholm","capacity_weight":100,"status":"active","ownership":"owned","provider":"Example","endpoints":[{"kind":"plain","port":51820,"params":{}}]}]}`
	vectorLMessageHex   = "3163711e927a304cb0f26e9a730227df33f5f6059a8414a4b3755c312e433606"
	vectorLChecksumHex  = "1e30f68403e91e276571847d7e871e30efe6ec4adcbb34c1ff7155165df15997"
	vectorLSignedHex    = "73696773756d2e6f72672f76312f747265652d6c656166001e30f68403e91e276571847d7e871e30efe6ec4adcbb34c1ff7155165df15997"
	vectorLSignatureHex = "7356ab3758093a66f3556c76cf8a631df715933bb03d33360b5d2d44e9140b073db6c3bdbb645bb63f6daed61f5ab35fe6be8e4a5505baf5f20b49a9d4298205"

	// N1: Ed25519 over x directly. N2: single hash (checksum = message). Each MUST be rejected
	// as a signature over vector C under the root.
	n1SignatureHex = "6065aa9d02edadd15a2cfb1c1a115813436bf428d3803b8ec47818dc1eb87dbf39aadac3a983f759bf64a6748c605ac72fb5584604a1462bf616bebea7dd0c0a"
	n2SignatureHex = "8a87e44e75eb5a0bcb07c9b4b9df57b0d2bd4cc6706ebfcc00c8597ef9403bcaaae6da6c861deb64f54bcfd9bb0a7542cb85afd5ce71c1c76f7e767ba0da7c0c"
)

func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(out) {
		t.Fatalf("failed to decode a 32-byte hex fixture: %v", err)
	}
	copy(out[:], b)

	return out
}

func mustHex64(t *testing.T, s string) [64]byte {
	t.Helper()
	var out [64]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(out) {
		t.Fatalf("failed to decode a 64-byte hex fixture: %v", err)
	}
	copy(out[:], b)

	return out
}

func TestVectorCAndVectorLHashAsTheContractPrints(t *testing.T) {
	if len(vectorC) != 281 || len(vectorL) != 545 {
		t.Fatalf("len(C), len(L) = %d, %d, want 281, 545", len(vectorC), len(vectorL))
	}
	for _, v := range []struct{ name, x, message, checksum, signed string }{
		{"C", vectorC, vectorCMessageHex, vectorCChecksumHex, vectorCSignedHex},
		{"L", vectorL, vectorLMessageHex, vectorLChecksumHex, vectorLSignedHex},
	} {
		m, c := leafMessage([]byte(v.x)), leafChecksum([]byte(v.x))
		if got := hex.EncodeToString(m[:]); got != v.message {
			t.Errorf("%s message = %s, want %s", v.name, got, v.message)
		}
		if got := hex.EncodeToString(c[:]); got != v.checksum {
			t.Errorf("%s checksum = %s, want %s", v.name, got, v.checksum)
		}
		if got := hex.EncodeToString(leafSigned([]byte(v.x))); got != v.signed {
			t.Errorf("%s signed = %s, want %s", v.name, got, v.signed)
		}
	}
	// message is SHA-256(x), checksum SHA-256(message): stated once, checked once.
	if m := sha256.Sum256([]byte(vectorC)); hex.EncodeToString(m[:]) != vectorCMessageHex {
		t.Error("vector C's message is not SHA-256 of its octets")
	}
}

func TestVectorCVerifiesUnderTheTestRootAndVectorLUnderTheTestSigningKey(t *testing.T) {
	if !verifyLeaf(mustHex32(t, testRootPubHex), []byte(vectorC), mustHex64(t, vectorCSignatureHex)) {
		t.Error("vector C does not verify under the test root")
	}
	if !verifyLeaf(mustHex32(t, testSigningPubHex), []byte(vectorL), mustHex64(t, vectorLSignatureHex)) {
		t.Error("vector L does not verify under the test signing key")
	}
}

func TestTheNegativeVectorsAreRefused(t *testing.T) {
	root, signing := mustHex32(t, testRootPubHex), mustHex32(t, testSigningPubHex)
	cases := map[string]struct {
		key [32]byte
		sig string
	}{
		"N1 Ed25519 over x directly":                    {root, n1SignatureHex},
		"N2 single hash":                                {root, n2SignatureHex},
		"N3 vector C's signature under the signing key": {signing, vectorCSignatureHex},
		"N4 vector L's signature over vector C":         {root, vectorLSignatureHex},
	}
	for name, tc := range cases {
		if verifyLeaf(tc.key, []byte(vectorC), mustHex64(t, tc.sig)) {
			t.Errorf("%s: accepted", name)
		}
	}
}
