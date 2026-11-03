// SPDX-License-Identifier: AGPL-3.0-only

package relayverify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// The contract's edge vectors: the twelve cases of ed25519-speccheck at commit
// 65519336fda78a3d016e947df6d82848aca0c9da, verbatim (Apache-2.0; see
// testdata/ed25519-speccheck-cases.README). The file is untrusted downloaded data, so its
// SHA-256 is checked against the contract's before a byte of it is parsed.
const speccheckSHA256 = "08e47a36d9aead288664930505584f353fff113ab854f2800db1e4f5b3540450"

// The contract's verdict table, index = case number. Case 11 (non-canonical A, not reduced for
// the hash) is ACCEPTED: Go, BoringSSL, CryptoKit and OpenSSL 3.0 accept it, and rejecting it is
// a disagreement between clients, not extra safety.
var speccheckVerdicts = [12]bool{true, true, true, true, false, false, false, false, false, false, false, true}

func readSpeccheck(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "ed25519-speccheck-cases.json"))
	if err != nil {
		t.Fatalf("failed to read the speccheck file: %v", err)
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != speccheckSHA256 {
		t.Fatalf("speccheck file SHA-256 = %x, want %s; refusing to parse it", sum, speccheckSHA256)
	}

	return b
}

func TestTheSpeccheckFileIsTheOneTheContractNames(t *testing.T) { readSpeccheck(t) }

func TestEverySpeccheckCaseGetsTheContractsVerdict(t *testing.T) {
	var cases []struct {
		Message   string `json:"message"`
		PubKey    string `json:"pub_key"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(readSpeccheck(t), &cases); err != nil {
		t.Fatalf("failed to parse the speccheck file: %v", err)
	}
	if len(cases) != len(speccheckVerdicts) {
		t.Fatalf("%d cases, want %d", len(cases), len(speccheckVerdicts))
	}

	for i, c := range cases {
		t.Run("case "+strconv.Itoa(i), func(t *testing.T) {
			msg, err := hex.DecodeString(c.Message)
			if err != nil {
				t.Fatalf("failed to decode the message: %v", err)
			}
			sig, err := hex.DecodeString(c.Signature)
			if err != nil {
				t.Fatalf("failed to decode the signature: %v", err)
			}
			if got := verifyEd25519(mustHex32(t, c.PubKey), msg, sig); got != speccheckVerdicts[i] {
				t.Errorf("verdict = %v, want %v", got, speccheckVerdicts[i])
			}
		})
	}
}
