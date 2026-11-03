// SPDX-License-Identifier: AGPL-3.0-only

package keyset_test

import (
	"bytes"
	"testing"

	"github.com/abylora/shared/pkg/keyset"
	"github.com/abylora/shared/pkg/keyset/keysetpb"
)

// A producer's set holds no malformed entry and no repeated key or address (rule 12's UNIQUE
// constraints), so SetOf refuses each.
func TestSetOfRefusesAMalformedEntry(t *testing.T) {
	bad := entry(0x11, 2)
	bad.ValidUntil++
	if _, err := keyset.SetOf([]*keysetpb.KeySetEntry{bad}); err != keyset.ErrEntryMalformed {
		t.Fatalf("err %v, want %v", err, keyset.ErrEntryMalformed)
	}
}

func TestSetOfRefusesARepeatedKey(t *testing.T) {
	if _, err := keyset.SetOf([]*keysetpb.KeySetEntry{entry(0x11, 2), entry(0x11, 3)}); err != keyset.ErrSetKeyRepeated {
		t.Fatalf("err %v, want %v", err, keyset.ErrSetKeyRepeated)
	}
}

func TestSetOfRefusesARepeatedTunnelAddress(t *testing.T) {
	if _, err := keyset.SetOf([]*keysetpb.KeySetEntry{entry(0x11, 2), entry(0x22, 2)}); err != keyset.ErrSetAddressRepeated {
		t.Fatalf("err %v, want %v", err, keyset.ErrSetAddressRepeated)
	}
}

// Entries is in raw byte order of the key (bytes.Compare). Eight keys, inserted out of order,
// so map iteration passes this by chance once in 40320 runs.
func TestEntriesAreInRawByteOrder(t *testing.T) {
	firsts := []byte{0xf8, 0x80, 0x22, 0x11, 0x00, 0xa0, 0x7f, 0x33}
	var in []*keysetpb.KeySetEntry
	for i, b := range firsts {
		in = append(in, entry(b, byte(10+i)))
	}
	s, err := keyset.SetOf(in)
	if err != nil {
		t.Fatalf("failed to build a set: %v", err)
	}
	var got []byte
	for _, e := range s.Entries() {
		k := e.PublicKey()
		got = append(got, k[0])
	}
	if want := []byte{0x00, 0x11, 0x22, 0x33, 0x7f, 0x80, 0xa0, 0xf8}; !bytes.Equal(got, want) {
		t.Errorf("order %x, want %x", got, want)
	}
}

// Rule 12, the producer's half: non-empty tunnel_ip6 values are unique too, although no
// consumer checks them yet, so a producer's set refuses a repeated one.
func TestSetOfRefusesARepeatedTunnelIP6(t *testing.T) {
	a, b := entry(0x11, 2), entry(0x22, 3)
	a.TunnelIp6 = bytes.Repeat([]byte{0xfd}, 16)
	b.TunnelIp6 = bytes.Repeat([]byte{0xfd}, 16)
	if _, err := keyset.SetOf([]*keysetpb.KeySetEntry{a, b}); err != keyset.ErrSetAddressRepeated {
		t.Fatalf("err %v, want %v", err, keyset.ErrSetAddressRepeated)
	}
}

// An empty tunnel_ip6 is absence, so any number of entries may have one.
func TestSetOfAcceptsSeveralEmptyTunnelIP6Values(t *testing.T) {
	s, err := keyset.SetOf([]*keysetpb.KeySetEntry{entry(0x11, 2), entry(0x22, 3), entry(0x33, 4)})
	if err != nil || s.Len() != 3 {
		t.Fatalf("err %v, %d entries; want no error and 3", err, s.Len())
	}
}

// Rule 12 at fc9a77b: a producer's set fails conformance under rule 11 when a malformed entry
// shares a valid entry's address, though a consumer keeps the valid one. SetOf, the snapshot
// check, refuses it.
func TestSetOfRefusesAMalformedEntryAtAValidEntrysAddress(t *testing.T) {
	bad := entry(0x22, 2)
	bad.PublicKey = bad.PublicKey[:31]
	if _, err := keyset.SetOf([]*keysetpb.KeySetEntry{entry(0x11, 2), bad}); err != keyset.ErrEntryMalformed {
		t.Fatalf("err %v, want %v", err, keyset.ErrEntryMalformed)
	}
}
