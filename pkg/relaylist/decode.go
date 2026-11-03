// SPDX-License-Identifier: AGPL-3.0-only

package relaylist

import (
	"encoding/json"
	"net/netip"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/abylora/shared/pkg/transport"
)

// The field names, spelled for READING. documentJSON's tags spell them for writing;
// TestDecodeOfTheGoldenDocumentReEncodesToTheGoldenBytes holds the two spellings together.
const (
	fieldType           = "_type"
	fieldVersion        = "version"
	fieldGeneratedAt    = "generated_at"
	fieldExpiresAt      = "expires_at"
	fieldAPIEndpoints   = "api_endpoints"
	fieldRelays         = "relays"
	fieldHost           = "host"
	fieldPort           = "port"
	fieldTransports     = "transports"
	fieldNodeID         = "node_id"
	fieldHostname       = "hostname"
	fieldIPv4           = "ipv4"
	fieldIPv6           = "ipv6"
	fieldWGPublicKey    = "wg_public_key"
	fieldCountry        = "country"
	fieldCity           = "city"
	fieldCapacityWeight = "capacity_weight"
	fieldStatus         = "status"
	fieldOwnership      = "ownership"
	fieldProvider       = "provider"
	fieldEndpoints      = "endpoints"
	fieldKind           = "kind"
	fieldParams         = "params"
)

// Decode parses a relay list's octets. IT VERIFIES NOTHING: call it only on octets that
// pkg/relayverify has verified, which is the order the contract requires.
//
// THE LIST'S UNKNOWN-FIELD RULE IS LENIENT, the opposite of the certificate's (contract, Strict
// parsing, ruled 2026-11-01): an unknown field is ignored at every level; an endpoint of unknown
// kind is skipped, its port and params unread; an api_endpoints transport of unknown value is
// skipped; a relay whose status is unknown is kept and is not Pickable; a relay left with no
// known endpoint stays; a node_id on more than one relay makes every relay carrying it
// unpickable, and the rest are kept. The list stays valid in every one of these cases. A refused
// unknown field would make every deployed client refuse every list the moment the producer adds
// one, and rollback refusal would lock that in.
//
// AN UNKNOWN VALUE IS LENIENT ONLY WHERE NO CLIENT ACTS ON IT. ownership, published for
// transparency, is kept verbatim and shown as it is (Ownership.Valid is false for an unknown
// one); country, city and provider are free text. Values a client acts on stay strict, and WHERE
// A VIOLATION IS FOUND DECIDES ITS SCOPE (contract, Strict parsing, ruled 2026-11-01):
//
//   - LIST LEVEL refuses the list: _type, version, the timestamps, and a document that is not
//     valid UTF-8 or carries a lone-surrogate escape; and ONLY TOP-LEVEL fields otherwise -- one
//     missing or of the wrong JSON type, an empty api_endpoints or relays array on the wire.
//   - RELAY LEVEL makes that relay unpickable and keeps the rest: a field of the relay missing or
//     of the wrong JSON type; an empty node_id, which cannot be matched to a readiness row; an
//     empty endpoints array, the same case as no known endpoint; ipv4 not a plain IPv4 address
//     (Is4); ipv6 not a plain IPv6 address (Is6, not IPv4-mapped, no zone); wg_public_key not
//     standard base64 of exactly 32 bytes; capacity_weight outside 0..100; a duplicate (kind,
//     port); a node_id carried by another relay. Each getter documents the value such a field is
//     left with. A relays element that is not an object is skipped.
//   - ENDPOINT LEVEL skips that endpoint, as an unknown kind does: an endpoint that is not an
//     object or has no kind, and a known-kind endpoint whose port is missing or not an integer in
//     1..65535, or whose params is missing or not an object of string values; and an
//     api_endpoints element that is not an object, or whose host is missing, not a string or fails
//     the host rule (a bare hostname or an IP literal with no zone, the rule Encode applies), whose
//     port is missing or not an integer in 1..65535, or whose transports is missing, not an array,
//     empty, or holds none this client knows. A transports element that is not a string is
//     skipped like an unknown transport, and a repeated one is deduplicated silently.
//     APIEndpoints() holds only usable entries; it may be empty, and the list stays valid.
//
// A SKIPPED ENDPOINT IS NOT AN ENDPOINT: it counts neither towards a duplicate (kind, port) nor
// towards a relay being pickable (contract, Strict parsing).
//
// AFTER SCOPING, A LIST THAT LEAVES NO PICKABLE RELAY IS REFUSED with ErrNoPickableRelay, and the
// client keeps its last-known-good list: adopting it would strand the client exactly as an empty
// list would (contract, Rules). Relay.Pickable is the one predicate.
//
// "One bad relay is a producer defect, and refusing the list would strand every client on its
// last-known-good list for it." Encode refuses every relay-level violation above that its values
// can carry -- through classifyRelay, the same function Decode scopes with, and repeatedNodeIDs
// for a repeated node_id -- so the producer cannot publish a relay a client would set aside. The
// producer never widens the
// value set of an acted-on field unless the contract defines the client's fallback for an unknown
// value: otherwise that kind of change is an additive field or a new _type.
//
// IT IS STRICT ON SHAPE WHERE A DIFFERENTIAL WOULD HIDE. A duplicate key at any depth is
// refused. Field names match exactly: encoding/json's case-insensitive matching is a parser
// differential. Every Shape field must be present; ipv6 may be null, and nothing else may be.
//
// A DECODED DOCUMENT NEED NOT RE-ENCODE: with an unknown status or ownership, a relay refused at
// relay level, or a relay left with no endpoint, Encode refuses it. Clients never re-encode or re-sign. On every document Encode
// can produce, Encode(Decode(x)) == x.
//
// Every error is one of this package's sentinels, BARE: no carrier, because the node_id a
// carrier would name is unverified input here.
func Decode(octets []byte) (Document, error) {
	if !utf8.Valid(octets) {
		return Document{}, ErrDecodeInvalidText
	}
	if err := scan(octets); err != nil {
		return Document{}, err
	}
	if hasLoneSurrogate(octets) {
		return Document{}, ErrDecodeInvalidText
	}
	top, ok := members(octets)
	if !ok {
		return Document{}, ErrDecodeMalformed
	}
	// Before the missing-field check, so a certificate given to Decode says what it is.
	if t, ok := text(top[fieldType]); !ok || t != DocumentType {
		return Document{}, ErrDecodeTypeUnknown
	}
	if !present(top, fieldVersion, fieldGeneratedAt, fieldExpiresAt, fieldAPIEndpoints, fieldRelays) {
		return Document{}, ErrDecodeFieldMissing
	}

	version, ok := integer(top[fieldVersion])
	if !ok {
		return Document{}, ErrDecodeMalformed
	}
	if version < 1 {
		return Document{}, ErrVersionNotPositive
	}
	generatedAt, ok1 := instant(top[fieldGeneratedAt])
	expiresAt, ok2 := instant(top[fieldExpiresAt])
	if !ok1 || !ok2 {
		return Document{}, ErrDecodeMalformed
	}
	if !expiresAt.After(generatedAt) {
		return Document{}, ErrExpiryNotAfterGeneration
	}

	// An empty array on the wire is refused; a fetch endpoint skipped at endpoint level is not,
	// even if every one is: the list stays valid with no usable fetch endpoint.
	apis, err := decodeEach(top[fieldAPIEndpoints], ErrNoAPIEndpoints, decodeAPIEndpoint)
	if err != nil {
		return Document{}, err
	}
	relays, err := decodeEach(top[fieldRelays], ErrNoRelays, decodeRelay)
	if err != nil {
		return Document{}, err
	}
	markRepeatedNodeIDs(relays)
	// After scoping: a list that leaves no pickable relay is refused, and the client keeps its
	// last-known-good list (contract, Rules). Pickable is the one predicate.
	if !slices.ContainsFunc(relays, Relay.Pickable) {
		return Document{}, ErrNoPickableRelay
	}

	return NewDocument(DocumentOpts{
		Version: version, GeneratedAt: generatedAt, ExpiresAt: expiresAt, APIEndpoints: apis, Relays: relays,
	}), nil
}

// markRepeatedNodeIDs refuses, at relay level, every relay whose node_id appears on more than
// one relay. The producer refuses such a list; a client that receives one anyway keeps the rest,
// because two relays with one node_id make readiness ambiguous (contract, Strict parsing). The
// list stays valid. The rule is repeatedNodeIDs, which Encode applies too.
func markRepeatedNodeIDs(relays []Relay) {
	repeated, _ := repeatedNodeIDs(relays)
	for i := range relays {
		if repeated[relays[i].nodeID] && relays[i].refused == relayKept {
			relays[i].refused = relayRefusedNodeIDRepeated
		}
	}
}

// decodeEach decodes a non-empty JSON array element by element, keeping the elements one
// reports kept. An empty array is refused with empty.
func decodeEach[T any](raw json.RawMessage, empty error, one func(json.RawMessage) (T, bool, error)) ([]T, error) {
	elems, ok := elements(raw)
	if !ok {
		return nil, ErrDecodeMalformed
	}
	if len(elems) == 0 {
		return nil, empty
	}

	out := make([]T, 0, len(elems))
	for _, e := range elems {
		v, keep, err := one(e)
		if err != nil {
			return nil, err
		}
		if keep {
			out = append(out, v)
		}
	}

	return out, nil
}

// decodeAPIEndpoint returns keep=false for a fetch endpoint skipped at ENDPOINT LEVEL: an
// api_endpoints element that is not an object; a host missing, not a string, or failing the host
// rule APIEndpoint.Validate applies (a bare hostname, or an IP literal with no zone); a port
// missing or not an integer in 1..65535; a transports array missing or not an array, or left with
// no transport this client knows. A transports element that is not a string is skipped like an
// unknown transport, and a repeated one is deduplicated silently. Nothing inside one entry refuses
// the list, so the error is always nil; APIEndpoints() holds only usable entries.
func decodeAPIEndpoint(raw json.RawMessage) (APIEndpoint, bool, error) {
	m, ok := members(raw)
	if !ok {
		return APIEndpoint{}, false, nil
	}
	host, ok1 := text(m[fieldHost])
	port, ok2 := portNumber(m[fieldPort])
	wire, ok3 := elements(m[fieldTransports])
	if !ok1 || !ok2 || !ok3 || validateHost(host) != nil {
		return APIEndpoint{}, false, nil
	}

	transports := make([]FetchTransport, 0, len(wire))
	for _, w := range wire {
		s, ok := text(w)
		if ft := FetchTransport(s); ok && ft.Valid() && !slices.Contains(transports, ft) {
			transports = append(transports, ft)
		}
	}
	if len(transports) == 0 {
		return APIEndpoint{}, false, nil
	}

	return NewAPIEndpoint(APIEndpointOpts{Host: host, Port: port, Transports: transports}), true, nil
}

// decodeRelay decodes one relay, and returns keep=false for a relays element that is not an
// object, which is skipped. Nothing inside one relay refuses the list: a field missing or of the
// wrong JSON type, and every RELAY-LEVEL violation classifyRelay names, are recorded on the relay
// as why it is not Pickable. Each offending field is left with the value its getter documents,
// the zero value for a field that was missing or of the wrong type. The error is always nil.
func decodeRelay(raw json.RawMessage) (Relay, bool, error) {
	m, ok := members(raw)
	if !ok {
		return Relay{}, false, nil
	}

	malformed := false
	str := func(field string) string {
		v, ok := text(m[field])
		if !ok {
			malformed = true
		}

		return v
	}
	nodeID, hostname, ipv4Text, wgKey := str(fieldNodeID), str(fieldHostname), str(fieldIPv4), str(fieldWGPublicKey)
	country, city, provider := str(fieldCountry), str(fieldCity), str(fieldProvider)
	status, ownership := Status(str(fieldStatus)), Ownership(str(fieldOwnership))

	ipv6Text, ipv6Null, ok := nullableText(m[fieldIPv6])
	if !ok {
		malformed = true
	}
	weight, ok := integer(m[fieldCapacityWeight])
	if !ok {
		malformed = true
	}
	wire, ok := elements(m[fieldEndpoints])
	if !ok {
		malformed = true
	}

	// An unparsable address is the invalid netip.Addr, which the address rules refuse.
	ipv4, _ := netip.ParseAddr(ipv4Text)
	var ipv6 netip.Addr
	if !ipv6Null {
		ipv6, _ = netip.ParseAddr(ipv6Text)
	}

	usable := make([]Endpoint, 0, len(wire))
	for _, w := range wire {
		if e, keep := decodeEndpoint(w); keep {
			usable = append(usable, e)
		}
	}

	refused := classifyRelay(relayFacts{
		fieldMalformed: malformed,
		nodeID:         NodeID(nodeID),
		endpointsEmpty: len(wire) == 0,
		ipv4:           ipv4,
		ipv6Given:      !ipv6Null,
		ipv6:           ipv6,
		wgPublicKey:    wgKey,
		capacityWeight: weight,
		endpoints:      usable,
	})

	// Each field a rule refuses is left with its documented value, through the same rules.
	if !ipv4Plain(ipv4) {
		ipv4 = netip.Addr{}
	}
	if !ipv6Plain(ipv6) {
		ipv6 = netip.Addr{}
	}
	if !wireGuardKey(wgKey) {
		wgKey = ""
	}
	if !capacityWeightInRange(weight) {
		weight = 0
	}

	r := NewRelay(RelayOpts{
		NodeID: NodeID(nodeID), Hostname: hostname, IPv4: ipv4, IPv6: ipv6, WGPublicKey: wgKey,
		Country: country, City: city, CapacityWeight: int(weight), Status: status, Ownership: ownership,
		Provider: provider, Endpoints: firstOfEachEndpoint(usable),
	})
	r.refused = refused

	return r, true, nil
}

// firstOfEachEndpoint keeps the first occurrence of each (kind, port), in order.
func firstOfEachEndpoint(endpoints []Endpoint) []Endpoint {
	seen := make(map[endpointKey]bool, len(endpoints))
	out := make([]Endpoint, 0, len(endpoints))
	for _, e := range endpoints {
		if !seen[e.key()] {
			seen[e.key()] = true
			out = append(out, e)
		}
	}

	return out
}

// decodeEndpoint returns keep=false for an endpoint this client must skip: an unknown kind, whose
// port and params are not read at all because a future kind may define them differently; or, at
// ENDPOINT LEVEL, an endpoint that is not an object, has no kind, or is a known kind whose port is
// missing or not an integer in 1..65535, or whose params is missing or not an object of string
// values. params is opaque and per transport, so a bad one breaks only that transport (contract,
// Strict parsing). Nothing inside one endpoint refuses the list.
func decodeEndpoint(raw json.RawMessage) (Endpoint, bool) {
	m, ok := members(raw)
	if !ok {
		return Endpoint{}, false
	}
	kind, ok := text(m[fieldKind])
	if !ok || !transport.Kind(kind).Valid() {
		return Endpoint{}, false
	}

	// An absent port or params reads as nil, which neither accepts.
	port, ok := portNumber(m[fieldPort])
	if !ok {
		return Endpoint{}, false
	}
	params, ok := stringMap(m[fieldParams])
	if !ok {
		return Endpoint{}, false
	}

	return NewEndpoint(EndpointOpts{Kind: transport.Kind(kind), Port: port, Params: params}), true
}

// portNumber reads a port: an integer in 1..65535. Anything else -- 0, negative, fractional, too
// large, or not a number -- is reported not ok, and the caller skips that endpoint.
func portNumber(raw json.RawMessage) (int, bool) {
	n, ok := integer(raw)
	if !ok || n < 1 || n > 65535 {
		return 0, false
	}

	return int(n), true
}

// stringMap reads params: an object of string values, and nothing else -- not null, and no value
// of another JSON type.
func stringMap(raw json.RawMessage) (map[string]string, bool) {
	pm, ok := members(raw)
	if !ok {
		return nil, false
	}
	params := make(map[string]string, len(pm))
	for k, v := range pm {
		if params[k], ok = text(v); !ok {
			return nil, false
		}
	}

	return params, true
}

// members reads a JSON object as exact-key members. The '{' check refuses null, which
// encoding/json would decode as an empty map.
func members(raw []byte) (map[string]json.RawMessage, bool) {
	raw = trimJSONSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, false
	}
	var m map[string]json.RawMessage

	return m, json.Unmarshal(raw, &m) == nil
}

// elements reads a JSON array, refusing null.
func elements(raw json.RawMessage) ([]json.RawMessage, bool) {
	raw = trimJSONSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return nil, false
	}
	var a []json.RawMessage

	return a, json.Unmarshal(raw, &a) == nil
}

// text reads a JSON string, refusing null, which encoding/json would decode as "".
func text(raw json.RawMessage) (string, bool) {
	raw = trimJSONSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string

	return s, json.Unmarshal(raw, &s) == nil
}

// integer reads a JSON integer, refusing 1.0, 1e0, "1" and null. Callers range-check the int64
// BEFORE converting to int, which is 32 bits on 32-bit Android.
func integer(raw json.RawMessage) (int64, bool) {
	raw = trimJSONSpace(raw)
	if len(raw) == 0 || (raw[0] != '-' && (raw[0] < '0' || raw[0] > '9')) {
		return 0, false
	}
	var n int64

	return n, json.Unmarshal(raw, &n) == nil
}

// instant reads an RFC 3339 timestamp, normalised as NewDocument normalises.
func instant(raw json.RawMessage) (time.Time, bool) {
	s, ok := text(raw)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)

	return t.UTC().Truncate(time.Second), err == nil
}

// nullableText reads "string | null": isNull reports null.
func nullableText(raw json.RawMessage) (value string, isNull, ok bool) {
	if string(trimJSONSpace(raw)) == "null" {
		return "", true, true
	}
	value, ok = text(raw)

	return value, false, ok
}

func present(m map[string]json.RawMessage, names ...string) bool {
	for _, n := range names {
		if _, ok := m[n]; !ok {
			return false
		}
	}

	return true
}
