// SPDX-License-Identifier: AGPL-3.0-only

package relaylist

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/abylora/shared/pkg/transport"
)

// Contract, Strict parsing (ruled 2026-11-01): where a violation is found decides its scope.
// A LIST-LEVEL violation refuses the list, a RELAY-LEVEL one makes that relay unpickable and
// keeps the rest, and an ENDPOINT-LEVEL one skips that endpoint. One bad relay is a producer
// defect, and refusing the list would strand every client on its last-known-good list for it.

// LIST-LEVEL: a document that is not valid UTF-8, or that carries a lone-surrogate escape. Go's
// decoder would silently replace either with U+FFFD, and a client that replaced them would
// disagree with a stricter client.
func TestDecodeRefusesInvalidUTF8AndLoneSurrogates(t *testing.T) {
	cases := map[string]string{
		"an invalid byte":              "Test\xffville",
		"an overlong encoding":         "Test\xc0\xafville",
		"a lone high-surrogate escape": `Test\ud800ville`,
		"a lone low-surrogate escape":  `Test\udc00ville`,
		"a high surrogate then a BMP":  `Test\ud800\u0041ville`,
		"two high surrogates":          `Test\ud800\ud800ville`,
	}

	for name, city := range cases {
		in := replaceOnce(t, goldenDocument, `"city":"Testville","capacity_weight":50`, `"city":"`+city+`","capacity_weight":50`)
		if _, err := Decode([]byte(in)); err != ErrDecodeInvalidText {
			t.Errorf("%s: Decode() error = %v, want ErrDecodeInvalidText", name, err)
		}
	}
}

// A surrogate PAIR escape is valid JSON for one character outside the BMP, and an escaped
// backslash followed by "ud800" is not an escape at all.
func TestDecodeAcceptsASurrogatePairAndAnEscapedBackslash(t *testing.T) {
	for city, want := range map[string]string{
		`Test\ud83d\ude00ville`: "Test\U0001F600ville",
		`Test\\ud800ville`:      `Test\ud800ville`,
	} {
		in := replaceOnce(t, goldenDocument, `"city":"Testville","capacity_weight":50`, `"city":"`+city+`","capacity_weight":50`)
		if got := mustDecode(t, in).Relays()[0].City(); got != want {
			t.Errorf("City() = %q, want %q", got, want)
		}
	}
}

// twoPickableRelays is a document whose two relays are both pickable, so a relay-level violation
// planted in the first can be seen to leave the second pickable. Every fragment the tests below
// replace occurs in it exactly once.
func twoPickableRelays(t *testing.T) string {
	t.Helper()
	second := firstRelayOpts()
	second.NodeID = secondNodeID
	second.IPv4 = netip.MustParseAddr("192.0.2.20")
	second.IPv6 = netip.MustParseAddr("2001:db8::20")
	second.WGPublicKey = testKey(0x02)
	second.CapacityWeight = 60
	second.Endpoints = []Endpoint{NewEndpoint(EndpointOpts{Kind: transport.KindQUIC, Port: 443})}

	opts := testDocumentOpts()
	opts.Relays = []Relay{NewRelay(firstRelayOpts()), NewRelay(second)}

	return mustEncode(t, NewDocument(opts))
}

// requireOnlyTheFirstRelayUnpickable decodes in and requires: the list valid, both relays kept,
// the first unpickable and the second still pickable.
func requireOnlyTheFirstRelayUnpickable(t *testing.T, in string) Relay {
	t.Helper()
	d := mustDecode(t, in)
	relays := d.Relays()
	if len(relays) != 2 {
		t.Fatalf("decoded %d relays, want both kept", len(relays))
	}
	if relays[0].Pickable() {
		t.Error("the relay with the violation is pickable")
	}
	if !relays[1].Pickable() {
		t.Error("the sibling relay is not pickable")
	}

	return relays[0]
}

// RELAY-LEVEL: each row decodes, makes that relay unpickable, and leaves its sibling pickable.
// The getter of the offending field returns the value documented on it, and none panics.
func TestARelayLevelViolationMakesOnlyThatRelayUnpickable(t *testing.T) {
	const firstKey = `"wg_public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="`
	cases := []struct {
		name     string
		old, new string
		check    func(Relay) bool
	}{
		{"ipv4 is an IPv6 address", `"ipv4":"192.0.2.10"`, `"ipv4":"2001:db8::10"`, func(r Relay) bool { return !r.IPv4().IsValid() }},
		{"ipv4 is IPv4-mapped IPv6", `"ipv4":"192.0.2.10"`, `"ipv4":"::ffff:192.0.2.10"`, func(r Relay) bool { return !r.IPv4().IsValid() }},
		{"ipv4 is not an address", `"ipv4":"192.0.2.10"`, `"ipv4":"relay-1"`, func(r Relay) bool { return !r.IPv4().IsValid() }},
		{"ipv6 is an IPv4 address", `"ipv6":"2001:db8::10"`, `"ipv6":"192.0.2.10"`, func(r Relay) bool { return !r.IPv6().IsValid() }},
		{"ipv6 is IPv4-mapped", `"ipv6":"2001:db8::10"`, `"ipv6":"::ffff:192.0.2.10"`, func(r Relay) bool { return !r.IPv6().IsValid() }},
		{"ipv6 has a zone", `"ipv6":"2001:db8::10"`, `"ipv6":"fe80::1%eth0"`, func(r Relay) bool { return !r.IPv6().IsValid() }},
		{"ipv6 is not an address", `"ipv6":"2001:db8::10"`, `"ipv6":"relay-1"`, func(r Relay) bool { return !r.IPv6().IsValid() }},
		{"wg_public_key is empty", firstKey, `"wg_public_key":""`, func(r Relay) bool { return r.WGPublicKey() == "" }},
		{"wg_public_key is 31 bytes", firstKey, `"wg_public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=="`, func(r Relay) bool { return r.WGPublicKey() == "" }},
		{"wg_public_key is URL-safe base64", firstKey, `"wg_public_key":"-_8BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="`, func(r Relay) bool { return r.WGPublicKey() == "" }},
		{"wg_public_key is unpadded", firstKey, `"wg_public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"`, func(r Relay) bool { return r.WGPublicKey() == "" }},
		{"capacity_weight 101", `"capacity_weight":50`, `"capacity_weight":101`, func(r Relay) bool { return r.CapacityWeight() == 0 }},
		{"capacity_weight -1", `"capacity_weight":50`, `"capacity_weight":-1`, func(r Relay) bool { return r.CapacityWeight() == 0 }},
		{"capacity_weight beyond 32 bits", `"capacity_weight":50`, `"capacity_weight":4294967346`, func(r Relay) bool { return r.CapacityWeight() == 0 }},
		{"a duplicate kind and port", firstEndpoints, firstEndpoints + `{"kind":"plain","port":51820,"params":{"x":"y"}},`, func(r Relay) bool { return len(r.Endpoints()) == 2 }},
		{"endpoints is empty on the wire", `"endpoints":[{"kind":"plain","port":51820,"params":{}},{"kind":"shadowsocks","port":8443,"params":{"a":"first","z":"last"}}]`,
			`"endpoints":[]`, func(r Relay) bool { return len(r.Endpoints()) == 0 }},
		{"node_id is empty", `"node_id":"3f0c6a51-0000-4000-8000-000000000001"`, `"node_id":""`, func(r Relay) bool { return r.NodeID() == "" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := requireOnlyTheFirstRelayUnpickable(t, replaceOnce(t, twoPickableRelays(t), tc.old, tc.new))
			if !tc.check(r) {
				t.Error("the offending field does not hold its documented value")
			}
			// No getter may panic on a relay refused at decode.
			_ = []any{r.NodeID(), r.Hostname(), r.IPv4().String(), r.IPv6().String(), r.WGPublicKey(), r.Country(),
				r.City(), r.CapacityWeight(), r.Status(), r.Ownership(), r.Provider(), r.Endpoints(), r.Pickable()}
		})
	}
}

// ENDPOINT-LEVEL: a known-kind endpoint whose port is not an integer in 1..65535, or whose params
// is not an object of string values, is skipped, as an unknown kind is. Its siblings are kept,
// and the relay stays pickable on them.
func TestAnEndpointLevelViolationSkipsOnlyThatEndpoint(t *testing.T) {
	const bad = `{"kind":"udp2tcp","port":PORT,"params":PARAMS},`
	cases := map[string][2]string{
		"port 0":                   {"0", "{}"},
		"port negative":            {"-1", "{}"},
		"port fractional":          {"443.5", "{}"},
		"port too large":           {"65536", "{}"},
		"port beyond 64 bits":      {"18446744073709551616", "{}"},
		"port a string":            {`"443"`, "{}"},
		"params null":              {"443", "null"},
		"params an array":          {"443", `["a"]`},
		"params with a number":     {"443", `{"a":1}`},
		"params with a nested obj": {"443", `{"a":{"b":"c"}}`},
		"params with a null value": {"443", `{"a":null}`},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			endpoint := replaceOnce(t, replaceOnce(t, bad, "PORT", c[0]), "PARAMS", c[1])
			d := mustDecode(t, replaceOnce(t, goldenDocument, firstEndpoints, firstEndpoints+endpoint))

			r := d.Relays()[0]
			for _, e := range r.Endpoints() {
				if e.Kind() == transport.KindUDP2TCP {
					t.Error("the bad endpoint was kept")
				}
			}
			if len(r.Endpoints()) != 2 || !r.Pickable() {
				t.Error("want the two good endpoints kept and the relay pickable")
			}
			if got := mustEncode(t, d); got != goldenDocument {
				t.Errorf("after skipping, Encode() =\n%s\nwant the golden document", got)
			}
		})
	}
}

// ENDPOINT-LEVEL, for a fetch endpoint: an api_endpoints entry whose host fails the host rule,
// whose port is not an integer in 1..65535, or that is left with no known transport is skipped.
// APIEndpoints() returns only usable entries.
func TestAFetchEndpointLevelViolationSkipsOnlyThatFetchEndpoint(t *testing.T) {
	cases := map[string]string{
		"a host with a port":        `{"host":"192.0.2.1:443","port":443,"transports":["https"]}`,
		"a host that is a URL":      `{"host":"https://api.example/","port":443,"transports":["https"]}`,
		"an empty host":             `{"host":"","port":443,"transports":["https"]}`,
		"port 0":                    `{"host":"192.0.2.1","port":0,"transports":["https"]}`,
		"port negative":             `{"host":"192.0.2.1","port":-443,"transports":["https"]}`,
		"port fractional":           `{"host":"192.0.2.1","port":443.5,"transports":["https"]}`,
		"port too large":            `{"host":"192.0.2.1","port":4294967739,"transports":["https"]}`,
		"only unknown transports":   `{"host":"192.0.2.1","port":443,"transports":["future-fetch"]}`,
		"an empty transports array": `{"host":"192.0.2.1","port":443,"transports":[]}`,
	}

	for name, entry := range cases {
		t.Run(name, func(t *testing.T) {
			d := mustDecode(t, replaceOnce(t, goldenDocument, `"api_endpoints":[`, `"api_endpoints":[`+entry+`,`))
			if got := mustEncode(t, d); got != goldenDocument {
				t.Errorf("after skipping, Encode() =\n%s\nwant the golden document", got)
			}
		})
	}
}

// The host rule is APIEndpoint's, unchanged: a bare hostname is a valid fetch host.
func TestABareHostnameIsAValidFetchHost(t *testing.T) {
	d := mustDecode(t, replaceOnce(t, goldenDocument, `"host":"192.0.2.1"`, `"host":"api.staging.example"`))
	if got := d.APIEndpoints(); len(got) != 2 || got[0].Host() != "api.staging.example" {
		t.Errorf("APIEndpoints() = %v, want the bare hostname kept", got)
	}
}

// Contract, Strict parsing: a list whose fetch endpoints are all skipped stays valid, with none
// usable. What a client then does is the client's.
func TestAListWithNoUsableFetchEndpointStaysValid(t *testing.T) {
	g := replaceOnce(t, goldenDocument, `"host":"192.0.2.1","port":443`, `"host":"192.0.2.1","port":0`)
	g = replaceOnce(t, g, `"host":"2001:db8::1","port":443`, `"host":"2001:db8::1","port":0`)
	if d := mustDecode(t, g); len(d.APIEndpoints()) != 0 || len(d.Relays()) != 2 {
		t.Errorf("want a valid list with no usable fetch endpoint and both relays")
	}
}

// An empty node_id cannot be matched to a readiness row: relay level. Two of them are not a
// "repeated node_id" -- the reason recorded on each is the empty node_id -- and both are
// unpickable either way.
func TestTwoEmptyNodeIDsAreEachRefusedAsEmpty(t *testing.T) {
	third := firstRelayOpts()
	third.NodeID = "3f0c6a51-0000-4000-8000-000000000003"
	third.IPv4 = netip.MustParseAddr("192.0.2.30")
	third.IPv6 = netip.MustParseAddr("2001:db8::30")
	third.WGPublicKey = testKey(0x03)
	third.Endpoints = []Endpoint{NewEndpoint(EndpointOpts{Kind: transport.KindQUIC, Port: 4433})}
	d := mustDecode(t, twoPickableRelays(t))
	opts := testDocumentOpts()
	opts.Relays = append(d.Relays(), NewRelay(third))

	in := replaceOnce(t, mustEncode(t, NewDocument(opts)), `"node_id":"3f0c6a51-0000-4000-8000-000000000001"`, `"node_id":""`)
	in = replaceOnce(t, in, `"node_id":"3f0c6a51-0000-4000-8000-000000000002"`, `"node_id":""`)

	relays := mustDecode(t, in).Relays()
	if len(relays) != 3 {
		t.Fatalf("decoded %d relays, want 3", len(relays))
	}
	for i, r := range relays[:2] {
		if r.Pickable() || r.refused != relayRefusedNodeIDEmpty {
			t.Errorf("relay %d: Pickable() = %v, refused = %d; want false, relayRefusedNodeIDEmpty", i, r.Pickable(), r.refused)
		}
	}
	if !relays[2].Pickable() {
		t.Error("the relay with its own node_id is not pickable")
	}
}

// ENDPOINT LEVEL, the shapes: an endpoint that is not an object, has no kind, or is a known kind
// lacking port or params is skipped, its siblings kept and the relay still pickable.
func TestAMalformedEndpointIsSkipped(t *testing.T) {
	cases := map[string]string{
		"a string":                `"plain",`,
		"a number":                `1,`,
		"null":                    `null,`,
		"an array":                `[{"kind":"plain"}],`,
		"no kind":                 `{"port":443,"params":{}},`,
		"a kind not a string":     `{"kind":1,"port":443,"params":{}},`,
		"a known kind, no port":   `{"kind":"udp2tcp","params":{}},`,
		"a known kind, no params": `{"kind":"udp2tcp","port":443},`,
	}

	for name, endpoint := range cases {
		t.Run(name, func(t *testing.T) {
			d := mustDecode(t, replaceOnce(t, goldenDocument, firstEndpoints, firstEndpoints+endpoint))
			if r := d.Relays()[0]; len(r.Endpoints()) != 2 || !r.Pickable() {
				t.Error("want the two good endpoints kept and the relay pickable")
			}
			if got := mustEncode(t, d); got != goldenDocument {
				t.Errorf("after skipping, Encode() =\n%s\nwant the golden document", got)
			}
		})
	}
}

// A transport repeated within one api_endpoints entry is harmless and is deduplicated silently.
func TestARepeatedFetchTransportIsDeduplicated(t *testing.T) {
	d := mustDecode(t, replaceOnce(t, goldenDocument, firstTransports, `"host":"192.0.2.1","port":443,"transports":["https","future-fetch","https"]`))
	if got := mustEncode(t, d); got != goldenDocument {
		t.Errorf("after deduplicating, Encode() =\n%s\nwant the golden document", got)
	}
}

// A relays element that is not an object is skipped, and the list stays valid while one object
// relay remains -- even an unpickable one.
func TestARelaysElementThatIsNotAnObjectIsSkipped(t *testing.T) {
	d := mustDecode(t, replaceOnce(t, goldenDocument, `"relays":[`, `"relays":["x",1,null,[],`))
	if got := mustEncode(t, d); got != goldenDocument {
		t.Errorf("after skipping, Encode() =\n%s\nwant the golden document", got)
	}
}

// Contract, Rules (ruled 2026-11-01): a client refuses a list that leaves NO PICKABLE relay once
// non-object entries are skipped and unpickable relays set aside, and keeps its last-known-good
// list -- adopting it would strand the client exactly as an empty list would. The golden
// document's second relay is draining with weight 0, so each row makes the first unpickable too.
func TestAListThatLeavesNoPickableRelayIsRefused(t *testing.T) {
	g := goldenDocument
	cases := map[string]string{
		"every element a non-object": g[:strings.Index(g, `"relays":[`)] + `"relays":["x",1,null]}`,
		"every relay draining":       replaceOnce(t, g, `"status":"active"`, `"status":"draining"`),
		"every relay weight 0":       replaceOnce(t, g, `"capacity_weight":50`, `"capacity_weight":0`),
		"every relay of unknown status": replaceOnce(t, replaceOnce(t, g, `"status":"active"`, `"status":"future-status"`),
			`"status":"draining"`, `"status":"future-status"`),
		"every relay refused at relay level": replaceOnce(t, replaceOnce(t, g, `"ipv4":"192.0.2.10"`, `"ipv4":"2001:db8::10"`),
			`"ipv4":"192.0.2.20"`, `"ipv4":"2001:db8::20"`),
	}

	for name, in := range cases {
		if _, err := Decode([]byte(in)); err != ErrNoPickableRelay {
			t.Errorf("%s: Decode() error = %v, want ErrNoPickableRelay", name, err)
		}
	}
}

// One pickable relay among many unpickable ones is enough: the list is valid.
func TestOnePickableRelayAmongUnpickableOnesIsEnough(t *testing.T) {
	in := replaceOnce(t, goldenDocument, `"relays":[`, `"relays":["x",null,`)
	d := mustDecode(t, in)
	if relays := d.Relays(); len(relays) != 2 || !relays[0].Pickable() || relays[1].Pickable() {
		t.Error("want both object relays kept, the first pickable and the second not")
	}
}

// Contract, Strict parsing (ruled): missing fields and wrong JSON types follow the same scope. A
// field missing, or of the wrong JSON type, inside one relay is RELAY LEVEL: the relay is kept,
// unpickable, and its sibling stays pickable. Only a top-level field refuses the list.
func TestAWrongTypeOrMissingFieldInARelayIsRelayLevel(t *testing.T) {
	const firstEndpointsArray = `"endpoints":[{"kind":"plain","port":51820,"params":{}},{"kind":"shadowsocks","port":8443,"params":{"a":"first","z":"last"}}]`
	cases := map[string][2]string{
		"ipv4 null":                {`"ipv4":"192.0.2.10"`, `"ipv4":null`},
		"ipv4 a number":            {`"ipv4":"192.0.2.10"`, `"ipv4":5`},
		"ipv6 a number":            {`"ipv6":"2001:db8::10"`, `"ipv6":5`},
		"status null":              {`"capacity_weight":50,"status":"active"`, `"capacity_weight":50,"status":null`},
		"status a number":          {`"capacity_weight":50,"status":"active"`, `"capacity_weight":50,"status":1`},
		"node_id null":             {`"node_id":"3f0c6a51-0000-4000-8000-000000000001"`, `"node_id":null`},
		"hostname a number":        {`"node_id":"3f0c6a51-0000-4000-8000-000000000001","hostname":"relay-1.test.example"`, `"node_id":"3f0c6a51-0000-4000-8000-000000000001","hostname":7`},
		"capacity_weight a string": {`"capacity_weight":50`, `"capacity_weight":"50"`},
		"capacity_weight 50.0":     {`"capacity_weight":50`, `"capacity_weight":50.0`},
		"capacity_weight 1e400":    {`"capacity_weight":50`, `"capacity_weight":1e400`},
		"endpoints null":           {firstEndpointsArray, `"endpoints":null`},
		"endpoints an object":      {firstEndpointsArray, `"endpoints":{}`},
		"city missing":             {`"city":"Testville","capacity_weight":50`, `"capacity_weight":50`},
		"ownership null":           {`"capacity_weight":50,"status":"active","ownership":"owned"`, `"capacity_weight":50,"status":"active","ownership":null`},
		"wg_public_key missing":    {`"wg_public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",`, ``},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			requireOnlyTheFirstRelayUnpickable(t, replaceOnce(t, twoPickableRelays(t), c[0], c[1]))
		})
	}
}

// Inside one api_endpoints entry, a field missing or of the wrong JSON type is ENDPOINT LEVEL:
// that fetch endpoint is skipped. An api_endpoints element that is not an object is skipped too.
func TestAWrongTypeOrMissingFieldInAFetchEndpointSkipsIt(t *testing.T) {
	cases := map[string]string{
		"host null":          `{"host":null,"port":443,"transports":["https"]}`,
		"host a number":      `{"host":7,"port":443,"transports":["https"]}`,
		"host missing":       `{"port":443,"transports":["https"]}`,
		"port missing":       `{"host":"192.0.2.1","transports":["https"]}`,
		"transports null":    `{"host":"192.0.2.1","port":443,"transports":null}`,
		"transports missing": `{"host":"192.0.2.1","port":443}`,
		"a string element":   `"https://192.0.2.1/"`,
		"a null element":     `null`,
	}

	for name, entry := range cases {
		t.Run(name, func(t *testing.T) {
			d := mustDecode(t, replaceOnce(t, goldenDocument, `"api_endpoints":[`, `"api_endpoints":[`+entry+`,`))
			if got := mustEncode(t, d); got != goldenDocument {
				t.Errorf("after skipping, Encode() =\n%s\nwant the golden document", got)
			}
		})
	}
}

// A transports element that is not a string is skipped like an unknown transport.
func TestAFetchTransportThatIsNotAStringIsSkipped(t *testing.T) {
	d := mustDecode(t, replaceOnce(t, goldenDocument, firstTransports, `"host":"192.0.2.1","port":443,"transports":[1,null,"https",{}]`))
	if got := mustEncode(t, d); got != goldenDocument {
		t.Errorf("after skipping, Encode() =\n%s\nwant the golden document", got)
	}
}

// Contract, Strict parsing (ruled): a skipped endpoint is not an endpoint. It does not count
// towards a duplicate (kind, port), and it does not make a relay pickable.
func TestASkippedEndpointIsNotAnEndpoint(t *testing.T) {
	t.Run("it is not a duplicate", func(t *testing.T) {
		in := replaceOnce(t, goldenDocument, firstEndpoints, firstEndpoints+`{"kind":"plain","port":51820,"params":{"x":1}},`)
		r := mustDecode(t, in).Relays()[0]
		if !r.Pickable() || r.refused != relayKept || len(r.Endpoints()) != 2 {
			t.Error("a skipped endpoint counted as a duplicate (kind, port)")
		}
	})
	t.Run("it does not make a relay pickable", func(t *testing.T) {
		in := replaceOnce(t, twoPickableRelays(t),
			`"endpoints":[{"kind":"plain","port":51820,"params":{}},{"kind":"shadowsocks","port":8443,"params":{"a":"first","z":"last"}}]`,
			`"endpoints":[{"kind":"plain","port":0,"params":{}},{"kind":"plain","port":51820,"params":{"x":1}}]`)
		requireOnlyTheFirstRelayUnpickable(t, in)
	})
	t.Run("the ruled case: one plain/51820 kept, the bad repeat skipped", func(t *testing.T) {
		in := replaceOnce(t, twoPickableRelays(t),
			`"endpoints":[{"kind":"plain","port":51820,"params":{}},{"kind":"shadowsocks","port":8443,"params":{"a":"first","z":"last"}}]`,
			`"endpoints":[{"kind":"plain","port":51820,"params":{}},{"kind":"plain","port":51820,"params":{"x":1}}]`)
		r := mustDecode(t, in).Relays()[0]
		if !r.Pickable() || len(r.Endpoints()) != 1 {
			t.Errorf("Pickable() = %v with %d endpoints, want pickable with 1", r.Pickable(), len(r.Endpoints()))
		}
	})
}
