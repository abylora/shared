package relaylist

import "errors"

// Every sentinel here is a constant string, and every carrier type holds a NodeID and nothing
// else. No error from this package may carry a hostname, an address, a provider or any other
// field of a document (D19): an error value is the easiest thing in the world to log, and the
// export path's rule is that an error says which version failed and why, never what was in
// it. The package cannot import fmt, which keeps that structural.
var (
	// The API endpoint refusals, one per operator mistake, so a caller can say which.
	// Decode returns none of them: a fetch endpoint with a bad host or port, or with no known
	// transport, is skipped at endpoint level, and a repeated transport is deduplicated
	// (contract, Strict parsing).
	ErrAPIEndpointHostAbsent        = errors.New("relaylist: api endpoint has no host")
	ErrAPIEndpointHostMalformed     = errors.New("relaylist: api endpoint host is not a bare hostname or IP address")
	ErrAPIEndpointPortOutOfRange    = errors.New("relaylist: api endpoint port is outside 1..65535")
	ErrAPIEndpointTransportsAbsent  = errors.New("relaylist: api endpoint has no fetch transport")
	ErrAPIEndpointTransportUnknown  = errors.New("relaylist: api endpoint names an unknown fetch transport")
	ErrAPIEndpointTransportRepeated = errors.New("relaylist: api endpoint names a fetch transport twice")

	// ErrVersionNotPositive: the producer's version sequence starts at 1, so a version below
	// it was never drawn.
	ErrVersionNotPositive = errors.New("relaylist: version is not positive")

	// ErrExpiryNotAfterGeneration: a list born expired raises refresh urgency at every client
	// on every fetch.
	ErrExpiryNotAfterGeneration = errors.New("relaylist: expires_at is not after generated_at")

	// ErrNoAPIEndpoints: a list with no fetch address removes self-healing (D18 item 3).
	ErrNoAPIEndpoints = errors.New("relaylist: no api endpoint")

	// ErrNoRelays: "the producer refuses to generate a list with no relays" (contract,
	// Rules). The producer's projection may refuse first; this is the encoder's own refusal
	// of the same unservable artifact.
	ErrNoRelays = errors.New("relaylist: no relay")

	// ErrRelayIncomplete: a relay with no node_id, no WireGuard public key, no IPv4 address
	// or no endpoint is one every client would fail to reach or refer to. Decode never returns
	// it: each of those is a relay-level violation there, and the relay is not pickable. This is
	// what stops the encoder ever
	// writing "wg_public_key":"" whatever the caller let through. Encode carries it in a
	// *RelayIncompleteError.
	ErrRelayIncomplete = errors.New("relaylist: relay is incomplete")

	// ErrEndpointKindUnknown: a relay endpoint whose kind is not one of transport.Kinds().
	// No client has a dialer for it. Always carried by an *EndpointKindUnknownError. Decode
	// never returns it: an endpoint of unknown kind is skipped there.
	ErrEndpointKindUnknown = errors.New("relaylist: relay has an endpoint of unknown kind")

	// ErrEndpointPortOutOfRange: a relay endpoint port outside 1..65535, which the
	// contract's uint16 cannot carry and no client can dial. Encode carries it in an
	// *EndpointPortOutOfRangeError.
	// Decode never returns it: in a decoded list that is an endpoint-level violation: the endpoint is skipped
	// (contract, Strict parsing).
	ErrEndpointPortOutOfRange = errors.New("relaylist: relay has an endpoint port outside 1..65535")

	// ErrEndpointRepeated: a relay declaring the same (kind, port) twice. Different kinds
	// sharing a port are accepted and published as declared (contract, Rules, ruled
	// 2026-10-09 for ABY-38); only an exact repeat is refused. Encode carries it in an
	// *EndpointRepeatedError.
	// Decode never returns it: in a decoded list that is a relay-level violation: the relay is not pickable
	// (contract, Strict parsing).
	ErrEndpointRepeated = errors.New("relaylist: relay repeats an endpoint kind and port")

	// ErrStatusUnknown: a relay whose status is neither active nor draining. THIS IS
	// LOAD-BEARING: the producer converts its own node status into a Status without a switch,
	// so this refusal is what keeps a staged or retired node off the wire. Always carried by
	// a *StatusUnknownError. Decode never returns it: an unknown status is kept, not pickable.
	ErrStatusUnknown = errors.New("relaylist: relay status is neither active nor draining")

	// ErrOwnershipUnknown: a relay whose ownership is neither owned nor rented. Always
	// carried by an *OwnershipUnknownError. Decode never returns it: no client acts on
	// ownership, so an unknown value is kept verbatim (contract, Strict parsing).
	ErrOwnershipUnknown = errors.New("relaylist: relay ownership is neither owned nor rented")

	// ErrCapacityWeightOutOfRange: a relay capacity_weight outside 0..100 (contract, Shape).
	// Above 100 skews every client's selection toward that node fleet-wide; 0 is legitimate
	// and means "do not pick". Encode carries it in a *CapacityWeightOutOfRangeError.
	// Decode never returns it: in a decoded list that is a relay-level violation: the relay is not pickable
	// (contract, Strict parsing).
	ErrCapacityWeightOutOfRange = errors.New("relaylist: relay capacity_weight is outside 0..100")

	// ErrRelayIPv4Invalid: a relay whose ipv4 is a valid address but not a plain IPv4 one (Is4)
	// -- an IPv6 or an IPv4-mapped IPv6 address. A zero ipv4 stays ErrRelayIncomplete. Decode
	// never returns it: there it is a relay-level violation, and the relay is not pickable.
	// Always carried by a *RelayIPv4InvalidError.
	ErrRelayIPv4Invalid = errors.New("relaylist: relay ipv4 is not a plain IPv4 address")

	// ErrRelayIPv6Invalid: a relay whose ipv6 is present but not a plain IPv6 address -- not Is6,
	// IPv4-mapped, or zoned. Decode never returns it: there it is a relay-level violation.
	// Always carried by a *RelayIPv6InvalidError.
	ErrRelayIPv6Invalid = errors.New("relaylist: relay ipv6 is not a plain IPv6 address")

	// ErrRelayWGPublicKeyInvalid: a relay whose wg_public_key is present but not standard padded
	// base64 of exactly 32 bytes in its one canonical spelling. An empty key stays
	// ErrRelayIncomplete. Decode never returns it: there it is a relay-level violation. Always
	// carried by a *RelayWGPublicKeyInvalidError.
	ErrRelayWGPublicKeyInvalid = errors.New("relaylist: relay wg_public_key is not base64 of 32 bytes")

	// ErrRelayRepeated: a node_id carried by more than one relay, which makes readiness
	// ambiguous (contract, Strict parsing). Checked at document level, after every relay's own
	// checks. Decode never returns it: a client makes every relay carrying it unpickable and
	// keeps the rest. Always carried by a *RelayRepeatedError naming the first repeat in relay
	// order.
	ErrRelayRepeated = errors.New("relaylist: relay node_id appears on more than one relay")

	// ErrTextNotUTF8: a string the document carries -- an API host, a relay field, a param key or
	// value -- is not valid UTF-8. encoding/json would write it as U+FFFD, so the artifact would
	// not say what the producer was given, and a client reading it back would re-encode different
	// octets. Document-level and bare: the offending string may be the node_id itself. Found by
	// FuzzEncodeDecodeRoundTrip.
	ErrTextNotUTF8 = errors.New("relaylist: a string is not valid UTF-8")

	// ErrEncodeFailed wraps a json.Marshal failure, which these types cannot produce.
	ErrEncodeFailed = errors.New("relaylist: failed to encode the document")

	// The decode refusals. Decode returns every sentinel BARE, these and the value refusals
	// above alike: the node_id a carrier would name is unverified input there.

	// ErrDecodeMalformed: the octets are not one JSON object, or a second value follows it, or
	// a TOP-LEVEL field has the wrong JSON type. Inside a relay a wrong type is relay-level, and
	// inside an endpoint or api_endpoints entry endpoint-level (contract, Strict parsing).
	ErrDecodeMalformed = errors.New("relaylist: not a relay list document")

	// ErrDecodeDuplicateKey: a key repeated in any object, at any depth. encoding/json keeps the
	// last occurrence and other languages differ, so a duplicate is a parser differential
	// (contract, Strict parsing). Still refused under the list's lenient rule.
	ErrDecodeDuplicateKey = errors.New("relaylist: duplicate key")

	// ErrDecodeTypeUnknown: _type is absent or is not DocumentType. A signing certificate given
	// to Decode lands here, which is the point of each document carrying its own _type.
	ErrDecodeTypeUnknown = errors.New("relaylist: _type is not " + DocumentType)

	// ErrDecodeInvalidText: the document is not valid UTF-8, or carries a lone-surrogate escape.
	// A list-level violation (contract, Strict parsing): encoding/json would silently replace
	// either with U+FFFD, and a client that replaced them would disagree with a stricter client.
	ErrDecodeInvalidText = errors.New("relaylist: not valid UTF-8, or a lone surrogate escape")

	// ErrNoPickableRelay: no relay of the document is Pickable -- once Decode has skipped
	// non-object elements and set unpickable relays aside, or as Encode is given it (contract,
	// Rules, ruled 2026-11-01). Encode refuses to write such a list, and Decode refuses one it
	// receives, so the client keeps its last-known-good list: adopting it would strand the client
	// exactly as an empty list would. Both use Relay.Pickable. Document-level, so it is bare, with
	// no NodeID carrier. Distinct from ErrNoRelays, which refuses relays: [] as written: this list
	// is well formed, and each relay in it may be one the producer meant to publish.
	ErrNoPickableRelay = errors.New("relaylist: no relay is pickable")

	// ErrDecodeFieldMissing: a TOP-LEVEL field of the contract's Shape is absent. Inside a relay
	// a missing field is relay-level, and inside an endpoint or api_endpoints entry
	// endpoint-level (contract, Strict parsing).
	ErrDecodeFieldMissing = errors.New("relaylist: missing field")
)

// RelayIncompleteError names the node whose relay cannot be published.
//
// IT HOLDS A NodeID AND NOTHING ELSE. D19 permits a node_id -- an opaque identifier already
// published in the list -- and forbids the hostname, addresses and provider that sit beside it
// in the Relay.
type RelayIncompleteError struct {
	nodeID NodeID
}

func (e *RelayIncompleteError) Error() string {
	return ErrRelayIncomplete.Error() + ": node " + string(e.nodeID)
}

func (e *RelayIncompleteError) Unwrap() error { return ErrRelayIncomplete }

// NodeID returns the node whose relay is incomplete.
func (e *RelayIncompleteError) NodeID() NodeID { return e.nodeID }

// The carriers below are RelayIncompleteError's siblings, one per refusal, and each holds a
// NodeID and nothing else -- not the offending kind, port, status or ownership -- for the
// same reason.

// EndpointKindUnknownError names the node whose relay has an endpoint of unknown kind.
type EndpointKindUnknownError struct {
	nodeID NodeID
}

func (e *EndpointKindUnknownError) Error() string {
	return ErrEndpointKindUnknown.Error() + ": node " + string(e.nodeID)
}

func (e *EndpointKindUnknownError) Unwrap() error { return ErrEndpointKindUnknown }

// NodeID returns the node whose relay has an endpoint of unknown kind.
func (e *EndpointKindUnknownError) NodeID() NodeID { return e.nodeID }

// EndpointPortOutOfRangeError names the node whose relay has an endpoint port out of range.
type EndpointPortOutOfRangeError struct {
	nodeID NodeID
}

func (e *EndpointPortOutOfRangeError) Error() string {
	return ErrEndpointPortOutOfRange.Error() + ": node " + string(e.nodeID)
}

func (e *EndpointPortOutOfRangeError) Unwrap() error { return ErrEndpointPortOutOfRange }

// NodeID returns the node whose relay has an endpoint port out of range.
func (e *EndpointPortOutOfRangeError) NodeID() NodeID { return e.nodeID }

// EndpointRepeatedError names the node whose relay repeats an endpoint kind and port.
type EndpointRepeatedError struct {
	nodeID NodeID
}

func (e *EndpointRepeatedError) Error() string {
	return ErrEndpointRepeated.Error() + ": node " + string(e.nodeID)
}

func (e *EndpointRepeatedError) Unwrap() error { return ErrEndpointRepeated }

// NodeID returns the node whose relay repeats an endpoint kind and port.
func (e *EndpointRepeatedError) NodeID() NodeID { return e.nodeID }

// StatusUnknownError names the node whose relay has an unknown status.
type StatusUnknownError struct {
	nodeID NodeID
}

func (e *StatusUnknownError) Error() string {
	return ErrStatusUnknown.Error() + ": node " + string(e.nodeID)
}

func (e *StatusUnknownError) Unwrap() error { return ErrStatusUnknown }

// NodeID returns the node whose relay has an unknown status.
func (e *StatusUnknownError) NodeID() NodeID { return e.nodeID }

// OwnershipUnknownError names the node whose relay has an unknown ownership.
type OwnershipUnknownError struct {
	nodeID NodeID
}

func (e *OwnershipUnknownError) Error() string {
	return ErrOwnershipUnknown.Error() + ": node " + string(e.nodeID)
}

func (e *OwnershipUnknownError) Unwrap() error { return ErrOwnershipUnknown }

// NodeID returns the node whose relay has an unknown ownership.
func (e *OwnershipUnknownError) NodeID() NodeID { return e.nodeID }

// CapacityWeightOutOfRangeError names the node whose relay has a capacity_weight out of range.
type CapacityWeightOutOfRangeError struct {
	nodeID NodeID
}

func (e *CapacityWeightOutOfRangeError) Error() string {
	return ErrCapacityWeightOutOfRange.Error() + ": node " + string(e.nodeID)
}

func (e *CapacityWeightOutOfRangeError) Unwrap() error { return ErrCapacityWeightOutOfRange }

// NodeID returns the node whose relay has a capacity_weight out of range.
func (e *CapacityWeightOutOfRangeError) NodeID() NodeID { return e.nodeID }

// RelayIPv4InvalidError names the node whose relay has an ipv4 that is not plain IPv4.
type RelayIPv4InvalidError struct {
	nodeID NodeID
}

func (e *RelayIPv4InvalidError) Error() string {
	return ErrRelayIPv4Invalid.Error() + ": node " + string(e.nodeID)
}

func (e *RelayIPv4InvalidError) Unwrap() error { return ErrRelayIPv4Invalid }

// NodeID returns the node whose relay has an ipv4 that is not plain IPv4.
func (e *RelayIPv4InvalidError) NodeID() NodeID { return e.nodeID }

// RelayIPv6InvalidError names the node whose relay has an ipv6 that is not plain IPv6.
type RelayIPv6InvalidError struct {
	nodeID NodeID
}

func (e *RelayIPv6InvalidError) Error() string {
	return ErrRelayIPv6Invalid.Error() + ": node " + string(e.nodeID)
}

func (e *RelayIPv6InvalidError) Unwrap() error { return ErrRelayIPv6Invalid }

// NodeID returns the node whose relay has an ipv6 that is not plain IPv6.
func (e *RelayIPv6InvalidError) NodeID() NodeID { return e.nodeID }

// RelayWGPublicKeyInvalidError names the node whose relay has a malformed wg_public_key.
type RelayWGPublicKeyInvalidError struct {
	nodeID NodeID
}

func (e *RelayWGPublicKeyInvalidError) Error() string {
	return ErrRelayWGPublicKeyInvalid.Error() + ": node " + string(e.nodeID)
}

func (e *RelayWGPublicKeyInvalidError) Unwrap() error { return ErrRelayWGPublicKeyInvalid }

// NodeID returns the node whose relay has a malformed wg_public_key.
func (e *RelayWGPublicKeyInvalidError) NodeID() NodeID { return e.nodeID }

// RelayRepeatedError names the first repeated node_id in relay order: the node_id of the first
// relay that an earlier relay already carries.
type RelayRepeatedError struct {
	nodeID NodeID
}

func (e *RelayRepeatedError) Error() string {
	return ErrRelayRepeated.Error() + ": node " + string(e.nodeID)
}

func (e *RelayRepeatedError) Unwrap() error { return ErrRelayRepeated }

// NodeID returns the first repeated node_id.
func (e *RelayRepeatedError) NodeID() NodeID { return e.nodeID }

// redacted is what every type in this package renders as through slog.LogValuer.
const redacted = "REDACTED"
