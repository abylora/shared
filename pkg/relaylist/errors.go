package relaylist

import "errors"

// Every sentinel here is a constant string, and every carrier type holds a NodeID and nothing
// else. No error from this package may carry a hostname, an address, a provider or any other
// field of a document (D19): an error value is the easiest thing in the world to log, and the
// export path's rule is that an error says which version failed and why, never what was in
// it. The package cannot import fmt, which keeps that structural.
var (
	// The API endpoint refusals, one per operator mistake, so a caller can say which.
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
	// or no endpoint is one every client would fail to reach or refer to. This is what stops the encoder ever
	// writing "wg_public_key":"" whatever the caller let through. Always carried by a
	// *RelayIncompleteError.
	ErrRelayIncomplete = errors.New("relaylist: relay is incomplete")

	// ErrEndpointKindUnknown: a relay endpoint whose kind is not one of transport.Kinds().
	// No client has a dialer for it. Always carried by an *EndpointKindUnknownError.
	ErrEndpointKindUnknown = errors.New("relaylist: relay has an endpoint of unknown kind")

	// ErrEndpointPortOutOfRange: a relay endpoint port outside 1..65535, which the
	// contract's uint16 cannot carry and no client can dial. Always carried by an
	// *EndpointPortOutOfRangeError.
	ErrEndpointPortOutOfRange = errors.New("relaylist: relay has an endpoint port outside 1..65535")

	// ErrEndpointRepeated: a relay declaring the same (kind, port) twice. Different kinds
	// sharing a port are accepted and published as declared (contract, Rules, ruled
	// 2026-10-09 for ABY-38); only an exact repeat is refused. Always carried by an
	// *EndpointRepeatedError.
	ErrEndpointRepeated = errors.New("relaylist: relay repeats an endpoint kind and port")

	// ErrStatusUnknown: a relay whose status is neither active nor draining. THIS IS
	// LOAD-BEARING: the producer converts its own node status into a Status without a switch,
	// so this refusal is what keeps a staged or retired node off the wire. Always carried by
	// a *StatusUnknownError.
	ErrStatusUnknown = errors.New("relaylist: relay status is neither active nor draining")

	// ErrOwnershipUnknown: a relay whose ownership is neither owned nor rented. Always
	// carried by an *OwnershipUnknownError.
	ErrOwnershipUnknown = errors.New("relaylist: relay ownership is neither owned nor rented")

	// ErrCapacityWeightOutOfRange: a relay capacity_weight outside 0..100 (contract, Shape).
	// Above 100 skews every client's selection toward that node fleet-wide; 0 is legitimate
	// and means "do not pick". Always carried by a *CapacityWeightOutOfRangeError.
	ErrCapacityWeightOutOfRange = errors.New("relaylist: relay capacity_weight is outside 0..100")

	// ErrEncodeFailed wraps a json.Marshal failure, which these types cannot produce.
	ErrEncodeFailed = errors.New("relaylist: failed to encode the document")
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

// redacted is what every type in this package renders as through slog.LogValuer.
const redacted = "REDACTED"
