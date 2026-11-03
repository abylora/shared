// SPDX-License-Identifier: AGPL-3.0-only

package keyset

import "errors"

// EVERY ERROR HERE IS A SENTINEL, returned unwrapped and compared by identity. None carries a
// public key, a tunnel address or any other field of an entry, and none can: the package has no
// fmt, and nothing here concatenates input into a string (rule 11: the consumer never logs the
// entry). A caller that needs to know which rule fired compares against these values.

// Rule 13's state machine, rule 5's gap and rule 9's version 0. Each closes the stream; the
// node reconnects with Hello{held_version: cursor}, its cursor and held set unchanged.
var (
	ErrMessageNoArm               = errors.New("keyset: a control-plane message has no known arm")
	ErrOpNoArm                    = errors.New("keyset: a delta op has neither an upsert nor a remove")
	ErrUpsertNoEntry              = errors.New("keyset: an upsert carries no entry")
	ErrSnapshotVersionZero        = errors.New("keyset: a snapshot begins at version 0")
	ErrSnapshotNested             = errors.New("keyset: a snapshot begins inside an open snapshot")
	ErrSnapshotEndWithoutBegin    = errors.New("keyset: a snapshot ends with no snapshot open")
	ErrSnapshotEndVersionMismatch = errors.New("keyset: a snapshot ends at a version other than the one it began at")
	ErrUpsertOutsideSnapshot      = errors.New("keyset: an upsert arrives outside a snapshot")
	ErrDeltaInsideSnapshot        = errors.New("keyset: a delta arrives inside a snapshot")
	ErrHeartbeatInsideSnapshot    = errors.New("keyset: a heartbeat arrives inside a snapshot")
	ErrDeltaFromVersionZero       = errors.New("keyset: a delta starts from version 0")
	ErrDeltaVersionsNotIncreasing = errors.New("keyset: a delta's to_version is not above its from_version")
	ErrDeltaGap                   = errors.New("keyset: a delta's from_version is not the cursor")
	ErrHeartbeatBelowCursor       = errors.New("keyset: a heartbeat's current_version is below the cursor")
	ErrHeartbeatAboveCursor       = errors.New("keyset: a heartbeat's current_version is above the cursor")
)

// ErrStreamClosed is returned by Receive, as OutcomeMisuse, when no stream is open: before the
// first Hello, or after an outcome that closed the stream. It is a driver error, not a contract
// rule.
var ErrStreamClosed = errors.New("keyset: no stream is open; open one with Hello")

// ErrApplyNil is returned by Receive, as OutcomeMisuse, when apply is nil.
var ErrApplyNil = errors.New("keyset: Receive was given a nil apply")

// ErrApplyFailed is the error of OutcomeApplyFailed (rule 5): the cursor is now 0.
var ErrApplyFailed = errors.New("keyset: the apply failed; the cursor is reset to 0")

// Refusals of SetOf and New.
var (
	ErrEntryMalformed     = errors.New("keyset: an entry of the set is malformed")
	ErrSetKeyRepeated     = errors.New("keyset: two entries of the set share a public key")
	ErrSetAddressRepeated = errors.New("keyset: two entries of the set share a tunnel address")
	ErrHeldSetHasOwnKey   = errors.New("keyset: the held set contains the node's own interface key")
)

// Producer conformance failures (CheckDelta), in the order CheckDelta tests them.
var (
	ErrDeltaVersionsMismatch   = errors.New("keyset: the delta's versions are not the old and new versions")
	ErrDeltaKeyRepeated        = errors.New("keyset: the delta carries more than one op for a key")
	ErrDeltaUpsertBeforeRemove = errors.New("keyset: the delta carries a remove after an upsert")
	ErrDeltaNotSorted          = errors.New("keyset: the delta's ops are not sorted by public key bytes within their group")
	ErrDeltaEntryRefused       = errors.New("keyset: the delta carries an entry a consumer must skip")
	ErrDeltaResultDiffers      = errors.New("keyset: applying the delta to the old set does not give the new set")
)

// ErrLogInvalid refuses a change log that is not a contiguous chain ending at the published
// version.
var ErrLogInvalid = errors.New("keyset: the change log is not a contiguous chain of deltas ending at the published version")

// The node's direction (rule 16), in the order NodeStreamChecker tests them.
var (
	ErrNodeMessageNoArm    = errors.New("keyset: a node message has no known arm")
	ErrAppliedBeforeHello  = errors.New("keyset: an applied arrives before the hello")
	ErrHelloRepeated       = errors.New("keyset: a second hello arrives on one stream")
	ErrAppliedNotDelivered = errors.New("keyset: an applied names a version not delivered on this stream")
	ErrAppliedDecreasing   = errors.New("keyset: an applied names a version below the previous applied")
	ErrNodeStreamClosed    = errors.New("keyset: the node's stream is closed; nothing more is recorded")
)
