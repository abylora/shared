// SPDX-License-Identifier: AGPL-3.0-only

package keysetvectors

import "github.com/abylora/shared/pkg/keyset/keysetpb"

// Schema is the value of every file's "schema" key. A change of meaning is a new schema value
// and new files, never an edit of these.
const Schema = "abylora.keyset.vectors.v1"

// Kind is a file's "kind".
type Kind string

const (
	KindConsumer      Kind = "consumer"
	KindConformance   Kind = "producer.conformance"
	KindResume        Kind = "producer.resume"
	KindNodeDirection Kind = "producer.node_direction"
)

var knownKinds = map[Kind]bool{KindConsumer: true, KindConformance: true, KindResume: true, KindNodeDirection: true}

// Outcome is a consumer step's expected outcome.
type Outcome string

const (
	OutcomeAccumulating Outcome = "accumulating"
	OutcomeUnchanged    Outcome = "unchanged"
	OutcomeApplied      Outcome = "applied"
	OutcomeApplyFailed  Outcome = "apply_failed"
	OutcomeViolation    Outcome = "violation"
)

var knownOutcomes = map[Outcome]bool{
	OutcomeAccumulating: true, OutcomeUnchanged: true, OutcomeApplied: true, OutcomeApplyFailed: true, OutcomeViolation: true,
}

// Violation names the rule a violating message breaks. Every vector that expects a violation is
// built so that exactly one applies, except where SCHEMA.md says otherwise.
type Violation string

// The consumer's violations: rule 13, rule 5's gap and rule 9's version 0.
const (
	ViolationMessageNoArm               Violation = "message_no_arm"
	ViolationOpNoArm                    Violation = "op_no_arm"
	ViolationUpsertNoEntry              Violation = "upsert_no_entry"
	ViolationSnapshotBeginVersionZero   Violation = "snapshot_begin_version_zero"
	ViolationSnapshotNested             Violation = "snapshot_nested"
	ViolationSnapshotEndWithoutBegin    Violation = "snapshot_end_without_begin"
	ViolationSnapshotEndVersionMismatch Violation = "snapshot_end_version_mismatch"
	ViolationUpsertOutsideSnapshot      Violation = "upsert_outside_snapshot"
	ViolationDeltaInsideSnapshot        Violation = "delta_inside_snapshot"
	ViolationHeartbeatInsideSnapshot    Violation = "heartbeat_inside_snapshot"
	ViolationDeltaFromVersionZero       Violation = "delta_from_version_zero"
	ViolationDeltaVersionsNotIncreasing Violation = "delta_versions_not_increasing"
	ViolationDeltaGap                   Violation = "delta_gap"
	ViolationHeartbeatBelowCursor       Violation = "heartbeat_below_cursor"
)

// The node direction's violations (rule 16).
const (
	ViolationNodeMessageNoArm    Violation = "node_message_no_arm"
	ViolationAppliedBeforeHello  Violation = "applied_before_hello"
	ViolationHelloRepeated       Violation = "hello_repeated"
	ViolationAppliedNotDelivered Violation = "applied_not_delivered"
	ViolationAppliedDecreasing   Violation = "applied_decreasing"
)

var consumerViolations = map[Violation]bool{
	ViolationMessageNoArm: true, ViolationOpNoArm: true, ViolationUpsertNoEntry: true,
	ViolationSnapshotBeginVersionZero: true, ViolationSnapshotNested: true, ViolationSnapshotEndWithoutBegin: true,
	ViolationSnapshotEndVersionMismatch: true, ViolationUpsertOutsideSnapshot: true, ViolationDeltaInsideSnapshot: true,
	ViolationHeartbeatInsideSnapshot: true, ViolationDeltaFromVersionZero: true, ViolationDeltaVersionsNotIncreasing: true,
	ViolationDeltaGap: true, ViolationHeartbeatBelowCursor: true,
}

var nodeViolations = map[Violation]bool{
	ViolationNodeMessageNoArm: true, ViolationAppliedBeforeHello: true, ViolationHelloRepeated: true,
	ViolationAppliedNotDelivered: true, ViolationAppliedDecreasing: true,
}

// Failure names why a Delta does not conform.
type Failure string

const (
	FailureDeltaShape         Failure = "delta_shape"
	FailureVersionsMismatch   Failure = "versions_mismatch"
	FailureKeyRepeated        Failure = "key_repeated"
	FailureUpsertBeforeRemove Failure = "upsert_before_remove"
	FailureNotSorted          Failure = "not_sorted"
	FailureEntryRefused       Failure = "entry_refused"
	FailureResultDiffers      Failure = "result_differs"
)

var knownFailures = map[Failure]bool{
	FailureDeltaShape: true, FailureVersionsMismatch: true, FailureKeyRepeated: true, FailureUpsertBeforeRemove: true,
	FailureNotSorted: true, FailureEntryRefused: true, FailureResultDiffers: true,
}

// NodeOutcome is a node-direction step's expected outcome.
type NodeOutcome string

const (
	NodeOutcomeRecord    NodeOutcome = "record"
	NodeOutcomeViolation NodeOutcome = "violation"
	NodeOutcomeClosed    NodeOutcome = "closed"
)

var knownNodeOutcomes = map[NodeOutcome]bool{NodeOutcomeRecord: true, NodeOutcomeViolation: true, NodeOutcomeClosed: true}

// Vectors is every case of one or more files, by kind.
type Vectors struct {
	Consumer      []ConsumerCase
	Conformance   []ConformanceCase
	Resume        []ResumeCase
	NodeDirection []NodeDirectionCase
}

func (v Vectors) ids() []string {
	var out []string
	for _, c := range v.Consumer {
		out = append(out, c.ID)
	}
	for _, c := range v.Conformance {
		out = append(out, c.ID)
	}
	for _, c := range v.Resume {
		out = append(out, c.ID)
	}
	for _, c := range v.NodeDirection {
		out = append(out, c.ID)
	}

	return out
}

// ConsumerCase is one consumer vector: start the node's state at InitialCursor holding
// InitialSet, refusing nothing, with no stream open; run Steps; compare with Final.
type ConsumerCase struct {
	File, ID, Description string
	OwnPublicKey          [32]byte
	InitialCursor         uint64
	InitialSet            []*keysetpb.KeySetEntry
	Steps                 []ConsumerStep
	Final                 ConsumerState
}

// ConsumerStep is either a Hello step (the node opens a stream and must send HeldVersion) or a
// receive step (Message arrives; the node's apply, if one is attempted, returns ApplySucceeds;
// Expect is the outcome).
type ConsumerStep struct {
	Hello         bool
	HeldVersion   uint64
	Message       *keysetpb.ControlPlaneMessage
	ApplySucceeds bool
	Expect        ConsumerExpect
}

// ConsumerExpect is a receive step's outcome. Applied is set for OutcomeApplied, Violation for
// OutcomeViolation.
type ConsumerExpect struct {
	Outcome   Outcome
	Applied   *keysetpb.Applied
	Violation Violation
}

// ConsumerState is the final state. Set is always asserted (SetAsserted is true for every loaded
// case): after an apply failure it is the last set applied successfully, unchanged, as rule 5
// was ruled. Skipped is asserted when SkippedAsserted is true, and may be left unasserted only
// after an apply failure.
type ConsumerState struct {
	Cursor          uint64
	Set             []*keysetpb.KeySetEntry
	SetAsserted     bool
	Skipped         uint64
	SkippedAsserted bool
}

// ConformanceCase is one producer conformance vector.
type ConformanceCase struct {
	File, ID, Description string
	OldVersion            uint64
	Old                   []*keysetpb.KeySetEntry
	NewVersion            uint64
	New                   []*keysetpb.KeySetEntry
	Delta                 *keysetpb.Delta
	Conforms              bool
	Failure               Failure
}

// LogDelta is one logged delta of a resume vector, by its versions.
type LogDelta struct {
	From, To uint64
}

// ResumeCase is one producer resume vector (rule 3).
type ResumeCase struct {
	File, ID, Description string
	HeldVersion           uint64
	Log                   []LogDelta
	Published             uint64
	Snapshot              bool
	SnapshotVersion       uint64
	Deltas                []LogDelta
}

// NodeRecord is what the control plane may record from one node message.
type NodeRecord struct {
	AppliedVersion uint64
	Skipped        uint64
	HasSkipped     bool
}

// NodeStep is either a sent step (the control plane sends Sent) or a received step (the node
// sends Received; Expect is the outcome).
type NodeStep struct {
	Sent     *keysetpb.ControlPlaneMessage
	Received *keysetpb.NodeMessage
	Expect   NodeExpect
}

type NodeExpect struct {
	Outcome   NodeOutcome
	Record    NodeRecord
	Violation Violation
}

// NodeDirectionCase is one rule 16 vector. Records is every record the steps allow, in order.
type NodeDirectionCase struct {
	File, ID, Description string
	Steps                 []NodeStep
	Records               []NodeRecord
}
