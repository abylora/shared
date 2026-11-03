// SPDX-License-Identifier: AGPL-3.0-only

package keysetvectors

import "errors"

// LoadError says which file, and which case when one is known, a loader error comes from. The
// vectors hold synthetic keys only, so naming a file and a case id is safe.
type LoadError struct {
	File, Case string
	Err        error
}

func (e *LoadError) Error() string {
	s := "keysetvectors"
	if e.File != "" {
		s += ": " + e.File
	}
	if e.Case != "" {
		s += ": " + e.Case
	}

	return s + ": " + e.Err.Error()
}

func (e *LoadError) Unwrap() error { return e.Err }

var (
	ErrNoFiles                   = errors.New("no vector file")
	ErrFileName                  = errors.New("a file name is not <consumer|producer>-<number>-<name>.json, or its group does not match its kind")
	ErrSchema                    = errors.New("unknown schema")
	ErrKindUnknown               = errors.New("unknown kind")
	ErrNoCases                   = errors.New("a file has no case")
	ErrJSON                      = errors.New("invalid JSON, or an unknown key")
	ErrTrailingData              = errors.New("data after the JSON value")
	ErrDuplicateKey              = errors.New("a JSON object repeats a key")
	ErrNull                      = errors.New("null is not a value in these files")
	ErrFieldMissing              = errors.New("a required key is missing")
	ErrHexInvalid                = errors.New("bytes are not lowercase, even-length hex")
	ErrDecimalInvalid            = errors.New("an integer is not a canonical decimal string in range")
	ErrArmUnknown                = errors.New("a message names an unknown arm")
	ErrArmsRepeated              = errors.New("a message names more than one arm")
	ErrWireInvalid               = errors.New("a wire message is not a valid protobuf encoding")
	ErrOwnKeyLength              = errors.New("own_public_key is not 32 bytes")
	ErrStepShape                 = errors.New("a step is not exactly one of its forms")
	ErrStepWithoutHello          = errors.New("a message is received with no stream open")
	ErrApplySucceedsInconsistent = errors.New("apply_succeeds is false exactly when the outcome is apply_failed")
	ErrExpectShape               = errors.New("an expectation's keys do not match its outcome")
	ErrWordUnknown               = errors.New("an outcome, violation or failure word is unknown")
	ErrFinalUnasserted           = errors.New("the final set is unasserted, or the gauge is unasserted but the last outcome is not apply_failed")
	ErrCaseIDPrefix              = errors.New("a case id does not start with its file's number")
	ErrCaseIDRepeated            = errors.New("a case id is repeated")
	ErrLogShape                  = errors.New("a resume expectation's keys do not match its send word")
	ErrStepAfterClose            = errors.New("a node message is received after a violation without expecting closed")
)
