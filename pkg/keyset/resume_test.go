// SPDX-License-Identifier: AGPL-3.0-only

package keyset_test

import (
	"testing"

	"github.com/abylora/shared/pkg/keyset"
)

// The log is a contiguous chain ending at the published version, which is at least 1 (rule 9).
// Anything else is a producer bug that would make the decision meaningless, so it is refused.
func TestPlanResumeRefusesABrokenLog(t *testing.T) {
	for name, tc := range map[string]struct {
		log       []keyset.LoggedDelta
		published uint64
	}{
		"published 0":                {nil, 0},
		"a from_version of 0":        {[]keyset.LoggedDelta{{From: 0, To: 94000}}, 94000},
		"a to_version not above":     {[]keyset.LoggedDelta{{From: 94000, To: 94000}}, 94000},
		"a break in the chain":       {[]keyset.LoggedDelta{{From: 94000, To: 95000}, {From: 95500, To: 96000}}, 96000},
		"a chain short of published": {[]keyset.LoggedDelta{{From: 94000, To: 95000}}, 96000},
	} {
		if _, err := keyset.PlanResume(5000, tc.log, tc.published); err != keyset.ErrLogInvalid {
			t.Errorf("%s: err = %v, want %v", name, err, keyset.ErrLogInvalid)
		}
	}
}
