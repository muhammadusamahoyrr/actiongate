package controlplane

import (
	"slices"
	"testing"
)

func TestSplitList(t *testing.T) {
	if got := SplitList(" U1, ,U2,"); !slices.Equal(got, []string{"U1", "U2"}) {
		t.Errorf("SplitList = %q", got)
	}
	if got := SplitList(""); got != nil {
		t.Errorf("SplitList(\"\") = %q, want nil", got)
	}
}
