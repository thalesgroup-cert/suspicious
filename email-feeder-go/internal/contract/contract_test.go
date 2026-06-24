package contract

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEmailDirPattern(t *testing.T) {
	if !EmailDirPattern.MatchString("260326141159-abc123") {
		t.Fatal("should match feeder dir")
	}
	if EmailDirPattern.MatchString("analysis_0") {
		t.Fatal("should not match analysis_0")
	}
}

func TestNewSubmissionID(t *testing.T) {
	id := NewSubmissionID(time.Date(2026, 3, 26, 14, 11, 59, 0, time.UTC))
	if !EmailDirPattern.MatchString(id) {
		t.Fatalf("id %q must match ^\\d{12}-[a-f0-9]+$", id)
	}
	if id[:12] != "260326141159" {
		t.Fatalf("ts prefix wrong: %q", id)
	}
}

func TestSanitizeBucketSegment(t *testing.T) {
	if got := SanitizeBucketSegment("Jane.Doe@Corp_X"); got != "jane-doe-corp-x" {
		t.Fatalf("got %q", got)
	}
	if got := SanitizeBucketSegment(string(make([]byte, 0)) + string(repeat('a', 100))); len(got) != 63 {
		t.Fatalf("len=%d want 63", len(got))
	}
}

func repeat(b byte, n int) []byte { s := make([]byte, n); for i := range s { s[i] = b }; return s }

func TestStatusMarshalKeys(t *testing.T) {
	s := Status{Schema: ContractSchema, Status: StatusTodo, SubmissionID: "x", ReportedBy: "u@x"}
	raw, _ := s.Marshal()
	var m map[string]any
	json.Unmarshal(raw, &m)
	for _, k := range []string{"schema", "status", "submission_id", "reported_by", "emails_to_analyze", "attachments", "submitted_at"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing key %q", k)
		}
	}
}
