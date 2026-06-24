package contract

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

const (
	StatusObjectName    = "_status.json"
	SubmissionEMLSuffix = "submission.eml"
	StatusTodo          = "todo"
	StatusProcessing    = "processing"
	StatusDone          = "done"
	ContractSchema      = 1
)

var EmailDirPattern = regexp.MustCompile(`^\d{12}-[a-f0-9]+$`)

func NewSubmissionID(now time.Time) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return now.Format("060102150405") + "-" + hex.EncodeToString(b)
}

var nonSegment = regexp.MustCompile(`[^a-z0-9-]+`)

func SanitizeBucketSegment(s string) string {
	s = strings.ToLower(s)
	s = nonSegment.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}

type Status struct {
	Schema          int      `json:"schema"`
	Status          string   `json:"status"`
	SubmissionID    string   `json:"submission_id"`
	ReportedBy      string   `json:"reported_by"`
	EmailsToAnalyze []string `json:"emails_to_analyze"`
	Attachments     []string `json:"attachments"`
	SubmittedAt     string   `json:"submitted_at"`
}

func (s Status) Marshal() ([]byte, error) {
	if s.EmailsToAnalyze == nil {
		s.EmailsToAnalyze = []string{}
	}
	if s.Attachments == nil {
		s.Attachments = []string{}
	}
	if s.SubmittedAt == "" {
		s.SubmittedAt = time.Now().UTC().Format(time.RFC3339)
	}
	return json.Marshal(s)
}
