package pipeline

import (
	"strings"
	"testing"
	"time"

	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/contract"
)

func sampleValid() *Parsed {
	return &Parsed{
		FromAddr:    "jane.doe@corp.com",
		Wrapper:     []byte("From: jane.doe@corp.com\r\n\r\nplease analyse"),
		Attachments: []Attachment{{Filename: "phish.eml", ContentType: "message/rfc822", Content: []byte("From: a@b\r\n\r\nx"), IsEmail: true}},
	}
}

func TestBuildSubmissionContractShape(t *testing.T) {
	caps := Caps{MaxAttachmentBytes: 1 << 20, MaxAttachments: 50, MaxTotalBytes: 1 << 21}
	sub, err := BuildSubmission(time.Date(2026, 3, 26, 14, 11, 59, 0, time.UTC), sampleValid(), caps)
	if err != nil {
		t.Fatal(err)
	}
	var wrapper, inner string
	for _, o := range sub.Objects {
		if strings.HasSuffix(o.Key, contract.SubmissionEMLSuffix) {
			wrapper = o.Key
		}
		if strings.HasSuffix(o.Key, ".eml") && !strings.HasSuffix(o.Key, contract.SubmissionEMLSuffix) {
			inner = o.Key
		}
	}
	if wrapper == "" {
		t.Fatal("no *submission.eml wrapper object")
	}
	if !strings.HasPrefix(wrapper, sub.ID+"/") {
		t.Fatalf("wrapper not under submission prefix: %q", wrapper)
	}
	// inner dir segment must match the contract regex
	seg := strings.Split(strings.TrimPrefix(inner, sub.ID+"/"), "/")[0]
	if !contract.EmailDirPattern.MatchString(seg) {
		t.Fatalf("inner dir %q does not match contract regex", seg)
	}
	if sub.Status.Status != contract.StatusTodo || sub.Status.ReportedBy != "jane.doe@corp.com" {
		t.Fatalf("status wrong: %+v", sub.Status)
	}
	// _status.json must NOT be in Objects (sink writes it last)
	for _, o := range sub.Objects {
		if strings.HasSuffix(o.Key, contract.StatusObjectName) {
			t.Fatal("_status.json must not be in Objects")
		}
	}
}

func TestBuildSubmissionCaps(t *testing.T) {
	caps := Caps{MaxAttachmentBytes: 4, MaxAttachments: 50, MaxTotalBytes: 1 << 21}
	_, err := BuildSubmission(time.Now(), sampleValid(), caps)
	if err != ErrCapsExceeded {
		t.Fatalf("want ErrCapsExceeded, got %v", err)
	}
}

// TestBuildSubmissionInnerDirGrouping verifies F1: only IsEmail attachments
// produce an inner dir; non-email siblings are dropped entirely.
func TestBuildSubmissionInnerDirGrouping(t *testing.T) {
	caps := Caps{MaxAttachmentBytes: 1 << 20, MaxAttachments: 50, MaxTotalBytes: 1 << 21}
	p := &Parsed{
		FromAddr: "reporter@example.com",
		Wrapper:  []byte("From: reporter@example.com\r\n\r\nbody"),
		Attachments: []Attachment{
			{Filename: "phish.eml", ContentType: "message/rfc822", Content: []byte("From: a@b\r\n\r\nx"), IsEmail: true},
			{Filename: "invoice.pdf", ContentType: "application/pdf", Content: []byte("%PDF-1.4"), IsEmail: false},
		},
	}
	sub, err := BuildSubmission(time.Date(2026, 3, 26, 14, 11, 59, 0, time.UTC), p, caps)
	if err != nil {
		t.Fatal(err)
	}

	// Count inner-dir segments: keys that are NOT the wrapper and end in .eml.
	var innerDirs []string
	var attachmentKeys []string
	for _, o := range sub.Objects {
		if strings.HasSuffix(o.Key, contract.SubmissionEMLSuffix) {
			continue // wrapper — skip
		}
		// Anything under an inner dir
		parts := strings.SplitN(strings.TrimPrefix(o.Key, sub.ID+"/"), "/", 2)
		seg := parts[0]
		if contract.EmailDirPattern.MatchString(seg) {
			innerDirs = append(innerDirs, seg)
			if strings.Contains(o.Key, "/attachments/") {
				attachmentKeys = append(attachmentKeys, o.Key)
			}
		}
	}

	// Exactly one inner-dir segment (one email attachment → one dir).
	if len(innerDirs) != 1 {
		t.Fatalf("expected exactly 1 inner dir segment, got %d: %v", len(innerDirs), innerDirs)
	}

	// No attachments/ objects (the PDF must be dropped).
	if len(attachmentKeys) != 0 {
		t.Fatalf("expected 0 attachments/ objects, got %d: %v", len(attachmentKeys), attachmentKeys)
	}

	// Status.Attachments must be empty.
	if len(sub.Status.Attachments) != 0 {
		t.Fatalf("expected Status.Attachments to be empty, got %v", sub.Status.Attachments)
	}

	// Status.EmailsToAnalyze must have exactly one entry.
	if len(sub.Status.EmailsToAnalyze) != 1 {
		t.Fatalf("expected 1 EmailsToAnalyze, got %d: %v", len(sub.Status.EmailsToAnalyze), sub.Status.EmailsToAnalyze)
	}
}
