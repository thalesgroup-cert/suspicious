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
