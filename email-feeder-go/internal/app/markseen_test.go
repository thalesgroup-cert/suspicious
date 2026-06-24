package app

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/ack"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/pipeline"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/sink"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/source"
)

// errPutter is a sink putter that always fails Store, so Dispatch returns
// (false, err) — simulating a transient upload error.
type errPutter struct{}

func (e *errPutter) EnsureBucket(ctx context.Context) error { return nil }
func (e *errPutter) PutObject(_ context.Context, _ string, _ []byte, _ string) error {
	return errors.New("s3 unavailable")
}

// TestMarkSeenFiredOnHandledDelivery proves that the consumer pattern used in
// main.go calls the Delivery.MarkSeen callback exactly once for each
// successfully handled delivery and never calls it when Dispatch returns an
// error. No live IMAP server is required — the callback is a simple counter.
func TestMarkSeenFiredOnHandledDelivery(t *testing.T) {
	caps := pipeline.Caps{MaxAttachmentBytes: 1 << 20, MaxAttachments: 50, MaxTotalBytes: 1 << 21}

	// validBody: carries an attached .eml → Dispatch returns (true, nil).
	validBody := []byte(
		"From: u@corp.com\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
			"--b\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"f.eml\"\r\n\r\n" +
			"From: a@b\r\nSubject: x\r\n\r\ny\r\n--b--\r\n")

	// noAttachBody: no attachment → Dispatch returns (true, nil) via Ack path.
	noAttachBody := []byte("From: u@corp.com\r\n\r\njust text, no attachment")

	type tc struct {
		name            string
		body            []byte
		putter          sink.Putter
		wantMarkSeenCnt int32
		wantHandled     bool
	}
	tests := []tc{
		{
			name:            "valid submission marks seen once",
			body:            validBody,
			putter:          &capSink{},
			wantMarkSeenCnt: 1,
			wantHandled:     true,
		},
		{
			name:            "no-attachment ack path marks seen once",
			body:            noAttachBody,
			putter:          &capSink{},
			wantMarkSeenCnt: 1,
			wantHandled:     true,
		},
		{
			name:            "sink error does not mark seen",
			body:            validBody,
			putter:          &errPutter{},
			wantMarkSeenCnt: 0,
			wantHandled:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var markSeenCnt atomic.Int32

			s := &sink.Sink{Bucket: "feeder", P: tt.putter}
			sender := &capSender{}
			a, _ := ack.New("sec@corp.com", nil, sender)

			raw := source.RawEmail{Mailbox: "abuse", UID: 42, Body: tt.body}
			d := source.Delivery{
				Raw: raw,
				MarkSeen: func() {
					markSeenCnt.Add(1)
				},
			}

			// Simulate the consumer logic from cmd/feeder/main.go:
			//   handled, err := Dispatch(...)
			//   if err == nil && handled { dedup.Mark(...); d.MarkSeen() }
			ctx := context.Background()
			handled, err := Dispatch(ctx, d.Raw, caps, s, a, time.Now)
			if err == nil && handled {
				d.MarkSeen()
			}

			if handled != tt.wantHandled {
				t.Errorf("handled: got %v, want %v (err=%v)", handled, tt.wantHandled, err)
			}
			got := markSeenCnt.Load()
			if got != tt.wantMarkSeenCnt {
				t.Errorf("MarkSeen call count: got %d, want %d", got, tt.wantMarkSeenCnt)
			}
		})
	}
}
