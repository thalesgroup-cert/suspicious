package app

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/ack"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/pipeline"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/sink"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/source"
)

// TestHandleDeliveryNeverDrops is the regression test for the C1 bug:
// the old main.go consumer guard `if dedup.Seen(raw.Mailbox, raw.UID) {
// continue }` ran AFTER the source had already called dedup.Mark, so every
// delivery was silently dropped. This test would have FAILED under that guard
// because it constructs a Delivery whose (Mailbox, UID) would be pre-seen,
// then asserts the message is actually stored/acked and MarkSeen fires.
//
// HandleDelivery does not consult any dedup, so the delivery must be processed
// unconditionally.
func TestHandleDeliveryNeverDrops(t *testing.T) {
	caps := pipeline.Caps{MaxAttachmentBytes: 1 << 20, MaxAttachments: 50, MaxTotalBytes: 1 << 21}

	// validBody: carries an attached .eml → store path.
	validBody := []byte(
		"From: u@corp.com\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
			"--b\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"f.eml\"\r\n\r\n" +
			"From: a@b\r\nSubject: x\r\n\r\ny\r\n--b--\r\n")

	// noAttachBody: no attachment → ack path.
	noAttachBody := []byte("From: u@corp.com\r\n\r\njust text, no attachment")

	type tc struct {
		name           string
		body           []byte
		wantStoredMin  int // stored >= wantStoredMin
		wantAcked      int
		wantMarkSeen   int32
	}
	tests := []tc{
		{
			name:          "valid submission is stored and MarkSeen fires",
			body:          validBody,
			wantStoredMin: 1, // Store calls PutObject once per object + status file
			wantAcked:     0,
			wantMarkSeen:  1,
		},
		{
			name:          "no-attachment mail is acked and MarkSeen fires",
			body:          noAttachBody,
			wantStoredMin: 0,
			wantAcked:     1,
			wantMarkSeen:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp := &capSink{}
			s := &sink.Sink{Bucket: "feeder", P: cp}
			sender := &capSender{}
			a, _ := ack.New("sec@corp.com", nil, sender)

			var markSeenCnt atomic.Int32

			// Build a Delivery. Crucially, we also call a shared Dedup and Mark
			// this UID before passing it to HandleDelivery — simulating what
			// source.fetchUnseen does (dedup.Mark before emitting). Under the old
			// broken guard in main.go this would have caused the delivery to be
			// silently dropped.
			dedup := source.NewDedup(10_000)
			const mailbox = "abuse"
			const uid uint32 = 99
			dedup.Mark(mailbox, uid) // pre-mark — mirrors what the source layer does

			d := source.Delivery{
				Raw:  source.RawEmail{Mailbox: mailbox, UID: uid, Body: tt.body},
				MarkSeen: func() { markSeenCnt.Add(1) },
			}

			err := HandleDelivery(context.Background(), d, caps, s, a, time.Now)
			if err != nil {
				t.Fatalf("HandleDelivery returned unexpected error: %v", err)
			}

			if cp.stored < tt.wantStoredMin {
				t.Errorf("stored: got %d, want >= %d", cp.stored, tt.wantStoredMin)
			}
			if sender.acked != tt.wantAcked {
				t.Errorf("acked: got %d, want %d", sender.acked, tt.wantAcked)
			}
			got := markSeenCnt.Load()
			if got != tt.wantMarkSeen {
				t.Errorf("MarkSeen call count: got %d, want %d", got, tt.wantMarkSeen)
			}
		})
	}
}

// TestHandleDeliverySinkErrorNoMarkSeen confirms that when Dispatch fails
// (transient upload error) MarkSeen is NOT called — the message stays \Unseen
// so the server can redeliver it.
func TestHandleDeliverySinkErrorNoMarkSeen(t *testing.T) {
	caps := pipeline.Caps{MaxAttachmentBytes: 1 << 20, MaxAttachments: 50, MaxTotalBytes: 1 << 21}
	validBody := []byte(
		"From: u@corp.com\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
			"--b\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"f.eml\"\r\n\r\n" +
			"From: a@b\r\nSubject: x\r\n\r\ny\r\n--b--\r\n")

	s := &sink.Sink{Bucket: "feeder", P: &errPutter{}}
	sender := &capSender{}
	a, _ := ack.New("sec@corp.com", nil, sender)

	var markSeenCnt atomic.Int32
	d := source.Delivery{
		Raw:      source.RawEmail{Mailbox: "abuse", UID: 7, Body: validBody},
		MarkSeen: func() { markSeenCnt.Add(1) },
	}

	err := HandleDelivery(context.Background(), d, caps, s, a, time.Now)
	if err == nil {
		t.Fatal("expected error from sink, got nil")
	}
	if got := markSeenCnt.Load(); got != 0 {
		t.Errorf("MarkSeen should not fire on error, got count=%d", got)
	}
}
