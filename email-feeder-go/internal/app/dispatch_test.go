package app

import (
	"context"
	"testing"
	"time"

	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/ack"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/pipeline"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/sink"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/source"
)

type capSink struct{ stored int }

func (c *capSink) EnsureBucket(ctx context.Context) error { return nil }
func (c *capSink) PutObject(ctx context.Context, k string, b []byte, ct string) error {
	c.stored++
	return nil
}

type capSender struct{ acked int }

func (c *capSender) Send(from string, to []string, msg []byte) error { c.acked++; return nil }

func TestDispatchValidStoresNoAck(t *testing.T) {
	cp := &capSink{}
	s := &sink.Sink{Bucket: "feeder", P: cp}
	sender := &capSender{}
	a, _ := ack.New("sec@corp.com", nil, sender)
	caps := pipeline.Caps{MaxAttachmentBytes: 1 << 20, MaxAttachments: 50, MaxTotalBytes: 1 << 21}
	raw := source.RawEmail{Mailbox: "abuse", Body: []byte(
		"From: u@corp.com\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
			"--b\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"f.eml\"\r\n\r\n" +
			"From: a@b\r\nSubject: x\r\n\r\ny\r\n--b--\r\n")}
	handled, err := Dispatch(context.Background(), raw, caps, s, a, time.Now)
	if err != nil || !handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if cp.stored == 0 || sender.acked != 0 {
		t.Fatalf("valid must store and not ack: stored=%d acked=%d", cp.stored, sender.acked)
	}
}

func TestDispatchNoAttachedMailAcksNoStore(t *testing.T) {
	cp := &capSink{}
	s := &sink.Sink{Bucket: "feeder", P: cp}
	sender := &capSender{}
	a, _ := ack.New("sec@corp.com", nil, sender)
	caps := pipeline.Caps{MaxAttachmentBytes: 1 << 20, MaxAttachments: 50, MaxTotalBytes: 1 << 21}
	raw := source.RawEmail{Mailbox: "abuse", Body: []byte("From: u@corp.com\r\n\r\njust text, no attachment")}
	handled, err := Dispatch(context.Background(), raw, caps, s, a, time.Now)
	if err != nil || !handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if cp.stored != 0 || sender.acked != 1 {
		t.Fatalf("bad submission must ack and not store: stored=%d acked=%d", cp.stored, sender.acked)
	}
}
