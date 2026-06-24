package ack

import (
	"strings"
	"testing"
)

type fakeSender struct{ to []string }

func (f *fakeSender) Send(from string, to []string, msg []byte) error { f.to = to; return nil }

func TestAckEscapesRecipient(t *testing.T) {
	a, err := New("sec@corp.com", nil, &fakeSender{})
	if err != nil {
		t.Fatal(err)
	}
	html, err := a.renderHTML(`</p><script>alert(1)</script>`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, "<script>alert(1)") {
		t.Fatal("recipient was not HTML-escaped")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatal("expected escaped form")
	}
}

func TestAckAllowlistSkips(t *testing.T) {
	fs := &fakeSender{}
	a, _ := New("sec@corp.com", []string{"corp.com"}, fs)
	if err := a.Ack("attacker@evil.test"); err != nil {
		t.Fatal(err)
	}
	if fs.to != nil {
		t.Fatal("ack to non-allowlisted domain must be skipped")
	}
}

// TestAckCRLFStrip verifies F2: a recipient containing CR/LF cannot inject
// additional SMTP headers (e.g. a Bcc: line) into the message.
func TestAckCRLFStrip(t *testing.T) {
	var capturedMsg []byte
	capture := &msgCaptureSender{fn: func(msg []byte) { capturedMsg = msg }}

	a, err := New("sec@corp.com", nil, capture)
	if err != nil {
		t.Fatal(err)
	}

	injected := "victim@corp.com\r\nBcc: attacker@evil.test"
	if err := a.Ack(injected); err != nil {
		t.Fatal(err)
	}

	// The message must not contain an injected Bcc: header line.
	// Check each MIME line (split on CRLF) — no line may start with "Bcc:".
	for _, line := range strings.Split(string(capturedMsg), "\r\n") {
		if strings.HasPrefix(line, "Bcc:") {
			t.Fatalf("SMTP header injection detected: found injected Bcc: header line\n%s", string(capturedMsg))
		}
	}
}

type msgCaptureSender struct {
	fn func(msg []byte)
}

func (m *msgCaptureSender) Send(from string, to []string, msg []byte) error {
	m.fn(msg)
	return nil
}
