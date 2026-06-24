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
