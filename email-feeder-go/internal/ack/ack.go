package ack

import (
	_ "embed"
	"fmt"
	"html/template"
	"strings"
)

//go:embed template.html
var tmplSrc string

type Sender interface {
	Send(from string, to []string, msg []byte) error
}

type Acker struct {
	From      string
	Allowlist []string
	tmpl      *template.Template
	S         Sender
}

func New(from string, allowlist []string, s Sender) (*Acker, error) {
	t, err := template.New("ack").Parse(tmplSrc)
	if err != nil {
		return nil, err
	}
	return &Acker{From: from, Allowlist: allowlist, tmpl: t, S: s}, nil
}

func (a *Acker) renderHTML(recipient string) (string, error) {
	var sb strings.Builder
	if err := a.tmpl.Execute(&sb, struct{ Recipient string }{recipient}); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func (a *Acker) allowed(recipient string) bool {
	if len(a.Allowlist) == 0 {
		return true
	}
	at := strings.LastIndexByte(recipient, '@')
	if at < 0 {
		return false
	}
	dom := strings.ToLower(recipient[at+1:])
	for _, d := range a.Allowlist {
		if strings.ToLower(d) == dom {
			return true
		}
	}
	return false
}

func (a *Acker) Ack(recipient string) error {
	// Strip CR/LF to prevent SMTP header injection via a malformed recipient.
	recipient = strings.NewReplacer("\r", "", "\n", "").Replace(recipient)

	if !a.allowed(recipient) {
		return nil
	}
	html, err := a.renderHTML(recipient)
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: Submission could not be processed\r\n"+
		"MIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		a.From, recipient, html)
	return a.S.Send(a.From, []string{recipient}, []byte(msg))
}
