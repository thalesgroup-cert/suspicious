package pipeline

import (
	"bytes"
	"net/mail"
	"strings"

	"github.com/jhillyerd/enmime/v2"
)

func Parse(raw []byte) (*Parsed, error) {
	env, err := enmime.ReadEnvelope(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	from := ""
	if addr, err := mail.ParseAddress(env.GetHeader("From")); err == nil {
		from = addr.Address
	}
	p := &Parsed{FromAddr: from, Wrapper: raw}
	for _, part := range append(env.Attachments, env.Inlines...) {
		ct := strings.ToLower(part.ContentType)
		fn := part.FileName
		p.Attachments = append(p.Attachments, Attachment{
			Filename:    fn,
			ContentType: part.ContentType,
			Content:     part.Content,
			IsEmail:     ct == "message/rfc822" || strings.HasSuffix(strings.ToLower(fn), ".eml"),
		})
	}
	return p, nil
}
