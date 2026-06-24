package pipeline

import "testing"

func TestClassify(t *testing.T) {
	valid := &Parsed{Attachments: []Attachment{{Filename: "forwarded.txt", ContentType: "message/rfc822", IsEmail: true}}}
	if Classify(valid) != Valid {
		t.Fatal("rfc822 attachment must be Valid")
	}
	eml := &Parsed{Attachments: []Attachment{{Filename: "evil.eml", ContentType: "application/octet-stream", IsEmail: true}}}
	if Classify(eml) != Valid {
		t.Fatal(".eml attachment must be Valid")
	}
	bad := &Parsed{Attachments: []Attachment{{Filename: "doc.pdf", ContentType: "application/pdf", IsEmail: false}}}
	if Classify(bad) != NoAttachedMail {
		t.Fatal("pdf-only must be NoAttachedMail")
	}
}

func TestParseSetsIsEmailAndFrom(t *testing.T) {
	raw := []byte("From: user@corp.com\r\n" +
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n" +
		"--b\r\nContent-Type: message/rfc822\r\n" +
		"Content-Disposition: attachment; filename=\"forwarded.txt\"\r\n\r\n" +
		"From: a@evil.test\r\nSubject: phish\r\n\r\nclick\r\n--b--\r\n")
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.FromAddr != "user@corp.com" {
		t.Fatalf("from = %q", p.FromAddr)
	}
	found := false
	for _, a := range p.Attachments {
		if a.IsEmail {
			found = true
		}
	}
	if !found {
		t.Fatal("rfc822 part not marked IsEmail")
	}
}
