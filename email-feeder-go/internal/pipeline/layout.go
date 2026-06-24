package pipeline

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/contract"
)

type Object struct {
	Key  string
	Body []byte
}

type Submission struct {
	ID      string
	Objects []Object
	Status  contract.Status
}

func innerDir(ts string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return ts + "-" + hex.EncodeToString(b)
}

func BuildSubmission(now time.Time, p *Parsed, caps Caps) (*Submission, error) {
	if err := caps.check(p); err != nil {
		return nil, err
	}
	id := contract.NewSubmissionID(now)
	ts := id[:12]
	sub := &Submission{ID: id}

	localPart := p.FromAddr
	if i := strings.IndexByte(localPart, '@'); i >= 0 {
		localPart = localPart[:i]
	}
	wrapperKey := id + "/" + contract.SanitizeBucketSegment(localPart) + "-" + contract.SubmissionEMLSuffix
	sub.Objects = append(sub.Objects, Object{Key: wrapperKey, Body: p.Wrapper})

	// Only forwarded emails (.eml attachments where IsEmail is true) get an
	// inner directory. Non-email attachments are dropped: their content lives
	// inside the forwarded .eml and will be extracted downstream by the backend.
	var emails []string
	for _, a := range p.Attachments {
		if !a.IsEmail {
			continue
		}
		dir := id + "/" + innerDir(ts)
		key := dir + "/" + contract.SanitizeBucketSegment(strings.TrimSuffix(a.Filename, ".eml")) + ".eml"
		sub.Objects = append(sub.Objects, Object{Key: key, Body: a.Content})
		emails = append(emails, key)
	}

	sub.Status = contract.Status{
		Schema:          contract.ContractSchema,
		Status:          contract.StatusTodo,
		SubmissionID:    id,
		ReportedBy:      p.FromAddr,
		EmailsToAnalyze: emails,
		Attachments:     []string{},
	}
	return sub, nil
}
