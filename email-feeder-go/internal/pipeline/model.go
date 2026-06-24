package pipeline

type Attachment struct {
	Filename    string
	ContentType string
	Content     []byte
	IsEmail     bool
}

type Parsed struct {
	FromAddr    string
	Wrapper     []byte
	Attachments []Attachment
}

type Outcome int

const (
	Valid Outcome = iota
	NoAttachedMail
)

func Classify(p *Parsed) Outcome {
	for _, a := range p.Attachments {
		if a.IsEmail {
			return Valid
		}
	}
	return NoAttachedMail
}
