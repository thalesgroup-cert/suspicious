package pipeline

import "errors"

var ErrCapsExceeded = errors.New("submission exceeds caps")

type Caps struct {
	MaxAttachmentBytes int
	MaxAttachments     int
	MaxTotalBytes      int
}

func (c Caps) check(p *Parsed) error {
	total := len(p.Wrapper)
	if len(p.Attachments) > c.MaxAttachments {
		return ErrCapsExceeded
	}
	for _, a := range p.Attachments {
		if len(a.Content) > c.MaxAttachmentBytes {
			return ErrCapsExceeded
		}
		total += len(a.Content)
	}
	if total > c.MaxTotalBytes {
		return ErrCapsExceeded
	}
	return nil
}
