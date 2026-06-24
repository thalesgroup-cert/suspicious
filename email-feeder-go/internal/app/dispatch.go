package app

import (
	"context"
	"errors"
	"time"

	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/ack"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/pipeline"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/sink"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/source"
)

func Dispatch(ctx context.Context, raw source.RawEmail, caps pipeline.Caps, s *sink.Sink, a *ack.Acker, now func() time.Time) (bool, error) {
	p, err := pipeline.Parse(raw.Body)
	if err != nil {
		return false, err
	}
	if pipeline.Classify(p) == pipeline.NoAttachedMail {
		return true, a.Ack(p.FromAddr)
	}
	sub, err := pipeline.BuildSubmission(now(), p, caps)
	if err != nil {
		if errors.Is(err, pipeline.ErrCapsExceeded) {
			return true, a.Ack(p.FromAddr) // oversized → treat as bad submission
		}
		return false, err
	}
	if err := s.Store(ctx, sub); err != nil {
		return false, err
	}
	return true, nil
}
