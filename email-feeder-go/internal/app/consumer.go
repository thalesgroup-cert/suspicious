package app

import (
	"context"
	"time"

	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/ack"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/pipeline"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/sink"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/source"
)

// HandleDelivery processes a single Delivery end-to-end: it calls Dispatch to
// parse, classify, and store (or ack) the message, and — if Dispatch signals
// the message was handled without error — calls d.MarkSeen() so the
// per-mailbox IMAP goroutine will apply STORE +FLAGS \Seen on the server.
//
// HandleDelivery is the canonical consumer body used by cmd/feeder/main.go's
// dispatch loop. It intentionally does NOT consult any in-process dedup: the
// Source already called dedup.Mark before emitting the Delivery, so the
// in-process double-emit guard lives entirely in the source layer. The only
// cross-restart guard is the server-side \Seen flag, which this function
// applies via d.MarkSeen.
func HandleDelivery(
	ctx context.Context,
	d source.Delivery,
	caps pipeline.Caps,
	s *sink.Sink,
	a *ack.Acker,
	now func() time.Time,
) error {
	handled, err := Dispatch(ctx, d.Raw, caps, s, a, now)
	if err != nil {
		return err
	}
	if handled {
		d.MarkSeen()
	}
	return nil
}
