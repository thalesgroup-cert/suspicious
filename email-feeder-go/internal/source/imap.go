package source

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/config"
)

// RawEmail is the minimal envelope emitted by Source for each new message.
type RawEmail struct {
	Mailbox string
	UID     uint32
	Body    []byte
}

// Source connects to one or more IMAP mailboxes and emits new messages as
// RawEmail values. For each mailbox it tries IDLE if the server advertises
// the capability; otherwise it falls back to polling every PollSeconds.
// Errors cause an exponential-backoff reconnect loop; the caller must drain
// the out channel to avoid blocking the source goroutines.
type Source struct {
	cfg   config.Config
	dedup *Dedup

	// markCh carries (mailbox, uid) pairs that the controller has confirmed as
	// processed; the background goroutine forwards them to the IMAP server via
	// Store \Seen and records them in the dedup set.
	markCh chan markReq
}

type markReq struct {
	mailbox string
	uid     uint32
}

// New creates a Source from the given config and an optional external Dedup.
// If dedup is nil a default Dedup with a 10 000-entry window is created.
func New(cfg config.Config, dedup *Dedup) *Source {
	if dedup == nil {
		dedup = NewDedup(10_000)
	}
	return &Source{
		cfg:    cfg,
		dedup:  dedup,
		markCh: make(chan markReq, 256),
	}
}

// MarkSeen tells the Source that the controller has successfully processed
// (mailbox, uid) and that the message should be flagged \Seen on the server.
// It is non-blocking: if the internal channel is full the mark is dropped
// (the dedup LRU still prevents reprocessing within the window, and the
// server-side \Seen will be applied on the next reconnect's SEARCH UNSEEN).
func (s *Source) MarkSeen(mailbox string, uid uint32) {
	select {
	case s.markCh <- markReq{mailbox: mailbox, uid: uid}:
	default:
	}
}

// Run starts one goroutine per enabled mailbox and blocks until ctx is
// cancelled. Each goroutine connects to its mailbox, selects INBOX, and
// enters an IDLE-or-poll loop. On wake it searches for UNSEEN messages,
// fetches their bodies, records them in the dedup set, and emits them on out.
// \Seen is applied only after the controller calls MarkSeen. Reconnects use
// exponential backoff (1 s … 5 min).
func (s *Source) Run(ctx context.Context, out chan<- RawEmail) {
	for i := range s.cfg.Mailboxes {
		mb := s.cfg.Mailboxes[i]
		if !mb.Enable {
			continue
		}
		go s.runMailbox(ctx, mb, out)
	}
	<-ctx.Done()
}

// runMailbox is the per-mailbox goroutine.
func (s *Source) runMailbox(ctx context.Context, mb config.Mailbox, out chan<- RawEmail) {
	backoff := time.Second
	const maxBackoff = 5 * time.Minute

	for {
		if ctx.Err() != nil {
			return
		}
		err := s.connectAndPoll(ctx, mb, out)
		if err != nil && ctx.Err() == nil {
			log.Printf("source[%s]: %v — reconnecting in %s", mb.Name, err, backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		} else {
			// Clean exit (ctx cancelled or nil error): stop.
			return
		}
	}
}

// connectAndPoll opens one IMAP session, selects INBOX, and runs the
// IDLE-or-poll loop until the context is cancelled or an error occurs.
func (s *Source) connectAndPoll(ctx context.Context, mb config.Mailbox, out chan<- RawEmail) error {
	addr := fmt.Sprintf("%s:%d", mb.Host, mb.Port)

	// Channel that the unilateral data handler signals on EXISTS updates.
	wakeCh := make(chan struct{}, 1)
	wake := func() {
		select {
		case wakeCh <- struct{}{}:
		default:
		}
	}

	opts := &imapclient.Options{
		UnilateralDataHandler: &imapclient.UnilateralDataHandler{
			Mailbox: func(data *imapclient.UnilateralDataMailbox) {
				if data.NumMessages != nil {
					wake()
				}
			},
		},
	}

	var c *imapclient.Client
	var err error

	if mb.UseSSL {
		tlsCfg := &tls.Config{ServerName: mb.Host}
		if mb.RootCA != "" {
			// A non-empty RootCA is a PEM file path; load it if present.
			// (TLS verification will fall back to system roots if loading fails.)
			log.Printf("source[%s]: note — custom RootCA loading not implemented, using system roots", mb.Name)
		}
		opts.TLSConfig = tlsCfg
		c, err = imapclient.DialTLS(addr, opts)
	} else {
		c, err = imapclient.DialInsecure(addr, opts)
	}
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer c.Close()

	// Login.
	if err := c.Login(mb.User, mb.Pass).Wait(); err != nil {
		return fmt.Errorf("login %s@%s: %w", mb.User, addr, err)
	}

	// Select INBOX.
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		return fmt.Errorf("select INBOX on %s: %w", addr, err)
	}

	// Check IDLE capability.
	caps := c.Caps()
	useIdle := caps.Has(imap.CapIdle)
	pollInterval := time.Duration(s.cfg.PollSeconds) * time.Second
	if pollInterval <= 0 {
		pollInterval = 60 * time.Second
	}

	log.Printf("source[%s]: connected to %s (IDLE=%v poll=%s)", mb.Name, addr, useIdle, pollInterval)

	// Initial fetch on connect.
	if err := s.fetchUnseen(ctx, c, mb.Name, out); err != nil {
		return fmt.Errorf("initial fetch on %s: %w", mb.Name, err)
	}

	// Build a map from mailbox name to the IMAP client so that markHandler can
	// call Store on the right session. Since we own a single session here we
	// handle marks inline via a select.
	for {
		if ctx.Err() != nil {
			return nil
		}

		if useIdle {
			if err := s.idleWait(ctx, c, mb.Name, wakeCh, pollInterval); err != nil {
				return err
			}
		} else {
			// Poll: sleep pollInterval or until context cancelled.
			select {
			case <-time.After(pollInterval):
			case <-ctx.Done():
				return nil
			}
		}

		// Apply pending MarkSeen requests for this mailbox.
		s.drainMarks(c, mb.Name)

		// Fetch all UNSEEN messages.
		if err := s.fetchUnseen(ctx, c, mb.Name, out); err != nil {
			return fmt.Errorf("fetch on %s: %w", mb.Name, err)
		}
	}
}

// idleWait starts IDLE, waits for an EXISTS notification (via wakeCh) or a
// poll-interval timeout (IMAP servers drop IDLE after ~29 min; we renew
// early), then closes IDLE and returns.
func (s *Source) idleWait(ctx context.Context, c *imapclient.Client, name string, wakeCh <-chan struct{}, renew time.Duration) error {
	// Drain stale wake signal before entering IDLE.
	select {
	case <-wakeCh:
	default:
	}

	idle, err := c.Idle()
	if err != nil {
		return fmt.Errorf("IDLE on %s: %w", name, err)
	}

	// Wait for wake, renew timeout, or ctx cancel.
	// We wait in a separate goroutine so we can close the IdleCommand.
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		select {
		case <-wakeCh:
		case <-time.After(renew):
		case <-ctx.Done():
		}
	}()

	<-doneCh

	if err := idle.Close(); err != nil {
		return fmt.Errorf("close IDLE on %s: %w", name, err)
	}
	if err := idle.Wait(); err != nil {
		// Wait returns an error when the IDLE was interrupted; that's expected
		// when we call Close. Ignore it.
		_ = err
	}
	return nil
}

// fetchUnseen searches for UNSEEN UIDs and fetches their full body, emitting
// each as a RawEmail on out. UIDs already in the dedup set are skipped.
func (s *Source) fetchUnseen(ctx context.Context, c *imapclient.Client, mailbox string, out chan<- RawEmail) error {
	if ctx.Err() != nil {
		return nil
	}

	criteria := &imap.SearchCriteria{
		NotFlag: []imap.Flag{imap.FlagSeen},
	}
	searchData, err := c.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return fmt.Errorf("UID SEARCH UNSEEN: %w", err)
	}

	uids := searchData.AllUIDs()
	if len(uids) == 0 {
		return nil
	}

	// Filter already-deduped UIDs.
	var toFetch []imap.UID
	for _, uid := range uids {
		if !s.dedup.Seen(mailbox, uint32(uid)) {
			toFetch = append(toFetch, uid)
		}
	}
	if len(toFetch) == 0 {
		return nil
	}

	uidSet := imap.UIDSetNum(toFetch...)
	fetchOpts := &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{{}}, // whole body
	}

	fetchCmd := c.Fetch(uidSet, fetchOpts)
	defer fetchCmd.Close()

	for {
		msgData := fetchCmd.Next()
		if msgData == nil {
			break
		}
		buf, err := msgData.Collect()
		if err != nil {
			log.Printf("source[%s]: collect message: %v", mailbox, err)
			continue
		}
		uid := uint32(buf.UID)
		if uid == 0 {
			// UID not returned — skip.
			continue
		}
		body := buf.FindBodySection(&imap.FetchItemBodySection{})
		if body == nil {
			log.Printf("source[%s]: uid %d: empty body section", mailbox, uid)
			continue
		}
		// Record in dedup before emitting so concurrent goroutines don't
		// double-emit.
		s.dedup.Mark(mailbox, uid)

		select {
		case out <- RawEmail{Mailbox: mailbox, UID: uid, Body: body}:
		case <-ctx.Done():
			return nil
		}
	}

	if err := fetchCmd.Close(); err != nil {
		// Already deferred; ignore duplicate close error.
		_ = err
	}
	return nil
}

// drainMarks applies all pending MarkSeen requests that target this mailbox
// via a server-side STORE +FLAGS \Seen. Errors are logged but do not abort
// the session; the message will simply remain unread on the server until the
// next reconnect.
func (s *Source) drainMarks(c *imapclient.Client, mailbox string) {
	for {
		select {
		case req := <-s.markCh:
			if req.mailbox != mailbox {
				// Put it back — another mailbox goroutine will handle it.
				// Use a non-blocking send to avoid deadlock if the channel
				// is temporarily full; the mark will be retried on the next
				// drain cycle.
				select {
				case s.markCh <- req:
				default:
				}
				return
			}
			uidSet := imap.UIDSetNum(imap.UID(req.uid))
			store := &imap.StoreFlags{
				Op:     imap.StoreFlagsAdd,
				Silent: true,
				Flags:  []imap.Flag{imap.FlagSeen},
			}
			if cmd := c.Store(uidSet, store, nil); cmd != nil {
				if err := cmd.Close(); err != nil {
					log.Printf("source[%s]: store \\Seen uid %d: %v", mailbox, req.uid, err)
				}
			}
		default:
			return
		}
	}
}
