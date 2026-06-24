package source

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
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

// Delivery pairs a RawEmail with a MarkSeen callback. The callback, when
// called, enqueues a \Seen flag request to the per-mailbox goroutine that owns
// the IMAP session for this message. The send is blocking so no mark is ever
// silently dropped.
type Delivery struct {
	Raw      RawEmail
	MarkSeen func()
}

// Source connects to one or more IMAP mailboxes and emits new messages as
// Delivery values. For each mailbox it tries IDLE if the server advertises
// the capability; otherwise it falls back to polling every PollSeconds.
// Errors cause an exponential-backoff reconnect loop; the caller must drain
// the out channel to avoid blocking the source goroutines.
type Source struct {
	cfg   config.Config
	dedup *Dedup
}

// New creates a Source from the given config and an optional external Dedup.
// If dedup is nil a default Dedup with a 10 000-entry window is created.
func New(cfg config.Config, dedup *Dedup) *Source {
	if dedup == nil {
		dedup = NewDedup(10_000)
	}
	return &Source{
		cfg:   cfg,
		dedup: dedup,
	}
}

// Run starts one goroutine per enabled mailbox and blocks until ctx is
// cancelled. Each goroutine connects to its mailbox, selects INBOX, and
// enters an IDLE-or-poll loop. On wake it searches for UNSEEN messages,
// fetches their bodies, records them in the dedup set, and emits them on out.
// \Seen is applied only after the consumer calls Delivery.MarkSeen.
// Reconnects use exponential backoff (1 s … 5 min).
func (s *Source) Run(ctx context.Context, out chan<- Delivery) {
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
func (s *Source) runMailbox(ctx context.Context, mb config.Mailbox, out chan<- Delivery) {
	backoff := time.Second
	const maxBackoff = 5 * time.Minute

	// Per-mailbox mark channel. The IMAP session goroutine drains this channel
	// and applies STORE +FLAGS \Seen. Sized generously so that a burst of
	// handled messages never stalls the consumer; the consumer does a blocking
	// send so no mark is dropped.
	markCh := make(chan uint32, 512)

	for {
		if ctx.Err() != nil {
			return
		}
		err := s.connectAndPoll(ctx, mb, out, markCh)
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
// markCh is the per-mailbox channel used to receive UIDs that should be
// flagged \Seen; it is owned by the runMailbox goroutine and drained here.
func (s *Source) connectAndPoll(ctx context.Context, mb config.Mailbox, out chan<- Delivery, markCh chan uint32) error {
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
			// Load custom CA certificate from PEM file into a dedicated pool.
			pem, readErr := os.ReadFile(mb.RootCA)
			if readErr != nil {
				log.Printf("source[%s]: cannot read RootCA %q: %v — falling back to system roots", mb.Name, mb.RootCA, readErr)
			} else {
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(pem) {
					log.Printf("source[%s]: RootCA %q contained no valid PEM certificates — falling back to system roots", mb.Name, mb.RootCA)
				} else {
					tlsCfg.RootCAs = pool
				}
			}
		}
		if mb.CertFile != "" && mb.KeyFile != "" {
			// Load mTLS client certificate + private key.
			cert, certErr := tls.LoadX509KeyPair(mb.CertFile, mb.KeyFile)
			if certErr != nil {
				log.Printf("source[%s]: cannot load client cert (%q / %q): %v — proceeding without mTLS", mb.Name, mb.CertFile, mb.KeyFile, certErr)
			} else {
				tlsCfg.Certificates = []tls.Certificate{cert}
			}
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
	if err := s.fetchUnseen(ctx, c, mb, out, markCh); err != nil {
		return fmt.Errorf("initial fetch on %s: %w", mb.Name, err)
	}

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
		drainMarks(c, mb.Name, markCh)

		// Fetch all UNSEEN messages.
		if err := s.fetchUnseen(ctx, c, mb, out, markCh); err != nil {
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
// each as a Delivery on out. UIDs already in the dedup set are skipped.
// The Delivery's MarkSeen closure does a blocking send to markCh so the
// per-mailbox IMAP goroutine can apply STORE +FLAGS \Seen without any mark
// being silently dropped.
func (s *Source) fetchUnseen(ctx context.Context, c *imapclient.Client, mb config.Mailbox, out chan<- Delivery, markCh chan<- uint32) error {
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
		if !s.dedup.Seen(mb.Name, uint32(uid)) {
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
			log.Printf("source[%s]: collect message: %v", mb.Name, err)
			continue
		}
		uid := uint32(buf.UID)
		if uid == 0 {
			// UID not returned — skip.
			continue
		}
		body := buf.FindBodySection(&imap.FetchItemBodySection{})
		if body == nil {
			log.Printf("source[%s]: uid %d: empty body section", mb.Name, uid)
			continue
		}
		// Record in dedup before emitting so concurrent goroutines don't
		// double-emit.
		s.dedup.Mark(mb.Name, uid)

		// Capture uid for the closure.
		capturedUID := uid
		d := Delivery{
			Raw: RawEmail{Mailbox: mb.Name, UID: uid, Body: body},
			// MarkSeen does a blocking send to the per-mailbox channel owned by
			// the runMailbox goroutine. The blocking send guarantees the mark is
			// never silently dropped: if the channel is full, the consumer pauses
			// until the IMAP goroutine drains it, which it does on every poll/IDLE
			// cycle. Capacity 512 means a burst of 512 messages can be enqueued
			// before any backpressure is felt.
			MarkSeen: func() {
				markCh <- capturedUID
			},
		}
		select {
		case out <- d:
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

// drainMarks applies all pending MarkSeen UIDs from the per-mailbox markCh
// via a server-side STORE +FLAGS \Seen. Errors are logged but do not abort
// the session; the message will simply remain unread on the server until the
// next reconnect. This function is called with the IMAP client for the mailbox
// that owns markCh.
func drainMarks(c *imapclient.Client, mailbox string, markCh <-chan uint32) {
	for {
		select {
		case uid := <-markCh:
			uidSet := imap.UIDSetNum(imap.UID(uid))
			store := &imap.StoreFlags{
				Op:     imap.StoreFlagsAdd,
				Silent: true,
				Flags:  []imap.Flag{imap.FlagSeen},
			}
			if cmd := c.Store(uidSet, store, nil); cmd != nil {
				if err := cmd.Close(); err != nil {
					log.Printf("source[%s]: store \\Seen uid %d: %v", mailbox, uid, err)
				}
			}
		default:
			return
		}
	}
}
