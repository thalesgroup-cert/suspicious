// Command feeder is the supervisor for the Go email-feeder service.
// It wires config, IMAP sources, MinIO sink, and the Dispatch pipeline.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/ack"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/app"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/config"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/sink"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/source"
)

// smtpSender implements ack.Sender via net/smtp.
// STARTTLS is always used (smtp.SendMail); implicit TLS is out of scope for now.
type smtpSender struct {
	addr string // host:port
	auth smtp.Auth
}

func newSMTPSender(cfg config.SMTPConfig) *smtpSender {
	addr := fmt.Sprintf("%s:%d", cfg.Server, cfg.Port)
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Server)
	}
	return &smtpSender{addr: addr, auth: auth}
}

func (s *smtpSender) Send(from string, to []string, msg []byte) error {
	return smtp.SendMail(s.addr, s.auth, from, to, msg)
}

// mailboxStatus tracks per-mailbox readiness for /health.
type mailboxStatus struct {
	mu      sync.RWMutex
	running map[string]bool
}

func newMailboxStatus() *mailboxStatus { return &mailboxStatus{running: make(map[string]bool)} }

func (ms *mailboxStatus) set(name string, up bool) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.running[name] = up
}

func (ms *mailboxStatus) snapshot() map[string]bool {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	out := make(map[string]bool, len(ms.running))
	for k, v := range ms.running {
		out[k] = v
	}
	return out
}

func main() {
	// JSON structured logging to stdout.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfgPath := os.Getenv("FEEDER_CONFIG")
	if cfgPath == "" {
		cfgPath = "/etc/feeder/config.json"
	}
	apiURL := os.Getenv("FEEDER_API_URL")
	apiToken := os.Getenv("FEEDER_API_TOKEN")

	cfg, err := config.Load(cfgPath, apiURL, apiToken)
	if err != nil {
		slog.Error("config load failed", "err", err)
		os.Exit(1)
	}

	// MinIO client.
	mc, err := minio.New(cfg.S3.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.S3.AccessKey, cfg.S3.SecretKey, ""),
		Secure: cfg.S3.Secure,
	})
	if err != nil {
		slog.Error("minio client init failed", "err", err)
		os.Exit(1)
	}

	sk := &sink.Sink{
		Bucket: cfg.S3.FeederBucket,
		P:      sink.NewMinioPutter(mc, cfg.S3.FeederBucket),
	}

	smtpS := newSMTPSender(cfg.SMTP)
	acker, err := ack.New(cfg.SMTP.Username, cfg.AckAllowlist, smtpS)
	if err != nil {
		slog.Error("acker init failed", "err", err)
		os.Exit(1)
	}

	dedup := source.NewDedup(10_000)
	mbStatus := newMailboxStatus()

	// Root context — SIGTERM cancels it.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// out carries Delivery values: each bundles a RawEmail with a MarkSeen
	// callback bound to the per-mailbox IMAP goroutine. Calling MarkSeen does
	// a blocking send to the mailbox-owned mark channel, ensuring no \Seen
	// flag is ever silently dropped.
	out := make(chan source.Delivery, 256)

	// cancelFuncs tracks per-mailbox cancel functions for hot-reload.
	type mbEntry struct {
		cancel context.CancelFunc
		name   string
	}
	var mu sync.Mutex
	active := make(map[string]mbEntry)

	startMailbox := func(mb config.Mailbox) {
		mbCtx, mbCancel := context.WithCancel(ctx)
		mu.Lock()
		active[mb.Name] = mbEntry{cancel: mbCancel, name: mb.Name}
		mu.Unlock()
		mbStatus.set(mb.Name, true)

		src := source.New(*cfg, dedup)
		go func() {
			defer func() {
				mbStatus.set(mb.Name, false)
				mu.Lock()
				delete(active, mb.Name)
				mu.Unlock()
			}()
			mbOut := make(chan source.Delivery, 64)
			go src.Run(mbCtx, mbOut)
			for {
				select {
				case d, ok := <-mbOut:
					if !ok {
						return
					}
					select {
					case out <- d:
					case <-mbCtx.Done():
						return
					}
				case <-mbCtx.Done():
					return
				}
			}
		}()
	}

	stopMailbox := func(name string) {
		mu.Lock()
		entry, ok := active[name]
		mu.Unlock()
		if ok {
			entry.cancel()
		}
		mbStatus.set(name, false)
	}

	// Start all enabled mailboxes.
	for i := range cfg.Mailboxes {
		if cfg.Mailboxes[i].Enable {
			startMailbox(cfg.Mailboxes[i])
		}
	}

	// Dispatch loop.
	// HandleDelivery does NOT consult any in-process dedup: the Source already
	// called dedup.Mark before emitting the Delivery, so the double-emit guard
	// lives entirely in the source layer. The cross-restart guard is the
	// server-side \Seen flag applied by HandleDelivery via d.MarkSeen().
	go func() {
		for {
			select {
			case d, ok := <-out:
				if !ok {
					return
				}
				if err := app.HandleDelivery(ctx, d, cfg.Caps, sk, acker, time.Now); err != nil {
					slog.Error("dispatch error", "mailbox", d.Raw.Mailbox, "uid", d.Raw.UID, "err", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// /health endpoint on :9091.
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		snap := mbStatus.snapshot()
		// Zero running mailboxes means the feeder is idle / misconfigured.
		allUp := len(snap) > 0
		for _, up := range snap {
			if !up {
				allUp = false
				break
			}
		}
		status := "ok"
		if !allUp {
			status = "degraded"
		}
		w.Header().Set("Content-Type", "application/json")
		if !allUp {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    status,
			"mailboxes": snap,
		})
	})
	healthSrv := &http.Server{Addr: ":9091", Handler: healthMux}
	go func() {
		if err := healthSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("health server error", "err", err)
		}
	}()

	// Signal handling: SIGHUP reload, SIGTERM shutdown.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM)

	for sig := range sigCh {
		switch sig {
		case syscall.SIGHUP:
			slog.Info("SIGHUP received — reloading config")
			newCfg, loadErr := config.Load(cfgPath, apiURL, apiToken)
			if loadErr != nil {
				slog.Error("config reload failed", "err", loadErr)
				continue
			}
			toStart, toStop := config.DiffMailboxes(cfg.Mailboxes, newCfg.Mailboxes)
			cfg = newCfg
			for _, mb := range toStop {
				slog.Info("stopping mailbox", "name", mb.Name)
				stopMailbox(mb.Name)
			}
			for _, mb := range toStart {
				slog.Info("starting mailbox", "name", mb.Name)
				startMailbox(mb)
			}

		case syscall.SIGTERM:
			slog.Info("SIGTERM received — shutting down")
			cancel()
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 15*time.Second)
			_ = healthSrv.Shutdown(shutCtx)
			shutCancel()
			return
		}
	}
}
