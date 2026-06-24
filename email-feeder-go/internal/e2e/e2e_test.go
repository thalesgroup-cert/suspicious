//go:build integration

// Package e2e contains end-to-end tests for the Go email-feeder.
//
// Tests in this file are excluded from `go test ./...` by default.
// They require external services (greenmail + rustfs/MinIO) to be running.
//
// # Manual setup
//
// Start the dev services from the Python feeder's compose file:
//
//	cd email-feeder   # the Python feeder directory
//	MINIO_ROOT_USER=minioadmin MINIO_ROOT_PASSWORD=minioadmin \
//	  docker compose -f docker-compose.dev.yaml up -d
//
// Then run the e2e tests:
//
//	cd email-feeder-go
//	go test -tags integration -v ./internal/e2e/ \
//	  -e2e.imap.addr=localhost:3143 \
//	  -e2e.imap.user=imap_user \
//	  -e2e.imap.pass=imap_password \
//	  -e2e.smtp.addr=localhost:3025 \
//	  -e2e.s3.endpoint=localhost:9000 \
//	  -e2e.s3.access=minioadmin \
//	  -e2e.s3.secret=minioadmin \
//	  -e2e.s3.bucket=feeder-e2e
//
// # Assertions
//
// For each email injected WITH a .eml attachment the test asserts:
//   - A S3 prefix matching `\d{12}-[a-f0-9]+` exists under the feeder bucket.
//   - `<prefix>/_status.json` exists and contains `"status":"todo"`.
//   - At least one `<prefix>/*submission.eml` object exists.
//
// For emails injected WITHOUT a .eml attachment the test asserts:
//   - NO matching prefix exists in S3 (ack-only path, nothing stored).
package e2e

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/app"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/config"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/contract"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/source"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/sink"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/pipeline"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/ack"
)

// ---------------------------------------------------------------------------
// Flags — allow overriding service addresses at test invocation time.
// ---------------------------------------------------------------------------

var (
	flagIMAPAddr   = flag.String("e2e.imap.addr", "localhost:3143", "greenmail IMAP address")
	flagIMAPUser   = flag.String("e2e.imap.user", "imap_user", "IMAP username")
	flagIMAPPass   = flag.String("e2e.imap.pass", "imap_password", "IMAP password")
	flagSMTPAddr   = flag.String("e2e.smtp.addr", "localhost:3025", "greenmail SMTP address (for injecting test emails)")
	flagS3Endpoint = flag.String("e2e.s3.endpoint", "localhost:9000", "rustfs/MinIO endpoint")
	flagS3Access   = flag.String("e2e.s3.access", "minioadmin", "S3 access key")
	flagS3Secret   = flag.String("e2e.s3.secret", "minioadmin", "S3 secret key")
	flagS3Bucket   = flag.String("e2e.s3.bucket", "feeder-e2e", "S3 bucket name")
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// injectEmail delivers msg to the greenmail IMAP mailbox via SMTP.
func injectEmail(t *testing.T, from, to, subject, body string) {
	t.Helper()
	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		from, to, subject, body,
	)
	if err := smtp.SendMail(*flagSMTPAddr, nil, from, []string{to}, []byte(msg)); err != nil {
		t.Fatalf("inject email via SMTP: %v", err)
	}
}

// multipartWithEML builds a multipart/mixed email body containing a .eml attachment.
func multipartWithEML(outerFrom, innerFrom, innerSubject, innerBody string) string {
	const boundary = "e2e-boundary-abc123"
	return fmt.Sprintf(
		"From: %s\r\n"+
			"Content-Type: multipart/mixed; boundary=%s\r\n\r\n"+
			"--%s\r\n"+
			"Content-Type: text/plain\r\n\r\n"+
			"Please analyse the attached email.\r\n"+
			"--%s\r\n"+
			"Content-Type: message/rfc822\r\n"+
			"Content-Disposition: attachment; filename=\"forwarded.eml\"\r\n\r\n"+
			"From: %s\r\nSubject: %s\r\n\r\n%s\r\n"+
			"--%s--\r\n",
		outerFrom,
		boundary, boundary, boundary,
		innerFrom, innerSubject, innerBody,
		boundary,
	)
}

// noopSender discards ack emails in tests (greenmail is already the recipient).
type noopSender struct{}

func (n *noopSender) Send(from string, to []string, msg []byte) error { return nil }

// listPrefixes returns all object keys in the bucket that start with prefix.
func listPrefixes(ctx context.Context, mc *minio.Client, bucket, prefix string) ([]string, error) {
	var keys []string
	for obj := range mc.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if obj.Err != nil {
			return nil, obj.Err
		}
		keys = append(keys, obj.Key)
	}
	return keys, nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestE2EFeederPipeline is the primary integration test. It:
//  1. Injects one email WITH a .eml attachment (valid submission) and one
//     WITHOUT (bad submission / ack-only) into greenmail via SMTP.
//  2. Runs Dispatch against an IMAP session and a real S3 bucket.
//  3. Asserts storage layout for the valid submission and absence of any S3
//     prefix for the bad submission.
//
// If any external service is unavailable the test skips with precise
// instructions for bringing the services up.
func TestE2EFeederPipeline(t *testing.T) {
	// -----------------------------------------------------------------------
	// 0. Verify services are reachable — skip with instructions if not.
	// -----------------------------------------------------------------------
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	mc, err := minio.New(*flagS3Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(*flagS3Access, *flagS3Secret, ""),
		Secure: false,
	})
	if err != nil {
		t.Skipf("cannot create MinIO client (%v). Start services with:\n"+
			"  cd email-feeder && MINIO_ROOT_USER=%s MINIO_ROOT_PASSWORD=%s "+
			"docker compose -f docker-compose.dev.yaml up -d\n"+
			"Then re-run: go test -tags integration -v ./internal/e2e/",
			err, *flagS3Access, *flagS3Secret)
	}

	// Probe S3 connectivity.
	if _, err := mc.ListBuckets(ctx); err != nil {
		t.Skipf("rustfs/MinIO not reachable at %s (%v). "+
			"Start services with:\n"+
			"  cd email-feeder && MINIO_ROOT_USER=%s MINIO_ROOT_PASSWORD=%s "+
			"docker compose -f docker-compose.dev.yaml up -d",
			*flagS3Endpoint, err, *flagS3Access, *flagS3Secret)
	}

	// -----------------------------------------------------------------------
	// 1. Ensure the test bucket exists.
	// -----------------------------------------------------------------------
	ok, err := mc.BucketExists(ctx, *flagS3Bucket)
	if err != nil {
		t.Fatalf("bucket exists check: %v", err)
	}
	if !ok {
		if err := mc.MakeBucket(ctx, *flagS3Bucket, minio.MakeBucketOptions{}); err != nil {
			t.Fatalf("make bucket: %v", err)
		}
	}

	// -----------------------------------------------------------------------
	// 2. Build feeder config pointing at greenmail + rustfs.
	// -----------------------------------------------------------------------
	imapParts := strings.SplitN(*flagIMAPAddr, ":", 2)
	imapHost := imapParts[0]
	imapPort := 3143
	if len(imapParts) == 2 {
		fmt.Sscanf(imapParts[1], "%d", &imapPort)
	}

	cfg := config.Config{
		PollSeconds: 2,
		Mailboxes: []config.Mailbox{
			{
				Name:   "e2e",
				Enable: true,
				Host:   imapHost,
				Port:   imapPort,
				User:   *flagIMAPUser,
				Pass:   *flagIMAPPass,
				UseSSL: false,
			},
		},
		S3: config.S3Config{
			Endpoint:     *flagS3Endpoint,
			AccessKey:    *flagS3Access,
			SecretKey:    *flagS3Secret,
			Secure:       false,
			FeederBucket: *flagS3Bucket,
		},
		Caps: pipeline.Caps{
			MaxAttachmentBytes: 1 << 20,
			MaxAttachments:     50,
			MaxTotalBytes:      1 << 21,
		},
	}

	sk := &sink.Sink{
		Bucket: cfg.S3.FeederBucket,
		P:      sink.NewMinioPutter(mc, cfg.S3.FeederBucket),
	}
	acker, err := ack.New("e2e-feeder@test.local", nil, &noopSender{})
	if err != nil {
		t.Fatalf("acker: %v", err)
	}

	// -----------------------------------------------------------------------
	// 3. Inject test emails via SMTP → greenmail.
	// -----------------------------------------------------------------------
	recipientAddr := *flagIMAPUser + "@localhost"

	// Valid submission: outer email with an attached .eml.
	validMsg := multipartWithEML(
		"reporter@corp.test",
		"phisher@evil.test",
		"Urgent: click here",
		"This is a phishing simulation.",
	)
	if err := smtp.SendMail(
		*flagSMTPAddr, nil,
		"reporter@corp.test",
		[]string{recipientAddr},
		[]byte(validMsg),
	); err != nil {
		t.Skipf("cannot inject email via SMTP at %s (%v). Is greenmail running?", *flagSMTPAddr, err)
	}

	// Bad submission: plain-text email with no attachment.
	badMsg := fmt.Sprintf(
		"From: reporter@corp.test\r\nTo: %s\r\nSubject: no attachment here\r\n\r\n"+
			"This email has no .eml attachment — feeder should ack only.",
		recipientAddr,
	)
	if err := smtp.SendMail(
		*flagSMTPAddr, nil,
		"reporter@corp.test",
		[]string{recipientAddr},
		[]byte(badMsg),
	); err != nil {
		t.Fatalf("inject bad email: %v", err)
	}

	// -----------------------------------------------------------------------
	// 4. Run the feeder Source + Dispatch against the live mailbox.
	// -----------------------------------------------------------------------
	dedup := source.NewDedup(1_000)
	src := source.New(cfg, dedup)

	runCtx, runCancel := context.WithTimeout(ctx, 30*time.Second)
	defer runCancel()

	deliveries := make(chan source.Delivery, 16)
	go src.Run(runCtx, deliveries)

	// Collect and dispatch deliveries until the mailbox is drained or timeout.
	var handled, errored int
	deadline := time.After(20 * time.Second)
loop:
	for {
		select {
		case d, ok := <-deliveries:
			if !ok {
				break loop
			}
			h, dispErr := app.Dispatch(runCtx, d.Raw, cfg.Caps, sk, acker, time.Now)
			if dispErr != nil {
				t.Logf("dispatch error uid=%d: %v", d.Raw.UID, dispErr)
				errored++
				continue
			}
			if h {
				dedup.Mark(d.Raw.Mailbox, d.Raw.UID)
				d.MarkSeen()
				handled++
			}
		case <-deadline:
			break loop
		case <-runCtx.Done():
			break loop
		}
	}
	runCancel()

	if errored > 0 {
		t.Errorf("dispatch errors: %d", errored)
	}
	if handled < 2 {
		t.Fatalf("expected at least 2 handled deliveries (valid + bad-ack), got %d", handled)
	}

	// -----------------------------------------------------------------------
	// 5. Assert S3 storage layout.
	// -----------------------------------------------------------------------

	// 5a. Expect exactly one submission prefix matching the UID pattern.
	keys, err := listPrefixes(ctx, mc, *flagS3Bucket, "")
	if err != nil {
		t.Fatalf("list S3 objects: %v", err)
	}

	// Collect unique prefixes matching \d{12}-[a-f0-9]+
	prefixSet := make(map[string]bool)
	for _, k := range keys {
		parts := strings.SplitN(k, "/", 2)
		if contract.EmailDirPattern.MatchString(parts[0]) {
			prefixSet[parts[0]] = true
		}
	}

	if len(prefixSet) != 1 {
		t.Errorf("expected exactly 1 submission prefix in S3, got %d: %v", len(prefixSet), prefixSet)
	}

	for prefix := range prefixSet {
		// 5b. _status.json must exist and contain status=todo.
		statusKey := prefix + "/" + contract.StatusObjectName
		obj, err := mc.GetObject(ctx, *flagS3Bucket, statusKey, minio.GetObjectOptions{})
		if err != nil {
			t.Fatalf("get _status.json for prefix %s: %v", prefix, err)
		}
		raw, err := io.ReadAll(obj)
		if err != nil {
			t.Fatalf("read _status.json: %v", err)
		}
		var status contract.Status
		if err := json.Unmarshal(raw, &status); err != nil {
			t.Fatalf("parse _status.json: %v", err)
		}
		if status.Status != contract.StatusTodo {
			t.Errorf("_status.json status: got %q, want %q", status.Status, contract.StatusTodo)
		}

		// 5c. At least one *submission.eml object must exist.
		subKeys, err := listPrefixes(ctx, mc, *flagS3Bucket, prefix+"/")
		if err != nil {
			t.Fatalf("list prefix %s: %v", prefix, err)
		}
		foundEML := false
		for _, k := range subKeys {
			if strings.HasSuffix(k, contract.SubmissionEMLSuffix) {
				foundEML = true
				break
			}
		}
		if !foundEML {
			t.Errorf("no *%s found under prefix %s; objects: %v", contract.SubmissionEMLSuffix, prefix, subKeys)
		}
	}

	t.Logf("e2e OK: %d deliveries handled; submission prefix(es): %v", handled, prefixSet)
}
