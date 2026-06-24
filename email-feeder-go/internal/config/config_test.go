package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// DiffMailboxes — from brief
// ---------------------------------------------------------------------------

func mb(name string, enable bool) Mailbox { return Mailbox{Name: name, Enable: enable} }

func TestDiffMailboxes(t *testing.T) {
	old := []Mailbox{mb("a", true), mb("b", true)}
	neu := []Mailbox{mb("a", true), mb("c", true), mb("b", false)}
	start, stop := DiffMailboxes(old, neu)
	if len(start) != 1 || start[0].Name != "c" {
		t.Fatalf("start=%v", start)
	}
	// b disabled -> stop; a unchanged -> neither
	names := map[string]bool{}
	for _, m := range stop {
		names[m.Name] = true
	}
	if !names["b"] {
		t.Fatalf("expected b stopped, stop=%v", stop)
	}
}

// Extra DiffMailboxes cases ---------------------------------------------------

func TestDiffMailboxes_ConnectionChange(t *testing.T) {
	old := []Mailbox{{Name: "x", Host: "old-host", Enable: true}}
	neu := []Mailbox{{Name: "x", Host: "new-host", Enable: true}}
	start, stop := DiffMailboxes(old, neu)
	if len(start) != 1 || start[0].Name != "x" {
		t.Fatalf("expected x in start (connection changed), got start=%v stop=%v", start, stop)
	}
	if len(stop) != 0 {
		t.Fatalf("expected empty stop, got %v", stop)
	}
}

func TestDiffMailboxes_NewlyEnabled(t *testing.T) {
	old := []Mailbox{mb("y", false)}
	neu := []Mailbox{mb("y", true)}
	start, stop := DiffMailboxes(old, neu)
	if len(start) != 1 || start[0].Name != "y" {
		t.Fatalf("newly enabled mailbox should start, got start=%v", start)
	}
	if len(stop) != 0 {
		t.Fatalf("expected empty stop, got %v", stop)
	}
}

func TestDiffMailboxes_Removed(t *testing.T) {
	old := []Mailbox{mb("z", true)}
	neu := []Mailbox{}
	start, stop := DiffMailboxes(old, neu)
	if len(start) != 0 {
		t.Fatalf("expected empty start, got %v", start)
	}
	if len(stop) != 1 || stop[0].Name != "z" {
		t.Fatalf("removed mailbox should stop, got stop=%v", stop)
	}
}

// ---------------------------------------------------------------------------
// Load — helpers
// ---------------------------------------------------------------------------

func writeJSON(t *testing.T, dir, name string, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func minimalConfig(bucket string) Config {
	return Config{
		Mailboxes: []Mailbox{{Name: "inbox", Enable: true}},
		S3:        S3Config{FeederBucket: bucket},
	}
}

// ---------------------------------------------------------------------------
// Load — file-only path
// ---------------------------------------------------------------------------

func TestLoad_FileOnly_Valid(t *testing.T) {
	dir := t.TempDir()
	p := writeJSON(t, dir, "config.json", minimalConfig("mybucket"))
	cfg, err := Load(p, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.S3.FeederBucket != "mybucket" {
		t.Fatalf("bucket=%q", cfg.S3.FeederBucket)
	}
}

func TestLoad_FileOnly_ValidationError_NoEnabledMailbox(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Mailboxes: []Mailbox{{Name: "inbox", Enable: false}},
		S3:        S3Config{FeederBucket: "bucket"},
	}
	p := writeJSON(t, dir, "config.json", cfg)
	_, err := Load(p, "", "")
	if err == nil {
		t.Fatal("expected validation error for no enabled mailbox")
	}
}

func TestLoad_FileOnly_ValidationError_EmptyBucket(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Mailboxes: []Mailbox{{Name: "inbox", Enable: true}},
		S3:        S3Config{FeederBucket: ""},
	}
	p := writeJSON(t, dir, "config.json", cfg)
	_, err := Load(p, "", "")
	if err == nil {
		t.Fatal("expected validation error for empty feeder_bucket")
	}
}

// ---------------------------------------------------------------------------
// Load — API merge happy path
// ---------------------------------------------------------------------------

func TestLoad_APIMerge_HappyPath(t *testing.T) {
	// Serve a fake /api/config/feeder/ response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/config/feeder/" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Token test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Return settings.json-shaped response with S3 + SMTP + ack_allowlist.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"storage": map[string]any{
				"s3": map[string]any{
					"endpoint":      "minio.example.com",
					"access_key":    "AKID",
					"secret_key":    "SECRET",
					"region":        "eu-west-1",
					"feeder_bucket": "api-bucket",
					"secure":        true,
					"path_style":    false,
				},
			},
			"email": map[string]any{
				"smtp": map[string]any{
					"server":   "smtp.example.com",
					"port":     587,
					"username": "feeder@example.com",
					"password": "smtppass",
					"tls":      true,
				},
				"content": map[string]any{
					"ack_allowlist": []string{"admin@example.com"},
				},
			},
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	// Local file: has a valid enabled mailbox but no S3 bucket (will come from API).
	local := Config{
		Mailboxes: []Mailbox{{Name: "inbox", Enable: true}},
		S3:        S3Config{FeederBucket: ""},    // will be filled by API
		PollSeconds: 60,
	}
	p := writeJSON(t, dir, "config.json", local)

	cfg, err := Load(p, srv.URL, "test-token")
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if cfg.S3.FeederBucket != "api-bucket" {
		t.Errorf("feeder_bucket=%q, want api-bucket", cfg.S3.FeederBucket)
	}
	if cfg.S3.Endpoint != "minio.example.com" {
		t.Errorf("endpoint=%q", cfg.S3.Endpoint)
	}
	if cfg.S3.SecretKey != "SECRET" {
		t.Errorf("secret_key=%q", cfg.S3.SecretKey)
	}
	if cfg.SMTP.Server != "smtp.example.com" {
		t.Errorf("smtp.server=%q", cfg.SMTP.Server)
	}
	if len(cfg.AckAllowlist) != 1 || cfg.AckAllowlist[0] != "admin@example.com" {
		t.Errorf("ack_allowlist=%v", cfg.AckAllowlist)
	}

	// Cache file should have been written.
	cacheData, err := os.ReadFile(p + ".cache")
	if err != nil {
		t.Fatalf("cache not written: %v", err)
	}
	var cached Config
	if err := json.Unmarshal(cacheData, &cached); err != nil {
		t.Fatalf("cache not valid JSON: %v", err)
	}
	if cached.S3.FeederBucket != "api-bucket" {
		t.Errorf("cached feeder_bucket=%q", cached.S3.FeederBucket)
	}
}

// ---------------------------------------------------------------------------
// Load — API failure falls back to cache
// ---------------------------------------------------------------------------

func TestLoad_APIFailure_FallbackToCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	dir := t.TempDir()
	local := Config{
		Mailboxes: []Mailbox{{Name: "inbox", Enable: true}},
		S3:        S3Config{FeederBucket: "local-bucket"},
	}
	p := writeJSON(t, dir, "config.json", local)

	// Pre-write a cache with a different bucket.
	cachedCfg := local
	cachedCfg.S3.FeederBucket = "cached-bucket"
	cachedCfg.S3.Endpoint = "cached-endpoint"
	cacheData, _ := json.Marshal(cachedCfg)
	if err := os.WriteFile(p+".cache", cacheData, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	cfg, err := Load(p, srv.URL, "tok")
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if cfg.S3.FeederBucket != "cached-bucket" {
		t.Errorf("expected cached-bucket, got %q", cfg.S3.FeederBucket)
	}
}

// ---------------------------------------------------------------------------
// Load — API failure with no cache returns file-only config
// ---------------------------------------------------------------------------

func TestLoad_APIFailure_NoCache_FileOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	local := Config{
		Mailboxes: []Mailbox{{Name: "inbox", Enable: true}},
		S3:        S3Config{FeederBucket: "local-bucket"},
	}
	p := writeJSON(t, dir, "config.json", local)

	cfg, err := Load(p, srv.URL, "tok")
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if cfg.S3.FeederBucket != "local-bucket" {
		t.Errorf("expected local-bucket, got %q", cfg.S3.FeederBucket)
	}
}

// ---------------------------------------------------------------------------
// Load — bad token returns 403, falls back to local file
// ---------------------------------------------------------------------------

func TestLoad_APIMerge_BadToken_FallbackToLocal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	dir := t.TempDir()
	local := minimalConfig("local-bucket")
	p := writeJSON(t, dir, "config.json", local)

	cfg, err := Load(p, srv.URL, "wrong-token")
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if cfg.S3.FeederBucket != "local-bucket" {
		t.Errorf("expected local-bucket, got %q", cfg.S3.FeederBucket)
	}
}
