// Package config handles loading, merging, and validating the email-feeder
// configuration. Config can be sourced from a local JSON file and optionally
// enriched with shared settings fetched from the backend /api/config/feeder/
// endpoint (S3, SMTP, branding). On API failure the last-good merged JSON is
// read from a .cache file written next to the local file.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/pipeline"
)

// S3Config holds MinIO / S3-compatible object storage settings.
type S3Config struct {
	Endpoint     string `json:"endpoint"`
	AccessKey    string `json:"access_key"`
	SecretKey    string `json:"secret_key"`
	Region       string `json:"region"`
	FeederBucket string `json:"feeder_bucket"`
	Secure       bool   `json:"secure"`
	PathStyle    bool   `json:"path_style"`
}

// SMTPConfig holds outbound mail relay settings.
type SMTPConfig struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	TLS      bool   `json:"tls"`
}

// Mailbox represents one IMAP account to poll. Name is used as a stable key
// for hot-reload diffing; all other fields drive the IMAP connection.
type Mailbox struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Pass     string `json:"pass"`
	UseSSL   bool   `json:"use_ssl"`
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
	RootCA   string `json:"root_ca,omitempty"`
	Enable   bool   `json:"enable"`
}

// Config is the root configuration for the Go email-feeder.
//
// Local JSON shape (config.json):
//
//	{
//	  "mailboxes": [ { "name":"...", "host":"...", "port":993, "user":"...",
//	                   "pass":"...", "use_ssl":true, "enable":true } ],
//	  "s3":         { "endpoint":"...", "access_key":"...", "secret_key":"...",
//	                  "region":"us-east-1", "feeder_bucket":"feeder",
//	                  "secure":true, "path_style":false },
//	  "smtp":        { "server":"...", "port":587, "username":"...",
//	                   "password":"...", "tls":true },
//	  "caps":        { "max_attachment_bytes":10485760, "max_attachments":5,
//	                   "max_total_bytes":52428800 },
//	  "poll_seconds": 60,
//	  "ack_allowlist": ["user@example.com"]
//	}
//
// Fields under "s3", "smtp", and "ack_allowlist" may be omitted from the
// local file and instead populated by the backend /api/config/feeder/ merge.
type Config struct {
	Mailboxes    []Mailbox      `json:"mailboxes"`
	S3           S3Config       `json:"s3"`
	SMTP         SMTPConfig     `json:"smtp"`
	Caps         pipeline.Caps  `json:"caps"`
	PollSeconds  int            `json:"poll_seconds"`
	AckAllowlist []string       `json:"ack_allowlist"`
}

// --------------------------------------------------------------------------
// DiffMailboxes — pure hot-reload helper
// --------------------------------------------------------------------------

// changed returns true when any connection-relevant field differs between two
// Mailbox values with the same Name (excluding Enable itself).
func changed(a, b Mailbox) bool {
	return a.Host != b.Host || a.Port != b.Port || a.User != b.User || a.Pass != b.Pass ||
		a.UseSSL != b.UseSSL || a.CertFile != b.CertFile || a.KeyFile != b.KeyFile || a.RootCA != b.RootCA
}

// DiffMailboxes computes the hot-reload delta between two mailbox slices.
//
// start: mailboxes present in neu with Enable==true that are either absent
// from old, were disabled in old, or have different connection settings.
//
// stop: mailboxes in old with Enable==true that are absent or disabled in neu.
func DiffMailboxes(old, neu []Mailbox) (start, stop []Mailbox) {
	oldByName := make(map[string]Mailbox, len(old))
	for _, m := range old {
		oldByName[m.Name] = m
	}
	newByName := make(map[string]Mailbox, len(neu))
	for _, m := range neu {
		newByName[m.Name] = m
		o, existed := oldByName[m.Name]
		if m.Enable && (!existed || !o.Enable || changed(o, m)) {
			start = append(start, m)
		}
	}
	for _, o := range old {
		n, ok := newByName[o.Name]
		if o.Enable && (!ok || !n.Enable) {
			stop = append(stop, o)
		}
	}
	return start, stop
}

// --------------------------------------------------------------------------
// Load
// --------------------------------------------------------------------------

// apiResponse mirrors the relevant subset of the backend /api/config/feeder/
// JSON response, which follows the settings.json nested shape:
//
//	{
//	  "storage": { "s3": { "endpoint":"...", "access_key":"...",
//	                        "secret_key":"...", "region":"...",
//	                        "feeder_bucket":"...", "secure":true,
//	                        "path_style":false } },
//	  "email":   { "smtp": { "server":"...", "port":587, "username":"...",
//	                          "password":"...", "tls":true },
//	               "content": { "ack_allowlist": [...] } }
//	}
//
// Only the fields needed by the feeder are decoded; extra fields are ignored.
type apiResponse struct {
	Storage struct {
		S3 struct {
			Endpoint     string `json:"endpoint"`
			AccessKey    string `json:"access_key"`
			SecretKey    string `json:"secret_key"`
			Region       string `json:"region"`
			FeederBucket string `json:"feeder_bucket"`
			Secure       bool   `json:"secure"`
			PathStyle    bool   `json:"path_style"`
		} `json:"s3"`
	} `json:"storage"`
	Email struct {
		SMTP struct {
			Server   string `json:"server"`
			Port     int    `json:"port"`
			Username string `json:"username"`
			Password string `json:"password"`
			TLS      bool   `json:"tls"`
		} `json:"smtp"`
		Content struct {
			AckAllowlist []string `json:"ack_allowlist"`
		} `json:"content"`
	} `json:"email"`
}

// mergeAPI overlays non-zero API fields onto cfg in place.
func mergeAPI(cfg *Config, api apiResponse) {
	s3 := api.Storage.S3
	if s3.Endpoint != "" {
		cfg.S3.Endpoint = s3.Endpoint
	}
	if s3.AccessKey != "" {
		cfg.S3.AccessKey = s3.AccessKey
	}
	if s3.SecretKey != "" {
		cfg.S3.SecretKey = s3.SecretKey
	}
	if s3.Region != "" {
		cfg.S3.Region = s3.Region
	}
	if s3.FeederBucket != "" {
		cfg.S3.FeederBucket = s3.FeederBucket
	}
	// bool fields: always overlay (false is a valid configured value, but
	// the API is authoritative for these when it responds successfully).
	cfg.S3.Secure = s3.Secure
	cfg.S3.PathStyle = s3.PathStyle

	smtp := api.Email.SMTP
	if smtp.Server != "" {
		cfg.SMTP.Server = smtp.Server
	}
	if smtp.Port != 0 {
		cfg.SMTP.Port = smtp.Port
	}
	if smtp.Username != "" {
		cfg.SMTP.Username = smtp.Username
	}
	if smtp.Password != "" {
		cfg.SMTP.Password = smtp.Password
	}
	cfg.SMTP.TLS = smtp.TLS

	if len(api.Email.Content.AckAllowlist) > 0 {
		cfg.AckAllowlist = api.Email.Content.AckAllowlist
	}
}

// Load reads the local JSON file at path into a *Config.
//
// If apiURL and token are both non-empty, it GETs apiURL+"/api/config/feeder/"
// with an Authorization: Token <token> header and a 10 s timeout.  On success
// the S3, SMTP, and AckAllowlist fields from the response are merged into the
// config and the merged JSON is written to path+".cache" (mode 0600) for use
// as a fallback.  On HTTP failure the cache file is consulted; if it exists
// the previously merged config is returned, otherwise the file-only config is
// returned without error (the local file is still the fallback-of-last-resort).
//
// After merge (or on file-only load) the config is validated:
//   - at least one Mailbox with Enable==true
//   - S3.FeederBucket is non-empty
func Load(path, apiURL, token string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	cachePath := path + ".cache"

	if apiURL != "" && token != "" {
		apiCfg, apiErr := fetchAPI(apiURL, token)
		if apiErr == nil {
			mergeAPI(&cfg, apiCfg)
			// Write merged config to cache file (0600).
			merged, _ := json.Marshal(&cfg)
			_ = os.WriteFile(cachePath, merged, 0o600)
		} else {
			// API failed: try the cache.
			if cacheRaw, readErr := os.ReadFile(cachePath); readErr == nil {
				var cached Config
				if jsonErr := json.Unmarshal(cacheRaw, &cached); jsonErr == nil {
					cfg = cached
				}
				// If the cache is corrupt, fall through with file-only cfg.
			}
			// No cache or corrupt cache: continue with file-only config.
		}
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// fetchAPI performs the HTTP GET to the backend config endpoint.
func fetchAPI(apiURL, token string) (apiResponse, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, apiURL+"/api/config/feeder/", nil)
	if err != nil {
		return apiResponse{}, fmt.Errorf("config: build request: %w", err)
	}
	req.Header.Set("Authorization", "Token "+token)
	resp, err := client.Do(req)
	if err != nil {
		return apiResponse{}, fmt.Errorf("config: GET /api/config/feeder/: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return apiResponse{}, fmt.Errorf("config: GET /api/config/feeder/ returned %d", resp.StatusCode)
	}
	var api apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&api); err != nil {
		return apiResponse{}, fmt.Errorf("config: decode API response: %w", err)
	}
	return api, nil
}

// validate enforces the minimum viable config invariants.
func validate(cfg *Config) error {
	hasEnabled := false
	for _, m := range cfg.Mailboxes {
		if m.Enable {
			hasEnabled = true
			break
		}
	}
	var errs []error
	if !hasEnabled {
		errs = append(errs, errors.New("config: at least one mailbox must have enable=true"))
	}
	if cfg.S3.FeederBucket == "" {
		errs = append(errs, errors.New("config: s3.feeder_bucket must not be empty"))
	}
	return errors.Join(errs...)
}
