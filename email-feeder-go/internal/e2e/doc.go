// Package e2e contains end-to-end integration tests for the Go email-feeder.
// Tests are gated behind the "integration" build tag and require external
// services (greenmail + rustfs/MinIO) to be running.
//
// Run with:
//
//	go test -tags integration -v ./internal/e2e/
package e2e
