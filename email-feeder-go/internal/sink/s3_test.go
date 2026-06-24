package sink

import (
	"context"
	"strings"
	"testing"

	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/contract"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/pipeline"
)

type fakePutter struct{ order []string }

func (f *fakePutter) EnsureBucket(ctx context.Context) error { f.order = append(f.order, "ensure"); return nil }
func (f *fakePutter) PutObject(ctx context.Context, key string, body []byte, ct string) error {
	f.order = append(f.order, key)
	return nil
}

func TestStoreWritesStatusLast(t *testing.T) {
	fp := &fakePutter{}
	s := &Sink{Bucket: "feeder", P: fp}
	sub := &pipeline.Submission{
		ID:      "260326141159-aaa",
		Objects: []pipeline.Object{{Key: "260326141159-aaa/jane-submission.eml", Body: []byte("w")}},
		Status:  contract.Status{Schema: 1, Status: contract.StatusTodo, SubmissionID: "260326141159-aaa"},
	}
	if err := s.Store(context.Background(), sub); err != nil {
		t.Fatal(err)
	}
	last := fp.order[len(fp.order)-1]
	if !strings.HasSuffix(last, contract.StatusObjectName) {
		t.Fatalf("last write must be _status.json, got %q", last)
	}
	if fp.order[0] != "ensure" {
		t.Fatalf("bucket must be ensured first, got %q", fp.order[0])
	}
}
