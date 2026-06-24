package sink

import (
	"bytes"
	"context"

	"github.com/minio/minio-go/v7"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/contract"
	"github.com/thalesgroup-cert/suspicious/email-feeder-go/internal/pipeline"
)

type Putter interface {
	EnsureBucket(ctx context.Context) error
	PutObject(ctx context.Context, key string, body []byte, contentType string) error
}

type Sink struct {
	Bucket string
	P      Putter
}

func (s *Sink) Store(ctx context.Context, sub *pipeline.Submission) error {
	if err := s.P.EnsureBucket(ctx); err != nil {
		return err
	}
	for _, o := range sub.Objects {
		if err := s.P.PutObject(ctx, o.Key, o.Body, "application/octet-stream"); err != nil {
			return err
		}
	}
	raw, err := sub.Status.Marshal()
	if err != nil {
		return err
	}
	// _status.json LAST — readers skip prefixes without it.
	return s.P.PutObject(ctx, sub.ID+"/"+contract.StatusObjectName, raw, "application/json")
}

type minioPutter struct {
	c      *minio.Client
	bucket string
}

func NewMinioPutter(c *minio.Client, bucket string) Putter { return &minioPutter{c: c, bucket: bucket} }

func (m *minioPutter) EnsureBucket(ctx context.Context) error {
	ok, err := m.c.BucketExists(ctx, m.bucket)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	return m.c.MakeBucket(ctx, m.bucket, minio.MakeBucketOptions{})
}

func (m *minioPutter) PutObject(ctx context.Context, key string, body []byte, ct string) error {
	_, err := m.c.PutObject(ctx, m.bucket, key, bytes.NewReader(body), int64(len(body)),
		minio.PutObjectOptions{ContentType: ct})
	return err
}
