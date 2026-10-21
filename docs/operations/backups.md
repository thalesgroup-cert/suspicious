# Backups

## Database (MariaDB)

```bash
make backup-db              # write a timestamped dump
make restore-db f=<file>    # restore from a dump
```

## Object storage

Artifacts and attachments live in the `rustfs` S3 bucket
(`storage.s3.media_bucket`). Back it up with your S3 client of choice against
the configured endpoint.

## Elasticsearch, ChromaDB and Redis

Elasticsearch and ChromaDB data are rebuildable (search index: `python manage.py
reindex_cases`; similarity store: refilled as cases are processed). Redis holds
no durable data (task queue and cache only). Back up `.env` and `.env.data`
with your other secrets: they contain the service credentials.
