# gunicorn.conf.py
#
# Mount at: /app/gunicorn.conf.py  (read-only volume in compose_apps.yaml)
#
# Gunicorn replaces Django's runserver for production:
#   • Worker management with automatic restarts on crash
#   • Graceful reloads (SIGUSR2 / SIGWINCH) during rolling deploys
#   • Proper signal handling for Docker SIGTERM → graceful shutdown
#   • Access and error logs for log aggregators
#
# Reference: https://docs.gunicorn.org/en/stable/settings.html

import multiprocessing
import os

# ---------------------------------------------------------------------------
# Server socket
# ---------------------------------------------------------------------------

bind    = "0.0.0.0:9020"
backlog = 2048

# ---------------------------------------------------------------------------
# Workers
#
# Formula: (2 × CPU count) + 1 is the classic recommendation.
# For I/O-heavy Django apps (DB + external APIs), gthread workers can handle
# more concurrency per process without the gevent monkey-patching overhead.
#
# Tune via environment variables in compose_apps.yaml / .env:
#   GUNICORN_WORKERS=5
#   GUNICORN_WORKER_CLASS=gthread
#   GUNICORN_THREADS=4
# ---------------------------------------------------------------------------

workers      = int(os.getenv("GUNICORN_WORKERS", multiprocessing.cpu_count() * 2 + 1))
worker_class = os.getenv("GUNICORN_WORKER_CLASS", "sync")  # or "gthread"
threads      = int(os.getenv("GUNICORN_THREADS", 1))        # >1 only with gthread

# ---------------------------------------------------------------------------
# Timeouts
# ---------------------------------------------------------------------------

timeout          = 120  # seconds — covers long-running Cortex analysis requests
keepalive        = 5    # seconds for HTTP keep-alive connections
graceful_timeout = 30   # seconds after SIGTERM before a worker is force-killed

# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------

max_requests        = 1000  # restart worker after N requests (prevents memory leaks)
max_requests_jitter =  100  # randomise restart to avoid thundering-herd restarts

# ---------------------------------------------------------------------------
# Process naming
# ---------------------------------------------------------------------------

proc_name = "suspicious"

# ---------------------------------------------------------------------------
# Logging
#
# Write to stdout/stderr — Docker captures these via `docker logs`.
# The access log format includes response time in microseconds (%(D)s)
# so slow requests are immediately visible without a separate APM tool.
# ---------------------------------------------------------------------------

accesslog  = "-"
errorlog   = "-"
loglevel   = os.getenv("GUNICORN_LOG_LEVEL", "info")

access_log_format = (
    '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)sµs'
)

# ---------------------------------------------------------------------------
# Process management
# ---------------------------------------------------------------------------

# preload_app = False  ← critical for LDAP / DB connection safety
#
# preload_app=True loads Django once in the master process before fork().
# Workers then inherit the master's open file descriptors — including any
# LDAP connections or DB sockets opened at import time. Forked workers
# share those fds and race each other, causing:
#   • Corrupted LDAP responses (two workers reading the same socket)
#   • "SSL connection has been closed unexpectedly" from MariaDB
#   • Intermittent 500 errors under concurrent load
#
# With preload_app=False each worker initialises its own connections after
# forking cleanly. The RAM saving from copy-on-write is not worth these bugs.
preload_app = False

# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------

def on_starting(server):
    server.log.info("Suspicious (Gunicorn) starting — workers: %d", workers)

def post_fork(server, worker):
    # Explicitly close any inherited DB connections in the worker so Django
    # opens a fresh one. Defensive no-op if preload_app is False, but
    # harmless and protects against future accidental preload_app=True.
    try:
        from django.db import connections
        for conn in connections.all():
            conn.close()
    except Exception:
        pass

def worker_exit(server, worker):
    server.log.info("Worker %d exited (pid=%d)", worker.age, worker.pid)