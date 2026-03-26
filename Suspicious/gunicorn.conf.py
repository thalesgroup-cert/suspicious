# gunicorn.conf.py
# Gunicorn replaces Django's runserver for production:
#   • Worker management with automatic restarts on crash
#   • Graceful reloads (SIGUSR2 / SIGWINCH) during rolling deploys
#   • Proper signal handling for Docker SIGTERM → graceful shutdown
#   • Access and error logs in JSON-friendly format for log aggregators
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
# For I/O-heavy Django apps (DB + external APIs), gevent or gthread workers
# can handle more concurrency per process.
# Start with sync workers; switch to gthread if you see CPU under-utilisation.
# ---------------------------------------------------------------------------

workers     = int(os.getenv("GUNICORN_WORKERS", multiprocessing.cpu_count() * 2 + 1))
worker_class = os.getenv("GUNICORN_WORKER_CLASS", "sync")  # or "gthread"
threads      = int(os.getenv("GUNICORN_THREADS", 1))       # >1 only with gthread

# ---------------------------------------------------------------------------
# Timeouts
# ---------------------------------------------------------------------------

timeout       = 120   # seconds — increase if you have long-running analysis requests
keepalive     = 5     # seconds for HTTP keep-alive connections
graceful_timeout = 30 # seconds after SIGTERM before a worker is killed

# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------

max_requests       = 1000  # restart worker after N requests (avoids memory leaks)
max_requests_jitter = 100  # randomise restart to avoid thundering herd

# ---------------------------------------------------------------------------
# Process naming (visible in `ps aux`)
# ---------------------------------------------------------------------------

proc_name = "suspicious"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

# Write to stdout/stderr so Docker picks them up via docker logs.
accesslog  = "-"
errorlog   = "-"
loglevel   = os.getenv("GUNICORN_LOG_LEVEL", "info")

access_log_format = (
    '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)sµs'
)

# ---------------------------------------------------------------------------
# Process management
# ---------------------------------------------------------------------------

# Django's static file serving is handled by Whitenoise or Nginx/Traefik,
# not Gunicorn.  Set preload_app=True to share memory across workers (saves
# RAM) but disable it if your app uses multiprocessing or has per-worker
# state.
preload_app = True

# ---------------------------------------------------------------------------
# Hooks — optional lifecycle callbacks
# ---------------------------------------------------------------------------

def on_starting(server):
    server.log.info("Suspicious (Gunicorn) starting — workers: %d", workers)

def worker_exit(server, worker):
    server.log.info("Worker %d exited", worker.pid)