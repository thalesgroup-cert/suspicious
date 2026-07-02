"""Shared ``safe_execution`` context manager factory.

Every ``mail_feeder`` submodule and ``tasp.cron`` used to carry its own
identical copy of a ``safe_execution`` context manager — try/yield/except,
log the error, re-raise — differing only in the bracketed log prefix. This
module replaces all of them with a single implementation built per call site
by :func:`make_safe_execution`.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Callable, ContextManager, Iterator, Optional


def make_safe_execution(
    prefix: str, logger: Optional[logging.Logger] = None
) -> Callable[[str], ContextManager[None]]:
    """Build a ``safe_execution(context)`` context manager.

    The returned context manager wraps a block in try/except: on any exception
    it logs ``[<prefix>] Error during <context>: <exc>`` with a traceback and
    re-raises. ``logger`` defaults to ``logging.getLogger(prefix)`` when not
    supplied, so a call site can keep its existing module logger for routing.
    """
    log = logger if logger is not None else logging.getLogger(prefix)

    @contextmanager
    def safe_execution(context: str) -> Iterator[None]:
        try:
            yield
        except Exception as exc:
            log.error("[%s] Error during %s: %s", prefix, context, exc, exc_info=True)
            raise

    return safe_execution
