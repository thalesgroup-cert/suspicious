"""Dispatch-time planning for URL analysis.

Collapses equivalent URLs, reuses recent cross-case results, and caps
per-domain analysis volume to the most interesting URLs. See
docs/superpowers/specs/2026-06-23-url-analysis-planner-design.md.

Every helper here is intended to be safe and fail-open: callers must never
let a planning failure drop a URL from analysis.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import timedelta
from urllib.parse import urlsplit, parse_qs

from django.utils import timezone

from settings.config import get_config

logger = logging.getLogger(__name__)


DEFAULT_SHORTENER_DOMAINS = (
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "cutt.ly", "rb.gy", "rebrand.ly", "lnkd.in",
)
DEFAULT_SUSPICIOUS_TLDS = (
    "zip", "mov", "xyz", "top", "click", "country", "kim", "work",
    "gq", "ml", "cf", "tk", "ga",
)
OPEN_REDIRECT_KEYS = frozenset({"url", "next", "redirect", "r", "dest", "continue", "return", "u"})
RISKY_PATH_SUFFIXES = (".exe", ".scr", ".js", ".hta", ".iso", ".zip", ".rar", ".7z", ".msi", ".bat", ".cmd")


def canonical_key(url: str) -> str:
    """Return the canonical equivalence key for ``url``.

    Key = ``scheme://host/path?<sorted query-key set>``:
      * host lower-cased, leading ``www.`` stripped
      * fragment dropped
      * query *values* dropped, query *key names* kept and sorted

    URLs that differ only in query values (victim id, tracking token) collapse
    to one key; a URL that introduces a *new* query key (e.g. ``redirect``)
    stays distinct on purpose.
    """
    if "://" not in url:
        url = "http://" + url
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    port = f":{parts.port}" if parts.port else ""
    path = parts.path or "/"
    query_keys = sorted(parse_qs(parts.query, keep_blank_values=True).keys())
    query = "?" + "&".join(query_keys) if query_keys else ""
    return f"{parts.scheme}://{host}{port}{path}{query}"


def _cfg_list(key: str, default: tuple[str, ...]) -> tuple[str, ...]:
    value = get_config(key, None)
    if isinstance(value, (list, tuple)) and value:
        return tuple(str(v).lower() for v in value)
    return default


def _registered_domain_lower(host: str) -> str:
    """Registered domain via the shared tldextract cache; '' on failure."""
    try:
        from mail_feeder.mail_utils.meioc import tldcache
        return (tldcache(host).registered_domain or "").lower()
    except Exception:  # noqa: BLE001 — scoring must never raise
        return ""


def score_interestingness(url: str, *, sender_domain: str | None = None) -> int:
    """Additive, table-driven interestingness score, clamped to 0..255.

    Higher = analyze sooner. Tuned so genuinely-suspicious traits outrank
    benign tracking noise; a payload-bearing query (``?redirect=``) is boosted
    so it survives per-domain capping.
    """
    try:
        if "://" not in url:
            url = "http://" + url
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        path = (parts.path or "").lower()
        query_keys = {k.lower() for k in parse_qs(parts.query, keep_blank_values=True)}

        score = 0

        is_ip = False
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            pass
        if is_ip:
            score += 40

        if "xn--" in host:
            score += 30

        shorteners = _cfg_list("url_analysis.shortener_domains", DEFAULT_SHORTENER_DOMAINS)
        if any(host == s or host.endswith("." + s) for s in shorteners):
            score += 30

        if "@" in (parts.netloc or ""):
            score += 25

        if query_keys & OPEN_REDIRECT_KEYS:
            score += 25

        sus_tlds = _cfg_list("url_analysis.suspicious_tlds", DEFAULT_SUSPICIOUS_TLDS)
        if not is_ip and host.rsplit(".", 1)[-1] in sus_tlds:
            score += 20

        if any(path.endswith(suf) for suf in RISKY_PATH_SUFFIXES):
            score += 20

        if parts.port and parts.port not in (80, 443):
            score += 15

        depth = len([seg for seg in path.split("/") if seg])
        if depth >= 4 or len(path) > 60:
            score += 10

        if len(query_keys) > 4:
            score += 5

        if sender_domain and not is_ip:
            if _registered_domain_lower(host) == sender_domain.lower():
                score -= 20

        if depth == 0 and not query_keys:
            score -= 10

        return max(0, min(255, score))
    except Exception:  # noqa: BLE001 — scoring must never raise
        logger.warning("score_interestingness failed for %r; defaulting to 0", url, exc_info=True)
        return 0


# ---------------------------------------------------------------------------
# URLAnalysisPlan dataclass + plan_url_analysis entry point
# ---------------------------------------------------------------------------

@dataclass
class URLAnalysisPlan:
    to_analyze: list = field(default_factory=list)
    to_reuse: list = field(default_factory=list)   # list[tuple[URL, URL]]
    skipped: list = field(default_factory=list)


def _safe_canonical(url) -> str:
    """Return canonical_key for *url*, defaulting to '' on any error (fail-open)."""
    try:
        return canonical_key(url.address or "")
    except Exception:  # noqa: BLE001
        logger.warning("canonical_key failed for URL id=%s; fail-open", url.pk, exc_info=True)
        return ""


def _registered_domain_for_url(url) -> str:
    """Best-effort registered domain for *url*; '' on failure."""
    try:
        addr = url.address or ""
        if "://" not in addr:
            addr = "http://" + addr
        return _registered_domain_lower(urlsplit(addr).hostname or "")
    except Exception:  # noqa: BLE001 — fail-open
        return ""


def _find_reusable_prior(canonical: str, ttl_days: int, exclude_ids: list):
    """Return the most-recent other URL with the same canonical_key that has
    a fresh (within TTL) AnalyzerReport, or ``None`` if no such row exists.
    """
    if not canonical:
        return None
    from url_process.models import URL
    from cortex_job.models import AnalyzerReport

    cutoff = timezone.now() - timedelta(days=ttl_days)
    candidate = (
        URL.objects.filter(
            canonical_key=canonical,
            analysis_status__in=[URL.AnalysisStatus.ANALYZED, URL.AnalysisStatus.REUSED],
        )
        .exclude(id__in=exclude_ids)
        .order_by("-last_update")
        .first()
    )
    if candidate is None:
        return None
    has_fresh_report = AnalyzerReport.objects.filter(
        url=candidate, creation_date__gte=cutoff
    ).exists()
    return candidate if has_fresh_report else None


def plan_url_analysis(url_instances, *, sender_domain=None) -> URLAnalysisPlan:
    """Decide which URLs in *url_instances* to analyze, reuse, or skip.

    Persists ``canonical_key``, ``interestingness``, ``analysis_status``, and
    ``analyzed_url`` on each row.  Fail-open per URL: an exception processing
    one URL must not prevent others from being planned.

    Steps:
      1. Annotate each URL with canonical_key + interestingness.
      2. Within-case collapse: URLs with the same canonical_key collapse to
         one representative; duplicates are marked REUSED → representative.
      3. Cross-case TTL reuse: if a representative's canonical_key has a
         recent AnalyzerReport in another row, reuse that row instead of
         dispatching a new analysis.
      4. Per-domain cap: keep only the top-N most-interesting URLs per
         registered domain; remainder are marked SKIPPED.
    """
    from url_process.models import URL

    plan = URLAnalysisPlan()
    if not url_instances:
        return plan

    max_per_domain = int(get_config("url_analysis.max_per_domain", 5) or 5)
    ttl_days = int(get_config("url_analysis.reuse_ttl_days", 7) or 7)
    all_ids = [u.pk for u in url_instances]

    # Step 1: annotate each URL with canonical_key + interestingness
    by_key: dict[str, list] = {}
    for u in url_instances:
        try:
            u.canonical_key = _safe_canonical(u)
            u.interestingness = score_interestingness(u.address or "", sender_domain=sender_domain)
            u.save(update_fields=["canonical_key", "interestingness"])
        except Exception:  # noqa: BLE001 — fail-open
            logger.warning("annotate failed for URL id=%s; fail-open", u.pk, exc_info=True)
        group_key = u.canonical_key or f"__unkeyed__:{u.pk}"
        by_key.setdefault(group_key, []).append(u)

    # Step 2: within-case collapse → one representative per canonical key
    representatives = []
    for key, group in by_key.items():
        # Sort: highest interestingness first; tie-break by longer address
        group.sort(key=lambda u: (-u.interestingness, len(u.address or "")))
        rep, dups = group[0], group[1:]
        representatives.append(rep)
        for d in dups:
            d.analysis_status = URL.AnalysisStatus.REUSED
            d.analyzed_url = rep
            d.save(update_fields=["analysis_status", "analyzed_url"])
            plan.to_reuse.append((d, rep))

    # Step 3: cross-case TTL reuse
    candidates = []
    for rep in representatives:
        prior = None
        try:
            prior = _find_reusable_prior(rep.canonical_key, ttl_days, all_ids)
        except Exception:  # noqa: BLE001 — fail-open → analyze
            logger.warning("TTL lookup failed for URL id=%s; fail-open", rep.pk, exc_info=True)
        if prior is not None:
            rep.analysis_status = URL.AnalysisStatus.REUSED
            rep.analyzed_url = prior
            rep.save(update_fields=["analysis_status", "analyzed_url"])
            plan.to_reuse.append((rep, prior))
        else:
            candidates.append(rep)

    # Step 4: per-domain cap — keep top-N most-interesting per registered domain
    by_domain: dict[str, list] = {}
    for c in candidates:
        by_domain.setdefault(_registered_domain_for_url(c), []).append(c)
    for domain, group in by_domain.items():
        group.sort(key=lambda u: -u.interestingness)
        keep, overflow = group[:max_per_domain], group[max_per_domain:]
        for k in keep:
            k.analysis_status = URL.AnalysisStatus.PENDING
            k.save(update_fields=["analysis_status"])
            plan.to_analyze.append(k)
        for o in overflow:
            o.analysis_status = URL.AnalysisStatus.SKIPPED
            o.save(update_fields=["analysis_status"])
            plan.skipped.append(o)

    return plan


def filter_dispatch_intents(intents, *, sender_domain=None):
    """Given a list of (obj, data_type) dispatch intents, return a possibly-reduced
    list with redundant URL intents removed per plan_url_analysis. Non-URL intents
    pass through untouched. Honors the url_analysis.enabled kill-switch and only
    engages when there is more than one URL intent. Fail-open: any error returns
    the original intents unchanged so dispatch is never blocked."""
    url_intents = [(v, t) for (v, t) in intents if t == "url"]
    if not get_config("url_analysis.enabled", False) or len(url_intents) <= 1:
        return list(intents)
    try:
        plan = plan_url_analysis([v for (v, _t) in url_intents], sender_domain=sender_domain)
        keep = set(plan.to_analyze)            # URL instances to dispatch
        return [(v, t) for (v, t) in intents if t != "url" or v in keep]
    except Exception:
        logger.warning("URL planner failed; dispatching all URL intents", exc_info=True)
        return list(intents)
