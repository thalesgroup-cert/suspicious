"""Extract display-ready fields from a VirusTotal v3 report_full.
Pure dict -> dict; no ORM, no network. Returns None when the payload
carries no usable VT attributes."""
from __future__ import annotations

import base64
import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

_CAT_ORDER = {"malicious": 0, "suspicious": 1, "type-unsupported": 2,
              "harmless": 3, "undetected": 3, "timeout": 4}
_NAMES_CAP = 10


def _attributes(report_full: Any) -> Optional[dict]:
    if not isinstance(report_full, dict):
        return None
    res = report_full.get("results")
    if not isinstance(res, dict):
        return None
    data = res.get("data")
    if isinstance(data, dict) and isinstance(data.get("attributes"), dict):
        return data["attributes"]
    if isinstance(res.get("attributes"), dict):
        return res["attributes"]
    if "last_analysis_results" in res or "last_analysis_stats" in res:
        return res
    return None


def _iso(ts: Any) -> Optional[str]:
    try:
        ts = int(ts)
    except (TypeError, ValueError, OverflowError, OSError):
        return None
    if ts <= 0:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _vendors_from_results(results: dict) -> list[dict]:
    out = []
    for engine, r in results.items():
        if not isinstance(r, dict):
            continue
        out.append({
            "name": engine,
            "category": str(r.get("category") or "undetected"),
            "result": r.get("result") or None,
        })
    out.sort(key=lambda v: (_CAT_ORDER.get(v["category"], 3), v["name"].lower()))
    return out


def _vendors_from_scans(scans: dict) -> list[dict]:
    out = []
    for engine, r in scans.items():
        if not isinstance(r, dict):
            continue
        detected = bool(r.get("detected"))
        out.append({
            "name": engine,
            "category": "malicious" if detected else "undetected",
            "result": r.get("result") or None,
        })
    out.sort(key=lambda v: (_CAT_ORDER.get(v["category"], 3), v["name"].lower()))
    return out


def _vt_link(data_type: str, value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    base = "https://www.virustotal.com/gui"
    dt = (data_type or "").lower()
    if dt in ("hash", "file"):
        return f"{base}/file/{value}"
    if dt == "ip":
        return f"{base}/ip-address/{value}"
    if dt == "domain":
        return f"{base}/domain/{value}"
    if dt == "url":
        uid = base64.urlsafe_b64encode(value.encode()).rstrip(b"=").decode()
        return f"{base}/url/{uid}"
    return None


def extract(report_full: Any, data_type: str, value: Optional[str] = None) -> Optional[dict]:
    try:
        return _extract(report_full, data_type, value)
    except Exception as exc:   # never break scoring
        logger.warning("VT enrichment extraction failed: %s", exc, exc_info=True)
        return None


def _extract(report_full: Any, data_type: str, value: Optional[str]) -> Optional[dict]:
    attrs = _attributes(report_full)
    legacy = None
    if attrs is None and isinstance(report_full, dict):
        res = report_full.get("results")
        if isinstance(res, dict) and "positives" in res:
            legacy = res
    if attrs is None and legacy is None:
        return None

    out: dict[str, Any] = {"source": "virustotal"}
    dt = (data_type or "").lower()

    if legacy is not None:
        scans = legacy.get("scans") if isinstance(legacy.get("scans"), dict) else {}
        out["vendors"] = _vendors_from_scans(scans)
        try:
            out["malicious_count"] = int(legacy.get("positives") or 0)
            out["suspicious_count"] = 0
            out["total"] = int(legacy.get("total") or len(scans) or 0)
        except (TypeError, ValueError):
            pass
        out["vt_link"] = _vt_link(dt, value)
        return out

    results = attrs.get("last_analysis_results")
    if isinstance(results, dict):
        out["vendors"] = _vendors_from_results(results)
    stats = attrs.get("last_analysis_stats")
    if isinstance(stats, dict):
        try:
            out["malicious_count"] = int(stats.get("malicious") or 0)
            out["suspicious_count"] = int(stats.get("suspicious") or 0)
            out["total"] = sum(int(v or 0) for v in stats.values())
        except (TypeError, ValueError):
            pass
    elif "vendors" in out:
        cats = [v["category"] for v in out["vendors"]]
        out["malicious_count"] = cats.count("malicious")
        out["suspicious_count"] = cats.count("suspicious")
        out["total"] = len(cats)

    rep = attrs.get("reputation")
    if isinstance(rep, (int, float)):
        out["reputation"] = int(rep)
    fs = _iso(attrs.get("first_submission_date"))
    if fs:
        out["first_seen"] = fs
    ls = _iso(attrs.get("last_analysis_date")) or _iso(attrs.get("last_submission_date"))
    if ls:
        out["last_seen"] = ls
    tags = attrs.get("tags")
    if isinstance(tags, list) and tags:
        out["tags"] = [str(t) for t in tags][:20]
    link = _vt_link(dt, value)
    if link:
        out["vt_link"] = link

    if dt == "ip":
        for k_src, k_dst in (("as_owner", "as_owner"), ("asn", "asn"),
                             ("country", "country"), ("continent", "continent"),
                             ("network", "network")):
            v = attrs.get(k_src)
            if v not in (None, ""):
                out[k_dst] = v
    elif dt in ("domain", "url"):
        for k_src, k_dst in (("registrar", "registrar"),):
            v = attrs.get(k_src)
            if v not in (None, ""):
                out[k_dst] = v
        cd = _iso(attrs.get("creation_date"))
        if cd:
            out["creation_date"] = cd
        cats = attrs.get("categories")
        if isinstance(cats, dict) and cats:
            out["categories"] = {str(k): str(v) for k, v in list(cats.items())[:10]}
        if dt == "url":
            for k_src, k_dst in (("last_final_url", "final_url"), ("title", "page_title")):
                v = attrs.get(k_src)
                if v not in (None, ""):
                    out[k_dst] = v
    elif dt in ("hash", "file"):
        for k_src, k_dst in (("meaningful_name", "meaningful_name"),
                             ("size", "size"),
                             ("type_description", "type_description")):
            v = attrs.get(k_src)
            if v not in (None, ""):
                out[k_dst] = v
        names = attrs.get("names")
        if isinstance(names, list) and names:
            out["names"] = [str(n) for n in names][:_NAMES_CAP]
        ptc = attrs.get("popular_threat_classification")
        if isinstance(ptc, dict):
            label = ptc.get("suggested_threat_label")
            if label:
                out["threat_label"] = str(label)
            cats = ptc.get("popular_threat_category")
            if isinstance(cats, list) and cats and isinstance(cats[0], dict):
                out["threat_category"] = str(cats[0].get("value") or "")

    return out
