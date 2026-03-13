import os
import json
import logging
import re
import ast
from datetime import datetime, timedelta, timezone as dt_timezone
from email.utils import parsedate_to_datetime
import numpy as np
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from api.serializers.campaigns import (
    CampaignClassificationCountsSerializer,
    CampaignPcaResponseSerializer,
    CampaignMailVolumeResponseSerializer,
)
from score_process.score_utils.thehive.utils import parse_and_decode_defaultdict, parse_headers

CONFIG_PATH = os.environ.get("SUSPICIOUS_SETTINGS_PATH", "/app/settings.json")
logger = logging.getLogger(__name__)

with open(CONFIG_PATH, "r") as f:
    settings = json.load(f)

chromadb_conf = settings.get("chromadb", {})
CHROMA_HOST = chromadb_conf.get("host", "chromadb")
CHROMA_PORT = chromadb_conf.get("port", 8000)
CHROMA_COLLECTION_NAME = chromadb_conf.get("collection_name", "suspicious")

def _disable_chromadb_telemetry():
    try:
        os.environ.setdefault("CHROMADB_TELEMETRY_ENABLED", "false")
        os.environ.setdefault("ANONYMIZED_TELEMETRY", "false")
        os.environ.setdefault("CHROMADB_DISABLE_TELEMETRY", "true")
        os.environ.setdefault("CHROMADB_TELEMETRY", "false")
    except Exception:
        pass

    try:
        from chromadb.telemetry import telemetry as _telemetry  # type: ignore

        if hasattr(_telemetry, "TELEMETRY_ENABLED"):
            try:
                _telemetry.TELEMETRY_ENABLED = False  # type: ignore[attr-defined]
            except Exception:
                pass

        inst = getattr(_telemetry, "telemetry_instance", None)
        if inst is not None:
            for attr in ("capture", "capture_event", "capture_span", "flush"):
                if hasattr(inst, attr):
                    setattr(inst, attr, lambda *a, **k: None)
    except Exception:
        pass

    try:
        from chromadb.telemetry import product as _product  # type: ignore

        posthog_mod = getattr(_product, "posthog", None)
        if posthog_mod is not None:
            def _noop_capture(*args, **kwargs):
                return None

            if hasattr(posthog_mod, "capture"):
                posthog_mod.capture = _noop_capture  # type: ignore[assignment]
            client_cls = getattr(posthog_mod, "Posthog", None)
            if client_cls is not None and hasattr(client_cls, "capture"):
                client_cls.capture = _noop_capture  # type: ignore[assignment]
    except Exception:
        pass


def _get_chroma_collection(collection_name: str = CHROMA_COLLECTION_NAME):
    try:
        import chromadb
    except Exception as e:
        logger.warning("ChromaDB not available in environment: %s", e)
        return None

    _disable_chromadb_telemetry()

    host = CHROMA_HOST
    port = int(CHROMA_PORT)

    try:
        client = chromadb.HttpClient(
            host=host,
            port=port,
        )
    except Exception as e:
        logger.error("Failed to connect to ChromaDB server %s:%s: %s", host, port, e)
        return None

    try:
        return client.get_collection(name=collection_name)
    except Exception as e:
        logger.warning(
            "ChromaDB collection '%s' not accessible: %s",
            collection_name,
            e,
        )
        return None


def _parse_source_refs(raw):
    if raw is None:
        return ()
    iterable = None
    if isinstance(raw, (list, tuple, set)):
        iterable = list(raw)
    else:
        text = str(raw).strip()
        if not text:
            return ()
        for parser in (json.loads, ast.literal_eval):
            try:
                parsed = parser(text)
            except Exception:
                continue
            if isinstance(parsed, (list, tuple, set)):
                iterable = list(parsed)
                break
            if isinstance(parsed, str):
                iterable = [parsed]
                break
        if iterable is None:
            stripped = text.strip("[](){}")
            if not stripped:
                return ()
            parts = [segment for segment in re.split(r"[;,]", stripped) if segment]
            iterable = [seg.strip().strip("'\"") for seg in parts]
    if iterable is None:
        return ()
    cleaned = []
    for item in iterable:
        sval = str(item).strip().strip("'\"")
        if sval:
            cleaned.append(sval)
    if not cleaned:
        return ()
    seen = {}
    for val in cleaned:
        if val not in seen:
            seen[val] = None
    return tuple(sorted(seen.keys()))


def _extract_headers_dict(raw):
    if not raw:
        return None
    if isinstance(raw, dict):
        return raw
    text = str(raw)
    if not text:
        return None
    if "defaultdict" in text:
        try:
            parsed = parse_and_decode_defaultdict(text)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
    for parser in (json.loads, ast.literal_eval):
        try:
            parsed = parser(text)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue
    try:
        parsed = parse_headers(text)
        if isinstance(parsed, dict):
            return dict(parsed)
    except Exception:
        pass
    return None


def _parse_to_utc_date(val):
    if val is None:
        return None
    try:
        if isinstance(val, (int, float)):
            ts = float(val)
            if ts > 1e12:
                ts = ts / 1000.0
            dt = datetime.fromtimestamp(ts, tz=dt_timezone.utc)
            return dt.date()

        s = str(val).strip()
        if not s:
            return None

        s = s.replace("Z", "+00:00")
        dt = None
        try:
            dt = datetime.fromisoformat(s)
        except Exception:
            s2 = s.replace("GMT", "+00:00").replace(",", "")
            try:
                dt = datetime.fromisoformat(s2)
            except Exception:
                core = s
                if "T" in s:
                    core = s.split("T", 1)[0] + "T" + s.split("T", 1)[1][:8]
                core = core[:19]
                try:
                    dt = datetime.fromisoformat(core)
                except Exception:
                    m = re.search(r"(\d{4}-\d{2}-\d{2})", s)
                    if m:
                        return datetime.fromisoformat(m.group(1)).date()
                    return None

        if dt.tzinfo is None:
            return dt.date()
        return dt.astimezone(dt_timezone.utc).date()
    except Exception:
        return None


def _parse_header_datetime(value):
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(str(value))
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=dt_timezone.utc)
        return dt.astimezone(dt_timezone.utc)
    except Exception:
        pass
    fallback_day = _parse_to_utc_date(value)
    if fallback_day is None:
        return None
    return datetime(
        fallback_day.year,
        fallback_day.month,
        fallback_day.day,
        tzinfo=dt_timezone.utc,
    )


def _extract_sent_datetime(meta):
    headers_dict = _extract_headers_dict(meta.get("headers"))
    if not isinstance(headers_dict, dict):
        return None

    candidates = []
    for key in ("Date", "date", "Sent", "Sent-Date", "Sent-date", "sent_date"):
        val = headers_dict.get(key)
        if not val:
            continue
        if isinstance(val, (list, tuple)):
            candidates.extend(val)
        else:
            candidates.append(val)

    for candidate in candidates:
        dt = _parse_header_datetime(candidate)
        if dt is not None:
            return dt
    return None


def _extract_case_id(meta_obj):
    if not isinstance(meta_obj, dict):
        return None
    raw = meta_obj.get("suspicious_case_id")
    if raw is None:
        raw = meta_obj.get("case_id")
    if raw is None:
        return None
    if isinstance(raw, (list, tuple)):
        raw = raw[0] if raw else None
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None

class CampaignClassificationCountsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        counts = {"SAFE": 0, "UNWANTED": 0, "DANGEROUS": 0}

        collection = _get_chroma_collection()
        if collection is None:
            serializer = CampaignClassificationCountsSerializer(data=counts)
            serializer.is_valid(raise_exception=True)
            return Response(serializer.data)

        def count_for(value: str) -> int:
            try:
                res = collection.get(where={"classification": value})
                ids = res.get("ids", []) if isinstance(res, dict) else []
                return len(ids)
            except Exception as e:
                logger.error("Error counting classification %s: %s", value, e, exc_info=True)
                return 0

        counts["SAFE"] = count_for("SAFE")
        counts["UNWANTED"] = count_for("UNWANTED")
        counts["DANGEROUS"] = count_for("DANGEROUS")

        if counts["UNWANTED"] == 0:
            suspicious = count_for("SUSPICIOUS")
            if suspicious:
                counts["UNWANTED"] = suspicious

        serializer = CampaignClassificationCountsSerializer(data=counts)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)
    
class CampaignPcaView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            limit = int(request.query_params.get("limit", "1500"))
        except Exception:
            limit = 1500

        collection = _get_chroma_collection()
        if collection is None:
            payload = {"points": [], "explained_variance": [0.0, 0.0]}
            serializer = CampaignPcaResponseSerializer(data=payload)
            serializer.is_valid(raise_exception=True)
            return Response(serializer.data)

        try:
            try:
                res = collection.get(include=["embeddings", "metadatas"])  # type: ignore[arg-type]
            except Exception:
                res = collection.get()

            if not isinstance(res, dict):
                payload = {"points": [], "explained_variance": [0.0, 0.0]}
                serializer = CampaignPcaResponseSerializer(data=payload)
                serializer.is_valid(raise_exception=True)
                return Response(serializer.data)

            ids = res.get("ids") or []

            def _ensure_list(obj):
                if obj is None:
                    return []
                if isinstance(obj, list):
                    return obj
                try:
                    return list(obj)
                except TypeError:
                    return [obj]

            embeddings = _ensure_list(res.get("embeddings"))
            metadatas = _ensure_list(res.get("metadatas"))

            if ids and not embeddings:
                chunk_size = 200

                def _fetch_chunk(id_slice, depth=0):
                    if not id_slice:
                        return [], []
                    try:
                        chunk_res = collection.get(ids=id_slice, include=["embeddings", "metadatas"])  # type: ignore[arg-type]
                    except Exception as chunk_err:
                        if len(id_slice) == 1:
                            logger.error("PCA: failed to fetch embedding for id %s: %s", id_slice[0], chunk_err)
                            return [], []
                        if depth > 10:
                            logger.error("PCA: giving up fetching %d ids after deep recursion: %s", len(id_slice), chunk_err)
                            return [], []
                        mid = len(id_slice) // 2 or 1
                        left_emb, left_meta = _fetch_chunk(id_slice[:mid], depth + 1)
                        right_emb, right_meta = _fetch_chunk(id_slice[mid:], depth + 1)
                        return left_emb + right_emb, left_meta + right_meta

                    chunk_embeddings = _ensure_list(chunk_res.get("embeddings"))
                    chunk_metadatas = _ensure_list(chunk_res.get("metadatas"))
                    return chunk_embeddings, chunk_metadatas

                embeddings_chunks = []
                metadatas_chunks = []
                for start in range(0, len(ids), chunk_size):
                    chunk_ids = ids[start:start + chunk_size]
                    chunk_embeddings, chunk_metadatas = _fetch_chunk(chunk_ids)
                    if chunk_embeddings:
                        embeddings_chunks.extend(chunk_embeddings)
                        metadatas_chunks.extend(chunk_metadatas)

                if embeddings_chunks:
                    embeddings = embeddings_chunks
                    metadatas = metadatas_chunks

            if len(metadatas) < len(embeddings):
                metadatas = metadatas + [None] * (len(embeddings) - len(metadatas))

            dim_buckets = {}
            emb_iter = list(embeddings) if embeddings is not None else []

            for i, emb in enumerate(emb_iter):
                try:
                    vec = np.asarray(emb, dtype=np.float32).reshape(-1)
                    if vec.size == 0:
                        continue
                    if not np.all(np.isfinite(vec)):
                        continue

                    meta = {}
                    if i < len(metadatas):
                        meta = metadatas[i] or {}

                    label = str((meta or {}).get("classification", "UNKNOWN"))
                    dim = int(vec.size)
                    bucket = dim_buckets.setdefault(dim, [])
                    bucket.append((vec, label, meta))
                except Exception:
                    continue

            if not dim_buckets:
                payload = {"points": [], "explained_variance": [0.0, 0.0]}
                serializer = CampaignPcaResponseSerializer(data=payload)
                serializer.is_valid(raise_exception=True)
                return Response(serializer.data)

            chosen_dim = max(dim_buckets.keys(), key=lambda d: (len(dim_buckets[d]), d))
            selected = dim_buckets[chosen_dim]

            X = [entry[0] for entry in selected]
            labels = [entry[1] for entry in selected]
            metas = [entry[2] for entry in selected]

            n = len(X)
            if n == 0:
                payload = {"points": [], "explained_variance": [0.0, 0.0]}
                serializer = CampaignPcaResponseSerializer(data=payload)
                serializer.is_valid(raise_exception=True)
                return Response(serializer.data)

            if n == 1:
                single_meta = metas[0] if metas else {}
                single_label = labels[0] if labels else "UNKNOWN"
                payload = {
                    "points": [{
                        "x": 0.0,
                        "y": 0.0,
                        "label": str(single_label or "UNKNOWN"),
                        "suspicious_case_id": _extract_case_id(single_meta),
                        "sourceRefs": list(_parse_source_refs((single_meta or {}).get("sourceRefs"))) if single_meta else [],
                    }],
                    "explained_variance": [0.0, 0.0],
                }
                serializer = CampaignPcaResponseSerializer(data=payload)
                serializer.is_valid(raise_exception=True)
                return Response(serializer.data)

            X = np.stack(X, axis=0)

            if n > limit > 0:
                idx = np.random.default_rng(seed=42).choice(n, size=limit, replace=False)
                X = X[idx]
                labels = [labels[int(i)] for i in idx]
                metas = [metas[int(i)] for i in idx]
                n = X.shape[0]

            Xc = X - X.mean(axis=0, keepdims=True)

            try:
                U, S, Vt = np.linalg.svd(Xc, full_matrices=False)
            except Exception:
                payload = {"points": [], "explained_variance": [0.0, 0.0]}
                serializer = CampaignPcaResponseSerializer(data=payload)
                serializer.is_valid(raise_exception=True)
                return Response(serializer.data)

            comps = Vt[:2]
            scores = Xc @ comps.T

            ev = S ** 2
            denom = float(ev.sum()) if ev.size else 0.0
            if denom <= 0.0:
                ratios = [0.0, 0.0]
            else:
                ratios = [
                    float(ev[0] / denom),
                    float(ev[1] / denom) if ev.size > 1 else 0.0,
                ]

            points = [
                {
                    "x": float(scores[i, 0]),
                    "y": float(scores[i, 1]),
                    "label": str(labels[i] or "UNKNOWN"),
                    "suspicious_case_id": _extract_case_id(metas[i] if i < len(metas) else None),
                    "sourceRefs": list(_parse_source_refs((metas[i] or {}).get("sourceRefs"))) if i < len(metas) else [],
                }
                for i in range(n)
            ]

            payload = {"points": points, "explained_variance": ratios}
            serializer = CampaignPcaResponseSerializer(data=payload)
            serializer.is_valid(raise_exception=True)
            return Response(serializer.data)

        except Exception as e:
            logger.error("Error computing PCA points: %s", e, exc_info=True)
            payload = {"points": [], "explained_variance": [0.0, 0.0]}
            serializer = CampaignPcaResponseSerializer(data=payload)
            serializer.is_valid(raise_exception=True)
            return Response(serializer.data)

class CampaignMailVolumeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        today_utc = datetime.now(dt_timezone.utc).date()
        start_utc = today_utc - timedelta(days=14)

        all_days = [start_utc + timedelta(days=i) for i in range(15)]
        idx = {d: i for i, d in enumerate(all_days)}
        non_danger = [0] * len(all_days)
        dangerous = [0] * len(all_days)

        collection = _get_chroma_collection()
        if collection is None:
            payload = {
                "dates": [d.isoformat() for d in all_days],
                "non_danger": non_danger,
                "dangerous": dangerous,
                "campaigns": [],
            }
            serializer = CampaignMailVolumeResponseSerializer(data=payload)
            serializer.is_valid(raise_exception=True)
            return Response(serializer.data)

        def _ensure_utc(dt):
            if dt is None:
                return None
            if dt.tzinfo is None:
                return dt.replace(tzinfo=dt_timezone.utc)
            return dt.astimezone(dt_timezone.utc)

        def _format_campaign_name(refs_key, fallback_index):
            if not refs_key:
                return f"Campaign {fallback_index}"
            parts = [ref for ref in refs_key if ref]
            if not parts:
                return f"Campaign {fallback_index}"
            if len(parts) <= 3:
                return ", ".join(parts)
            return ", ".join(parts[:3]) + "…"

        campaign_windows = {}

        try:
            try:
                res = collection.get(include=["metadatas"], limit=100000)  # type: ignore[arg-type]
            except Exception:
                try:
                    res = collection.get(include=["metadatas"])  # type: ignore[arg-type]
                except Exception:
                    res = collection.get()

            if not isinstance(res, dict):
                raise ValueError("Unexpected ChromaDB get() result type")

            metadatas = res.get("metadatas", []) or []
            date_keys = (
                "sent_date", "date", "received_at", "created_at",
                "created", "timestamp", "date_received", "mail_date",
                "headers_date", "date_header", "ingested_at", "submitted_at",
                "time", "ts"
            )
            class_key = "classification"

            for meta in metadatas:
                try:
                    meta = meta or {}
                    refs_key = _parse_source_refs(meta.get("sourceRefs"))
                    sent_dt = _extract_sent_datetime(meta)
                    day = sent_dt.date() if sent_dt else None

                    dval = None
                    if day is None:
                        for k in date_keys:
                            if k in meta and meta[k]:
                                dval = meta[k]
                                break
                        if dval is None:
                            for v in meta.values():
                                potential_day = _parse_to_utc_date(v)
                                if potential_day is not None:
                                    dval = v
                                    break
                        if dval is not None:
                            day = _parse_to_utc_date(dval)

                    if refs_key:
                        if sent_dt is None and day is not None:
                            sent_dt = datetime(day.year, day.month, day.day, tzinfo=dt_timezone.utc)
                        if sent_dt is not None:
                            window = campaign_windows.get(refs_key)
                            if window is None:
                                campaign_windows[refs_key] = {"first": sent_dt, "last": sent_dt}
                            else:
                                if sent_dt < window["first"]:
                                    window["first"] = sent_dt
                                if sent_dt > window["last"]:
                                    window["last"] = sent_dt

                    if day is None:
                        continue
                    if not (start_utc <= day <= today_utc):
                        continue
                    pos = idx.get(day)
                    if pos is None:
                        continue

                    cls = str(meta.get(class_key, "UNKNOWN")).upper()
                    if cls == "DANGEROUS":
                        dangerous[pos] += 1
                    else:
                        non_danger[pos] += 1
                except Exception:
                    continue

        except Exception as e:
            logger.error("Error computing mail volume: %s", e, exc_info=True)

        window_start_dt = datetime(start_utc.year, start_utc.month, start_utc.day, tzinfo=dt_timezone.utc)
        window_end_dt = datetime(today_utc.year, today_utc.month, today_utc.day, tzinfo=dt_timezone.utc) + timedelta(days=1)

        campaigns_out = []
        for idx_num, (refs_key, bounds) in enumerate(campaign_windows.items(), start=1):
            start_dt = _ensure_utc(bounds.get("first"))
            end_dt = _ensure_utc(bounds.get("last"))
            if start_dt is None or end_dt is None:
                continue
            if end_dt < start_dt:
                start_dt, end_dt = end_dt, start_dt
            if end_dt < window_start_dt or start_dt > window_end_dt:
                continue

            clamped_start = max(start_dt, window_start_dt)
            clamped_end = min(end_dt, window_end_dt)
            if clamped_end < clamped_start:
                continue

            campaigns_out.append({
                "name": _format_campaign_name(refs_key, idx_num),
                "start": clamped_start.isoformat(),
                "end": clamped_end.isoformat(),
            })

        payload = {
            "dates": [d.isoformat() for d in all_days],
            "non_danger": non_danger,
            "dangerous": dangerous,
            "campaigns": campaigns_out,
        }
        serializer = CampaignMailVolumeResponseSerializer(data=payload)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)