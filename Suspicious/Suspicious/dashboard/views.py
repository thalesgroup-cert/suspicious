import ast
import json
import logging
from datetime import date, timedelta
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.models import User
from django.http import JsonResponse, HttpRequest, HttpResponse
from django.shortcuts import redirect, render, get_object_or_404

from dashboard.dash_utils.dashboard import (
    update_all_kpi_stats,
    update_monthly_cases_summary,
    update_total_cases_stats
)
from dashboard.dash_utils.utils import (
    get_dashboard_score,
    get_dashboard_email_prefix,
    new_reporters_dash,
    total_reporters_dash,
    total_by_danger_dash,
    get_case_all_dash,
    dashboard_score_scope,
    dashboard_mail_scope,
    new_reporters_dash_scope,
    total_reporters_dash_scope,
    total_by_danger_dash_scope,
    get_case_all_dash_scope,
)

from .models import (
    Kpi,
    MonthlyReporterStats,
    MonthlyCasesSummary,
    TotalCasesStats,
)

import numpy as np  # For PCA computation without sklearn
from datetime import datetime, timezone
import re
from email.utils import parsedate_to_datetime

from score_process.score_utils.utils import parse_and_decode_defaultdict, parse_headers

logger = logging.getLogger(__name__)


def _disable_chromadb_telemetry():
    """Force-disable ChromaDB telemetry (PostHog) to avoid noisy logs."""
    try:
        import os

        os.environ.setdefault("CHROMADB_TELEMETRY_ENABLED", "false")
        os.environ.setdefault("ANONYMIZED_TELEMETRY", "false")
        os.environ.setdefault("CHROMADB_DISABLE_TELEMETRY", "true")
        os.environ.setdefault("CHROMADB_TELEMETRY", "false")
    except Exception:
        pass

    # Monkey-patch telemetry capture routines if the modules are available.
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


def logout_view(request: HttpRequest) -> HttpResponse:
    """
    Log out the user and redirect to the login page.
    Always redirects (or returns a JSON message) regardless of logout success.
    """
    try:
        if request.user.is_authenticated:
            logger.info(f"User {request.user} is logging out")
            auth_logout(request)
            logger.info(f"User {request.user} logged out successfully")
        else:
            logger.warning("Unauthenticated user attempted to log out")
    except Exception as e:
        logger.error(f"Error logging out user: {e}", exc_info=True)
    # Always redirect to the login page (or you can return a JSON response if needed)
    return redirect('login')


# --- ChromaDB helper utilities ---

def _get_chroma_collection(collection_name: str = "suspicious_mails"):
    """Best-effort ChromaDB collection getter handling API/tenant differences.

    Returns the collection object or None if unavailable.
    """
    try:
        import os
        import chromadb  # type: ignore
        from chromadb.config import Settings  # type: ignore
    except Exception as e:
        logger.warning("ChromaDB not available in environment: %s", e)
        return None

    _disable_chromadb_telemetry()

    persist_path = "/app/Suspicious/chromadb"
    errors = []

    # Attempt matrix for different versions
    attempts = []
    try:
        attempts.append(lambda: chromadb.PersistentClient(path=persist_path, tenant="default_tenant", database="default_database", settings=Settings(anonymized_telemetry=False)))
    except Exception:
        # Signature may not support tenant/database
        attempts.append(lambda: chromadb.PersistentClient(path=persist_path, settings=Settings(anonymized_telemetry=False)))

    # Older API fallback: Client with Settings(is_persistent=True)
    def _legacy_client():
        try:
            s = Settings(is_persistent=True, persist_directory=persist_path, anonymized_telemetry=False)  # type: ignore[arg-type]
            return chromadb.Client(s)
        except Exception as e:
            errors.append(f"Legacy client failed init: {e}")
            raise

    attempts.append(_legacy_client)

    client = None
    for factory in attempts:
        try:
            client = factory()
            break
        except Exception as e:
            errors.append(str(e))
            client = None
            continue

    if client is None:
        logger.error("Failed to init ChromaDB client: %s", " | ".join(errors))
        return None

    try:
        return client.get_collection(name=collection_name)
    except Exception as e:
        logger.warning("ChromaDB collection '%s' not accessible: %s", collection_name, e)
        return None


@login_required
def dashboard(request: HttpRequest) -> HttpResponse:
    """
    Render the dashboard page.
    Retrieves the current month and year, and loads KPI data via a cron job import.
    """
    today = date.today()
    current_month = today.strftime('%m')
    current_year = today.year
    # Importing here to avoid circular imports or to ensure it runs on-demand.
    from tasp.cron import sync_monthly_kpi  
    kpi = sync_monthly_kpi()  # Although kpi isn't used in context, it might trigger needed side effects.
    context = {
        'month': current_month,
        'year': current_year,
    }
    logger.info(f"User {request.user} is on the dashboard page")
    return render(request, 'tasp/dashboard.html', context)

@login_required
def dashboard_campaigns(request: HttpRequest) -> HttpResponse:
    """Simple page for /dashboard/campaigns."""
    logger.info("User %s visited dashboard campaigns page", request.user)
    return render(request, 'tasp/campaigns.html')

# New endpoint: provide classification counts for campaigns page
@login_required
def dashboard_campaigns_classification_counts(request: HttpRequest) -> JsonResponse:
    """Return counts for main classifications from ChromaDB.

    Returns a JSON object: { 'SAFE': int, 'UNWANTED': int, 'DANGEROUS': int }
    If ChromaDB is unavailable, zeros are returned.
    """
    counts = {'SAFE': 0, 'UNWANTED': 0, 'DANGEROUS': 0}

    collection = _get_chroma_collection()
    if collection is None:
        return JsonResponse(counts)

    def count_for(value: str) -> int:
        try:
            res = collection.get(where={"classification": value})
            ids = res.get('ids', []) if isinstance(res, dict) else []
            return len(ids)
        except Exception as e:
            logger.error("Error counting classification %s: %s", value, e, exc_info=True)
            return 0

    counts['SAFE'] = count_for('SAFE')
    counts['UNWANTED'] = count_for('UNWANTED')
    counts['DANGEROUS'] = count_for('DANGEROUS')

    # Fallback mapping if 'UNWANTED' is not used but 'SUSPICIOUS' is
    if counts['UNWANTED'] == 0:
        suspicious = count_for('SUSPICIOUS')
        if suspicious:
            counts['UNWANTED'] = suspicious

    return JsonResponse(counts)

# New endpoint: PCA of all embeddings in ChromaDB
@login_required
def dashboard_campaigns_pca(request: HttpRequest) -> JsonResponse:
    """
    Compute 2D PCA on all ChromaDB embeddings and return scatter points.

    Response format:
    {
    "points": [ {"x": float, "y": float, "label": str}, ... ],
    "explained_variance": [ pc1_ratio, pc2_ratio ]
    }
    Optional query param: ?limit=1500 to subsample points if needed.

    """
    # Limit points for payload size
    try:
        limit = int(request.GET.get("limit", "1500"))
    except Exception:
        limit = 1500

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
        # Preserve order but deduplicate
        seen = {}
        for val in cleaned:
            if val not in seen:
                seen[val] = None
        return tuple(sorted(seen.keys()))

    collection = _get_chroma_collection()
    if collection is None:
        return JsonResponse({"points": [], "explained_variance": [0.0, 0.0]})

    try:
        # Fetch embeddings and labels
        try:
            res = collection.get(include=["embeddings", "metadatas"])  # type: ignore[arg-type]
        except Exception:
            res = collection.get()

        if not isinstance(res, dict):
            logger.warning("Unexpected ChromaDB get() result type: %s", type(res))
            return JsonResponse({"points": [], "explained_variance": [0.0, 0.0]})

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
            logger.warning("PCA: initial get() returned %d ids but no embeddings. Attempting chunked refetch.", len(ids))
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
            else:
                logger.warning("PCA: chunked refetch still yielded zero embeddings (ids=%d)", len(ids))

        if len(metadatas) < len(embeddings):
            metadatas = metadatas + [None] * (len(embeddings) - len(metadatas))

        dim_buckets = {}
        total_embeddings = 0
        skipped_non_finite = 0
        skipped_errors = 0
        # Some APIs may return numpy arrays; iterate safely
        try:
            emb_iter = list(embeddings)
        except Exception:
            emb_iter = []
        for i, emb in enumerate(emb_iter):
            try:
                vec = np.asarray(emb, dtype=np.float32).reshape(-1)
                if vec.size == 0:
                    continue
                total_embeddings += 1
                if not np.all(np.isfinite(vec)):
                    skipped_non_finite += 1
                    continue
                meta = {}
                if i < len(metadatas) and metadatas is not None:
                    try:
                        meta = metadatas[i] or {}
                    except Exception:
                        meta = {}
                label = str((meta or {}).get("classification", "UNKNOWN"))
                dim = int(vec.size)
                bucket = dim_buckets.setdefault(dim, [])
                bucket.append((vec, label, meta))
            except Exception:
                skipped_errors += 1
                continue

        if not dim_buckets:
            if total_embeddings > 0:
                logger.warning("PCA: all %d embeddings were filtered out", total_embeddings)
            return JsonResponse({"points": [], "explained_variance": [0.0, 0.0]})

        # Choose the dimension with the most vectors; tie-breaker prefers larger dimension
        chosen_dim = max(dim_buckets.keys(), key=lambda d: (len(dim_buckets[d]), d))
        if len(dim_buckets) > 1:
            skipped = sum(len(v) for dim, v in dim_buckets.items() if dim != chosen_dim)
            if skipped:
                logger.info(
                    "PCA: selected dimension %d with %d vectors; skipped %d vectors from other dimensions",
                    chosen_dim,
                    len(dim_buckets[chosen_dim]),
                    skipped,
                )
        if skipped_non_finite:
            logger.warning("PCA: skipped %d embeddings with non-finite values", skipped_non_finite)
        if skipped_errors:
            logger.warning("PCA: failed to process %d embeddings due to errors", skipped_errors)

        selected = dim_buckets[chosen_dim]
        X = [entry[0] for entry in selected]
        labels = [entry[1] for entry in selected]
        metas = [entry[2] for entry in selected]

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
            try:
                # Normalize to simple string without whitespace
                text = str(raw).strip()
            except Exception:
                return None
            return text or None

        n = len(X)
        if n == 0:
            return JsonResponse({"points": [], "explained_variance": [0.0, 0.0]})

        if n == 1:
            single_meta = metas[0] if metas else {}
            single_label = labels[0] if labels else "UNKNOWN"
            single_point = {
                "x": 0.0,
                "y": 0.0,
                "label": str(single_label or "UNKNOWN"),
                "suspicious_case_id": _extract_case_id(single_meta),
                "sourceRefs": list(_parse_source_refs((single_meta or {}).get("sourceRefs"))) if single_meta else [],
            }
            return JsonResponse({"points": [single_point], "explained_variance": [0.0, 0.0]})

        X = np.stack(X, axis=0)
        # Subsample if exceeding limit
        if n > limit > 0:
            idx = np.random.default_rng(seed=42).choice(n, size=limit, replace=False)
            X = X[idx]
            labels = [labels[int(i)] for i in idx]
            metas = [metas[int(i)] for i in idx]
            n = X.shape[0]

        # Center data
        Xc = X - X.mean(axis=0, keepdims=True)
        # SVD-based PCA
        try:
            U, S, Vt = np.linalg.svd(Xc, full_matrices=False)
        except Exception as e:
            logger.error("SVD failed for PCA: %s", e, exc_info=True)
            return JsonResponse({"points": [], "explained_variance": [0.0, 0.0]})

        # Project onto first two principal components
        comps = Vt[:2]  # (2, d)
        scores = Xc @ comps.T  # (n, 2)

        # Explained variance ratio for first two components
        ev = (S ** 2)
        denom = float(ev.sum()) if ev.size else 0.0
        if denom <= 0.0:
            ratios = [0.0, 0.0]
        else:
            ratios = [float(ev[0] / denom), float(ev[1] / denom) if ev.size > 1 else 0.0]

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
        return JsonResponse({"points": points, "explained_variance": ratios})

    except Exception as e:
        logger.error("Error computing PCA points: %s", e, exc_info=True)
        return JsonResponse({"points": [], "explained_variance": [0.0, 0.0]})


# Helper for KPI input parsing

def _coerce_int(value, default_val: int) -> int:
    """Convert various request values (str/list/tuple/int) to int with fallback."""
    try:
        v = value
        if isinstance(v, (list, tuple)):
            v = v[0] if v else default_val
        return int(v)
    except Exception:
        return default_val


@login_required
def create_new_kpi(request: HttpRequest) -> JsonResponse:
    """
    Create a new Kpi object using data from the request.
    Expects POST requests with KPI data (JSON or form data) and returns the new Kpi details.
    """
    if request.method != 'POST':
        logger.warning("Method %s not allowed on create_new_kpi by user %s", request.method, request.user)
        return JsonResponse({'success': False, 'message': 'Method not allowed'}, status=405)

    try:
        data = json.loads(request.body.decode('utf-8')) if request.body else request.POST.dict()
    except ValueError as e:
        logger.error("Invalid JSON data in create_new_kpi: %s", e, exc_info=True)
        return JsonResponse({'success': False, 'message': 'Invalid JSON data'}, status=400)

    # Parse month/year safely
    month_int = _coerce_int(data.get('month', date.today().month), date.today().month)
    year_int = _coerce_int(data.get('year', date.today().year), date.today().year)

    # Create KPI record with normalized fields
    kpi = Kpi.objects.create(month=f"{month_int:02d}", year=str(year_int))

    # Delegate related objects creation/updating to dashboard utils
    try:
        update_all_kpi_stats(kpi, month_int, year_int)
    except Exception as e:
        logger.exception("Failed to update KPI stats on create: %s", e)
        return JsonResponse({'success': False, 'message': 'Failed to compute KPI stats'}, status=500)

    logger.info("New KPI created successfully by user %s", request.user)
    return JsonResponse({'success': True, 'kpi_id': kpi.id})


@login_required
def update_existing_kpi(request: HttpRequest, kpi_id: int) -> JsonResponse:
    """
    Update an existing Kpi object using data from the request.
    Expects POST requests with updated KPI data and returns the updated details.
    """
    if request.method != 'POST':
        logger.warning("Method %s not allowed on update_existing_kpi by user %s", request.method, request.user)
        return JsonResponse({'success': False, 'message': 'Method not allowed'}, status=405)

    kpi = get_object_or_404(Kpi, id=kpi_id)

    try:
        data = json.loads(request.body.decode('utf-8')) if request.body else request.POST.dict()
    except ValueError as e:
        logger.error("Invalid JSON data in update_existing_kpi: %s", e, exc_info=True)
        return JsonResponse({'success': False, 'message': 'Invalid JSON data'}, status=400)

    # Parse month/year and persist on KPI
    month_int = _coerce_int(data.get('month', kpi.month), int(kpi.month) if str(kpi.month).isdigit() else date.today().month)
    year_int = _coerce_int(data.get('year', kpi.year), int(kpi.year) if str(kpi.year).isdigit() else date.today().year)

    kpi.month = f"{month_int:02d}"
    kpi.year = str(year_int)
    kpi.save()

    # Recompute and save related stats
    try:
        update_all_kpi_stats(kpi, month_int, year_int)
    except Exception as e:
        logger.exception("Failed to update KPI stats on update: %s", e)
        return JsonResponse({'success': False, 'message': 'Failed to compute KPI stats'}, status=500)

    logger.info("KPI ID %d updated successfully by user %s", kpi.id, request.user)
    return JsonResponse({'success': True, 'kpi_id': kpi.id})


@login_required
def dashboard_change(request: HttpRequest, month: str, year: str) -> JsonResponse:
    """
    Change the dashboard month and year.
    Returns JSON data with updated scores, mail labels, new users, total reporters, total cases, and stats.
    """
    try:
        new_month = int(month)
        new_year = int(year)
    except ValueError:
        return JsonResponse({'success': False, 'message': 'Invalid month or year'}, status=400)
    
    data = []
    labels = []
    stats = {
        'failure': 0,
        'safe': 0,
        'inconclusive': 0,
        'suspicious': 0,
        'dangerous': 0
    }
    
    # Retrieve data for the top 10 ranks.
    for rank in range(1, 11):
        data.append(get_dashboard_score(rank, 10, new_month, new_year))
        labels.append(get_dashboard_email_prefix(rank, 10, new_month, new_year))
    
    new_users = new_reporters_dash(new_month, new_year)
    total_reporters = total_reporters_dash(new_month, new_year)
    total_cases = get_case_all_dash(new_month, new_year)
    
    for danger in stats:
        stats[danger] = total_by_danger_dash(danger, new_month, new_year)
    
    logger.info("User %s changed dashboard month/year to %d/%d", request.user, new_month, new_year)
    return JsonResponse({
        'success': True,
        'data': data,
        'labels': labels,
        'new_users': new_users,
        'total_reporters': total_reporters,
        'total_cases': total_cases,
        'stats': stats
    })


@login_required
def dashboard_change_scope(request: HttpRequest, month: str, year: str, scope: str) -> JsonResponse:
    """
    Change the scope of the dashboard and retrieve corresponding data.
    Returns JSON data with updated scores, mail labels, new users, total reporters, total cases, and stats based on the given scope.
    """
    try:
        new_month = int(month)
        new_year = int(year)
    except ValueError:
        return JsonResponse({'success': False, 'message': 'Invalid month or year'}, status=400)
    
    new_scope = scope  # Keeping naming as provided
    data = []
    labels = []
    stats = {
        'failure': 0,
        'safe': 0,
        'inconclusive': 0,
        'suspicious': 0,
        'dangerous': 0
    }
    
    for rank in range(1, 11):
        data.append(dashboard_score_scope(rank, 10, new_month, new_year, new_scope))
        labels.append(dashboard_mail_scope(rank, 10, new_month, new_year, new_scope))
    
    new_users = new_reporters_dash_scope(new_scope, new_month, new_year)
    total_reporters = total_reporters_dash_scope(new_scope, new_month, new_year)
    total_cases = get_case_all_dash_scope(new_scope, new_month, new_year)
    
    for danger in stats:
        stats[danger] = total_by_danger_dash_scope(danger, new_month, new_year, new_scope)
    
    logger.info("User %s changed dashboard scope to %s for %d/%d", request.user, new_scope, new_month, new_year)
    return JsonResponse({
        'success': True,
        'data': data,
        'labels': labels,
        'new_users': new_users,
        'total_reporters': total_reporters,
        'total_cases': total_cases,
        'stats': stats
    })

# New endpoint: mail volume data for last 14 days
@login_required
def dashboard_campaigns_mail_volume(request: HttpRequest) -> JsonResponse:
    """
    Return stacked mail volume for the last 15 days.

    Response format:
    {
    "dates": ["YYYY-MM-DD", ...],
    "non_danger": [int, ...],
    "dangerous": [int, ...],
    "campaigns": [ {"name": str, "start": "YYYY-MM-DD", "end": "YYYY-MM-DD"}, ... ]
    }

    """
    # Define 15-day window by UTC dates (inclusive of today)
    today_utc = datetime.now(timezone.utc).date()
    start_utc = today_utc - timedelta(days=14)

    # Ordered list of day buckets
    all_days = [start_utc + timedelta(days=i) for i in range(15)]
    idx = {d: i for i, d in enumerate(all_days)}
    non_danger = [0] * len(all_days)
    dangerous = [0] * len(all_days)

    collection = _get_chroma_collection()
    if collection is None:
        return JsonResponse({
            "dates": [d.isoformat() for d in all_days],
            "non_danger": non_danger,
            "dangerous": dangerous,
            "campaigns": [],
        })

    # Helper to parse datetime-like values and return UTC date
    def _parse_to_utc_date(val):
        if val is None:
            return None
        try:
            # Numeric epoch? seconds or milliseconds
            if isinstance(val, (int, float)):
                try:
                    # Heuristic: milliseconds if large
                    ts = float(val)
                    if ts > 1e12:
                        ts = ts / 1000.0
                    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                    return dt.date()
                except Exception:
                    return None
            s = str(val).strip()
            if not s:
                return None
            # Try ISO-like formats
            s = s.replace("Z", "+00:00")
            dt = None
            try:
                dt = datetime.fromisoformat(s)
            except Exception:
                # Common email date formats often have 'GMT' or commas; try a few fixes
                s2 = s.replace("GMT", "+00:00").replace(",", "")
                try:
                    dt = datetime.fromisoformat(s2)
                except Exception:
                    # Try truncate to seconds
                    core = s
                    if "T" in s:
                        core = s.split("T", 1)[0] + "T" + s.split("T", 1)[1][:8]
                    core = core[:19]
                    try:
                        dt = datetime.fromisoformat(core)
                    except Exception:
                        # Fallback: regex date-only
                        m = re.search(r"(\d{4}-\d{2}-\d{2})", s)
                        if m:
                            try:
                                return datetime.fromisoformat(m.group(1)).date()
                            except Exception:
                                return None
                        return None
            # Assume naive timestamps are UTC
            if dt.tzinfo is None:
                return dt.date()
            return dt.astimezone(timezone.utc).date()
        except Exception:
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
        # Preserve order but deduplicate
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

    def _parse_header_datetime(value):
        if not value:
            return None
        try:
            dt = parsedate_to_datetime(str(value))
            if dt is None:
                return None
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass
        fallback_day = _parse_to_utc_date(value)
        if fallback_day is None:
            return None
        return datetime(fallback_day.year, fallback_day.month, fallback_day.day, tzinfo=timezone.utc)

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

    def _ensure_utc(dt):
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

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
        # Fetch only metadatas to reduce payload; some versions support 'limit'
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
        # Accept multiple possible metadata keys for date and classification
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
                    # 1) Known keys
                    for k in date_keys:
                        if k in meta and meta[k]:
                            dval = meta[k]
                            break
                    # 2) If not found, scan values for date-looking strings or epochs
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
                        sent_dt = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
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

    # Build UTC datetime window [start_of_first_day, start_of_day_after_last_day)
    window_start_dt = datetime(start_utc.year, start_utc.month, start_utc.day, tzinfo=timezone.utc)
    window_end_dt = datetime(today_utc.year, today_utc.month, today_utc.day, tzinfo=timezone.utc) + timedelta(days=1)

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

    return JsonResponse({
        "dates": [d.isoformat() for d in all_days],
        "non_danger": non_danger,
        "dangerous": dangerous,
        "campaigns": campaigns_out,
    })
