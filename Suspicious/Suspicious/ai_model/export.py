"""The ledger export a training job reads (Plan E, Task 8a): the trainable rows (trust `folder`,
status `active`; verdict and challenge rows are provenance, spec section 4) as the npz of
training/dataset.py, uploaded under DATASET_BUCKET/<job_id>/dataset.npz with a short presigned
GET. The digests the job params need are computed here and returned next to the URL, not stored in
the file. No mail text: embeddings, folder labels and case ids only. The URL is not logged."""
import io
import json
from dataclasses import dataclass

from case_handler.models import CampaignMember

from . import registry, training_data
from .models import LabelRecord
from .training_data import TRAINING_PREPROCESSING

ExportRefused = training_data.DatasetRefused


@dataclass(frozen=True)
class LedgerExport:
    key: str  # in registry.DATASET_BUCKET
    url: str  # presigned GET, registry.PRESIGN_EXPIRY; never log it
    rows: int
    excluded: int  # trainable rows left out: not embedded in TRAINING_PREPROCESSING
    ledger_digest: str  # sorted (message_id_hash, label) pairs
    campaign_refs: tuple[str, ...]  # campaigns the exported cases belong to
    campaign_refs_digest: str


def trainable_rows():
    return LabelRecord.objects.filter(trust=LabelRecord.Trust.FOLDER, status=LabelRecord.Status.ACTIVE)


def campaign_ties(case_ids) -> list[tuple[int, int]]:
    """Row index pairs that the campaign groups must join: the rows of each campaign's member cases
    (CampaignMember), chained in row order, so members far apart in the embedding space never
    straddle a fold (spec section 5)."""
    rows_of = {}
    for i, case_id in enumerate(case_ids):
        if case_id is not None:
            rows_of.setdefault(case_id, []).append(i)
    members = {}
    for campaign_id, case_id in CampaignMember.objects.filter(case_id__in=rows_of).values_list(
            "campaign_id", "case_id"):
        members.setdefault(campaign_id, []).extend(rows_of[case_id])
    ties = []
    for rows in members.values():
        rows = sorted(set(rows))
        ties.extend(zip(rows, rows[1:]))
    return sorted(ties)


def export_ledger(job_id: str) -> LedgerExport:
    """ExportRefused (a clear message) when no trainable row is in the training preprocessing, a
    head class has fewer than 8 rows or there are too many rows; RegistryError for a bad job_id.

    Trainable rows not embedded in TRAINING_PREPROCESSING are left out and counted (`excluded`):
    a row whose mail can no longer be fetched for `manage.py ai_model_reembed_ledger` would
    otherwise block every retrain. Every row synced before Task 8a is legacy-first128, so the
    re-embed command must run once before the first export has anything to train on.

    case_ids: a row without a case is NO_CASE (-1). Two active folder rows of the same case (two
    messages matched to it) keep the id on the first row in pk order and write -1 on the later
    ones, as the reader wants real ids unique; classify's exclude_case_ids then leaves only the
    first row out of that case's neighbours."""
    key = registry.dataset_key_for(job_id)
    trainable = trainable_rows()
    excluded = trainable.exclude(preprocessing_version=TRAINING_PREPROCESSING).count()
    rows = trainable.filter(preprocessing_version=TRAINING_PREPROCESSING).order_by("pk")
    if not rows.exists():
        raise ExportRefused(f"no trainable row is embedded in {TRAINING_PREPROCESSING} "
                            f"({excluded} left out: run manage.py ai_model_reembed_ledger)")
    count = rows.count()
    if count > training_data.MAX_ROWS:  # before loading the vectors
        raise ExportRefused(f"the ledger has {count} rows, at most {training_data.MAX_ROWS} can be trained on")
    values = list(rows.values_list("label", "embedding", "campaign_embedding", "case_id", "message_id_hash"))
    try:
        parsed = [(label, json.loads(emb), json.loads(cmp), case_id)
                  for label, emb, cmp, case_id, _ in values]
    except ValueError:
        raise ExportRefused("a trainable row has an unreadable embedding") from None
    ties = campaign_ties([v[3] for v in values])
    try:
        data = training_data.build_dataset(parsed, ties)
    except ExportRefused as exc:
        if not excluded:
            raise
        raise ExportRefused(f"{exc} ({excluded} row(s) not in {TRAINING_PREPROCESSING} left out)") from None
    case_ids = {v[3] for v in values if v[3] is not None}
    refs = tuple(sorted(set(CampaignMember.objects.filter(case_id__in=case_ids)
                            .values_list("campaign__ref", flat=True))))
    registry.ensure_dataset_bucket()
    store = registry.get_store()
    store.put(registry.DATASET_BUCKET, key, io.BytesIO(data), length=len(data),
              content_type="application/octet-stream")
    return LedgerExport(
        key=key,
        url=store.presign_get(registry.DATASET_BUCKET, key, registry.PRESIGN_EXPIRY),
        rows=len(values),
        excluded=excluded,
        ledger_digest=training_data.digest((h, label) for label, _, _, _, h in values),
        campaign_refs=refs,
        campaign_refs_digest=training_data.digest(refs),
    )
