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
    ledger_digest: str  # sorted (message_id_hash, label) pairs
    campaign_refs: tuple[str, ...]  # campaigns the exported cases belong to
    campaign_refs_digest: str


def trainable_rows():
    return LabelRecord.objects.filter(trust=LabelRecord.Trust.FOLDER, status=LabelRecord.Status.ACTIVE)


def export_ledger(job_id: str) -> LedgerExport:
    """ExportRefused (a clear message) when rows are in another preprocessing, a head class has
    fewer than 8 rows or there are too many rows; RegistryError for a bad job_id.

    case_ids: a row without a case is NO_CASE (-1). Two active folder rows of the same case (two
    messages matched to it) keep the id on the first row in pk order and write -1 on the later
    ones, as the reader wants real ids unique; classify's exclude_case_ids then leaves only the
    first row out of that case's neighbours.

    Every row synced before Task 8a is legacy-first128, so this refuses until
    `manage.py ai_model_reembed_ledger` has run once."""
    key = registry.dataset_key_for(job_id)
    rows = trainable_rows().order_by("pk")
    stale = rows.exclude(preprocessing_version=TRAINING_PREPROCESSING).count()
    if stale:
        raise ExportRefused(f"{stale} trainable row(s) are not embedded in {TRAINING_PREPROCESSING}: "
                            "run manage.py ai_model_reembed_ledger first")
    count = rows.count()
    if count > training_data.MAX_ROWS:  # before loading the vectors
        raise ExportRefused(f"the ledger has {count} rows, at most {training_data.MAX_ROWS} can be trained on")
    values = list(rows.values_list("label", "embedding", "campaign_embedding", "case_id", "message_id_hash"))
    try:
        parsed = [(label, json.loads(emb), json.loads(cmp), case_id)
                  for label, emb, cmp, case_id, _ in values]
    except ValueError:
        raise ExportRefused("a trainable row has an unreadable embedding") from None
    data = training_data.build_dataset(parsed)
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
        ledger_digest=training_data.digest((h, label) for label, _, _, _, h in values),
        campaign_refs=refs,
        campaign_refs_digest=training_data.digest(refs),
    )
