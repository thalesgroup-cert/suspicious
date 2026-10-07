from secrets import token_hex
import json
import ast
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
update_cases_logger = logging.getLogger('tasp.cron.update_ongoing_case_jobs')


def get_suspicious_collection(chroma_client):
    return chroma_client.get_or_create_collection(
        name="suspicious_mails",
        metadata={"hnsw:space": "cosine"},
    )


def get_similar_dangerous_mails(embedding, suspicious_collection, n_results: int = 20):
    try:
        embedding_data = json.loads(embedding)
        if not isinstance(embedding_data, list):
            embedding_data = [embedding_data]
    except (json.JSONDecodeError, TypeError):
        update_cases_logger.error(f"Error decoding embedding JSON: {embedding}")
        return {}

    return suspicious_collection.query(
        query_embeddings=embedding_data,
        where={"classification": "DANGEROUS"},
        n_results=n_results,
        include=["embeddings", "metadatas", "documents", "distances"],
    )


def add_to_suspicious_collection(full, alert_id, sourceRef, suspicious_case_id, suspicious_collection):
    timestamp = datetime.now()

    # One document per case: the report is re-parsed on every reconcile pass, and
    # each extra copy would count as another "similar mail" towards a campaign.
    doc_id = f"case-{suspicious_case_id}"
    if suspicious_case_id is not None and suspicious_collection.get(ids=[doc_id]).get("ids"):
        return None

    suspicious_collection.add(
        documents=full["report"]["analyzed_mail_content"],
        embeddings=json.loads(full["report"]["email_embedding"]),
        metadatas=[{
            'detection_date': str(timestamp),
            'malscore': str(full["malscore"]),
            'confidence': str(full["confidence"]),
            'classification': str(full["classification"]),
            'sub_classification': str(full["sub_classification"]),
            'headers': str(full["report"]["analyzed_mail_headers"]),
            'alert_ids': json.dumps([str(alert_id)]),
            'sourceRefs': json.dumps([str(sourceRef)]),
            'suspicious_case_id': str(suspicious_case_id),
        }],
        ids=doc_id if suspicious_case_id is not None
        else timestamp.strftime("%y%m%d") + "-" + str(token_hex(8)),
    )

    return timestamp


def _parse_list_field(value: str) -> list:
    """Parse a stored list field — handles both JSON and ast.literal_eval formats."""
    try:
        result = json.loads(value)
        if isinstance(result, list):
            return result
    except (json.JSONDecodeError, TypeError):
        pass
    try:
        result = ast.literal_eval(value)
        if isinstance(result, list):
            return result
    except Exception:
        pass
    update_cases_logger.warning(f"Could not parse list field, wrapping as-is: {value!r}")
    return [value] if value else []


def set_campaign_ref(suspicious_collection, doc_ids, ref):
    """Tag documents with their campaign: the Campaigns page groups mails by sourceRefs."""
    found = suspicious_collection.get(ids=list(doc_ids))
    for doc_id, metadata in zip(found.get("ids") or [], found.get("metadatas") or []):
        updated = dict(metadata)
        updated["sourceRefs"] = json.dumps([ref])
        suspicious_collection.update(ids=doc_id, metadatas=updated)
