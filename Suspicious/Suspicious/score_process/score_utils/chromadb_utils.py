from secrets import token_hex
import json
from datetime import datetime

import logging

logger = logging.getLogger(__name__)
update_cases_logger = logging.getLogger('tasp.cron.update_ongoing_case_jobs')

def get_suspicious_collection(chroma_client):
        return chroma_client.get_or_create_collection(
            name="suspicious_mails",
            metadata={
                "hnsw:space": "cosine",
            }
        )

def get_similar_dangerous_mails(embedding, suspicious_collection):
    # Ensure embedding is properly loaded from JSON
    try:
        embedding_data = json.loads(embedding)
        if not isinstance(embedding_data, list):
            embedding_data = [embedding_data]
    except json.JSONDecodeError:
        update_cases_logger.error(f"Error decoding embedding JSON: {embedding}")
        return {}

    similar_mails = suspicious_collection.query(
        query_embeddings=embedding_data,
        where={"classification": "DANGEROUS"},
        n_results=70,
        include=["embeddings", "metadatas", "documents", "distances"]
    )

    return similar_mails

def add_to_suspicious_collection(full, alert_id, sourceRef, suspicious_case_id, suspicious_collection):
    timestamp = datetime.now()

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
            'alert_ids': "[" + str(alert_id) + "]",
            'sourceRefs': "[" + str(sourceRef) + "]",
            'suspicious_case_id': str(suspicious_case_id),
        }],
        ids=timestamp.strftime("%y%m%d") + "-" + str(token_hex(8))
    )

    return timestamp

def update_suspicious_collection(phishing_campaign, alert_id, sourceRef, suspicious_collection):
    for i in range(len(phishing_campaign['ids'][0])):
        updated_metadatas = phishing_campaign['metadatas'][0][i]
        updated_metadatas['alert_ids'] = str(json.loads(updated_metadatas['alert_ids']) + [alert_id])
        updated_metadatas['sourceRefs'] = str(json.loads(updated_metadatas['sourceRefs']) + [sourceRef])
        suspicious_collection.update(
            ids=phishing_campaign['ids'][0][i],
            metadatas=updated_metadatas
        )