import json
import logging

from typing import List
from thehive4py import TheHiveApi
from minio import Minio
from minio.error import S3Error

from mail_feeder.models import MailArtifact, MailAttachment

from .client import TheHiveService

from .models import (
    ChallengerModel,
    ArtifactModel,
    CaseModel,
    MailModel,
    MinioConfig,
)
from .utils import safe, generate_ref, build_mail_attachments_paths

logger = logging.getLogger(__name__)
update_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

class ChallengeToTheHiveService:
    def __init__(self, hive: TheHiveService, minio_cfg: MinioConfig):
        self.hive = hive
        self.minio_cfg = minio_cfg


    def send(self, case, challenger_raw: dict):
        challenger = ChallengerModel(**challenger_raw)
        case_data = CaseModel.model_validate(case.__dict__)

        mail = getattr(getattr(case, "fileOrMail", None), "mail", None)

        if not mail:
            return self._send_without_mail(case_data, challenger)

        mail_data = MailModel(
            subject=getattr(mail, "subject", None),
            mail_from=getattr(mail, "mail_from", None),
            mail_id=getattr(mail, "mail_id", None),
        )

        artifacts = self._extract_artifacts(mail)
        attachments = self._extract_attachments(mail)

        return self._create_alert(
            case_data, mail_data, challenger, artifacts, attachments
        )

    def _extract_artifacts(self, mail) -> List[ArtifactModel]:
        result = []
        for a in MailArtifact.objects.filter(mail=mail):
            if a.artifact_type and a.artifact_value:
                result.append(
                    ArtifactModel(
                        value=a.artifact_value,
                        datatype=a.artifact_type.lower(),
                    )
                )
        return result

    def _extract_attachments(self, mail) -> List[str]:
        return [
            att.file.file_path.name
            for att in MailAttachment.objects.filter(mail=mail)
            if att.file and att.file.file_path
        ]

    def _create_alert(
        self,
        case: CaseModel,
        mail: MailModel,
        challenger: ChallengerModel,
        artifacts: List[ArtifactModel],
        attachments: List[str],
    ):
        api = TheHiveApi(
            url=self.thehive_cfg.url,
            apikey=self.thehive_cfg.api_key,
            verify=self.thehive_cfg.the_hive_verify_ssl,
        )

        ticket_id = generate_ref()
        title = f"Challenge: Case #{case.id} - {safe(mail.subject, 'No Subject')}"

        description = (
            f"# {challenger.firstname} {challenger.lastname} "
            f"({challenger.email}) has challenged case #{case.id}\n\n"
            f"|Value|Description|\n|---|---|\n"
            f"|Mail Subject|{safe(mail.subject)}|\n"
            f"|From|{safe(mail.mail_from)}|\n"
            f"|Case Score|{safe(case.score)}|\n"
            f"|Case Confidence|{safe(case.confidence)}|\n"
            f"|Results|{safe(case.results)}|"
        )

        observables = [
            {"data": a.value, "dataType": a.datatype} for a in artifacts
        ]

        eml = self._fetch_eml(mail.mail_id)
        tmp_path = build_mail_attachments_paths(eml, ticket_id)

        return api.alert.create(
            alert={
                "type": "user_challenge",
                "source": "suspicious",
                "sourceRef": ticket_id,
                "title": title,
                "description": description,
                "observables": observables,
                "severity": 1,
                "tlp": 1,
                "pap": 1,
                "tags": ["challenge", "mail", "suspicious"],
                "customFields": {"tha-id": ticket_id},
            },
            attachment_map={ticket_id: tmp_path} if tmp_path else None,
        )

    def _fetch_eml(self, mail_id: str) -> str:
        if not mail_id:
            return ""

        client = Minio(
            self.minio_cfg.endpoint,
            access_key=self.minio_cfg.access_key,
            secret_key=self.minio_cfg.secret_key,
            secure=False,
        )

        for bucket in client.list_buckets():
            if bucket.name.endswith(f"-{mail_id.split('-')[0]}"):
                try:
                    key = f"{mail_id}/{mail_id}.eml"
                    data = client.get_object(bucket.name, key)
                    return data.read().decode()
                except S3Error:
                    pass
        return ""

    def _create_simple_alert(
        self,
        api: TheHiveApi,
        case: CaseModel,
        challenger: ChallengerModel,
        artifact: ArtifactModel,
        title_suffix: str,
    ):
        ticket_id = generate_ref()

        title = f"Challenge: Case #{case.id} - {title_suffix}"

        description = (
            f"# {challenger.firstname} {challenger.lastname} "
            f"({challenger.email}) has challenged the result of case #{case.id}.\n\n"
            f"|Value|Description|\n"
            f"|---|---|\n"
            f"|Case Score|{safe(case.score)}|\n"
            f"|Case Confidence|{safe(case.confidence)}|\n"
            f"|Results|{safe(case.results)}|"
        )

        return api.alert.create(
            alert={
                "type": "user_challenge",
                "source": "suspicious",
                "sourceRef": ticket_id,
                "title": title,
                "description": description,
                "observables": [
                    {"data": artifact.value, "dataType": artifact.datatype}
                ],
                "severity": 1,
                "tlp": 1,
                "pap": 1,
                "tags": ["challenge", "file_ioc", "suspicious"],
                "customFields": {"tha-id": ticket_id},
            }
        )

    def _send_without_mail(
        self,
        case: CaseModel,
        challenger: ChallengerModel,
    ):
        api = TheHiveApi(
            url=self.thehive_cfg.url,
            apikey=self.thehive_cfg.api_key,
            verify=self.thehive_cfg.the_hive_verify_ssl,
        )

        ticket_id = generate_ref()

        # Case may contain file or non-file IOCs
        fileormail = getattr(case, "fileOrMail", None)

        if fileormail and getattr(fileormail, "file", None):
            file = fileormail.file
            ioc_value = getattr(getattr(file, "linked_hash", None), "value", None)

            if ioc_value:
                artifact = ArtifactModel(value=ioc_value, datatype="hash")
                return self._create_simple_alert(
                    api=api,
                    case=case,
                    challenger=challenger,
                    artifact=artifact,
                    title_suffix=f"File {file.file_path.name}",
                )

        non_file_iocs = getattr(case, "nonFileIocs", None)
        if not non_file_iocs:
            return None

        results = []

        for attr, datatype in (
            ("url", "url"),
            ("ip", "ip"),
            ("hash", "hash"),
        ):
            obj = getattr(non_file_iocs, attr, None)
            value = getattr(obj, "address", None) or getattr(obj, "value", None)

            if value:
                artifact = ArtifactModel(value=value, datatype=datatype)
                results.append(
                    self._create_simple_alert(
                        api=api,
                        case=case,
                        challenger=challenger,
                        artifact=artifact,
                        title_suffix=f"IOC {value} ({datatype})",
                    )
                )

        return results
