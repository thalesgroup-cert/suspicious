"""
This module provides different interfaces allowing the parsing all the configs
from a JSON object.
"""

import pydantic
import pathlib
import typing


import classes.models.configs.internals.imap
import classes.models.configs.internals.minio
import classes.models.configs.internals.mail


class MainConfigMailConnectorsConfig(pydantic.BaseModel):
    imap: dict[str, classes.models.configs.internals.imap.IMAPConfig] = pydantic.Field(
        default_factory=dict[str, classes.models.configs.internals.imap.IMAPConfig]
    )
    """All the non-SSL IMAP configurations."""

    imaps: dict[str, classes.models.configs.internals.imap.IMAPConfig] = pydantic.Field(
        default_factory=dict[str, classes.models.configs.internals.imap.IMAPConfig]
    )
    """All the SSL IMAP configurations."""


DEFAULT_CASE_BASE_PATH = pathlib.Path("/app/case")
DEFAULT_SLEEP_INTERVAL = 10  # seconds


class MainConfig(pydantic.BaseModel):
    mail_connectors: MainConfigMailConnectorsConfig
    """All the IMAP connectors configuration."""

    minio: classes.models.configs.internals.minio.MinioConfig
    """The Minio configuration."""

    mail: classes.models.configs.internals.mail.MailConfig
    """The mailing configuration."""

    working_path: pathlib.Path = pydantic.Field(default=DEFAULT_CASE_BASE_PATH)
    """The working path for the different email processing."""

    timer_inbox_emails: int | float = pydantic.Field(default=DEFAULT_SLEEP_INTERVAL)
    """Delay (in seconds) between each mailbox refresh."""

    @staticmethod
    def from_json(json_object: dict[str, typing.Any]) -> "MainConfig":
        raw_mail_connectors = json_object.get("mail-connectors")
        if raw_mail_connectors is None:
            mail_connectors = MainConfigMailConnectorsConfig()
        else:
            raw_mail_connectors_imap = raw_mail_connectors.get("imap", {})
            raw_mail_connectors_imaps = raw_mail_connectors.get("imaps", {})
            mail_connectors = MainConfigMailConnectorsConfig(
                imap={
                    connector_name: classes.models.configs.internals.imap.IMAPConfig(
                        **connector
                    )
                    for connector_name, connector in raw_mail_connectors_imap.items()
                },
                imaps={
                    connector_name: classes.models.configs.internals.imap.IMAPConfig(
                        **connector
                    )
                    for connector_name, connector in raw_mail_connectors_imaps.items()
                },
            )

        working_path = json_object.get("working-path", "/app/case")

        timer_inbox_emails = json_object.get("timer-inbox-emails", 10)

        raw_minio = json_object.get("minio")
        if raw_minio is None:
            raise ValueError("You must provide a configuration for 'minio'.")
        required_minio_keys = {"endpoint", "access_key", "secret_key"}
        if set(raw_minio) < required_minio_keys:
            raise ValueError(
                f"Some Minio configuration are not set. Expected: {', '.join(required_minio_keys)}"
            )
        minio = classes.models.configs.internals.minio.MinioConfig(
            endpoint=raw_minio["endpoint"],
            access_key=raw_minio["access_key"],
            secret_key=raw_minio["secret_key"],
        )

        raw_mail = json_object.get("mail")
        if raw_mail is None:
            raise ValueError("You must provide a configuration for 'mail'.")
        required_mail_keys = {"server"}
        if set(raw_mail) < required_mail_keys:
            raise ValueError(
                f"Some Minio configuration are not set. Expected: {', '.join(required_mail_keys)}"
            )
        mail = classes.models.configs.internals.mail.MailConfig(**raw_mail)

        return MainConfig(
            mail_connectors=mail_connectors,
            minio=minio,
            mail=mail,
            working_path=working_path,
            timer_inbox_emails=timer_inbox_emails,
        )
