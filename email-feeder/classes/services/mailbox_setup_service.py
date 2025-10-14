import logging
import classes.models.configs.main_config
import classes.models.configs.internals.imap
import classes.services.mailbox_service


def setup_mailboxes(
    config: classes.models.configs.main_config.MainConfig,
    logger: logging.Logger,
) -> list[classes.services.mailbox_service.Mailbox]:
    """
    Connects to mailboxes defined in the configuration file and returns a list of Mailbox objects.

    Args:
        config: A MainConfig object containing the whole project configuration.
                It is expected to have both "mail-connectors" and "working-path"
                sections.

    Returns:
        A list of successfully initialized and logged-in Mailbox objects.
    """
    mailboxes: list[classes.services.mailbox_service.Mailbox] = []

    mail_connectors: list[
        tuple[str, dict[str, classes.models.configs.internals.imap.IMAPConfig]]
    ] = [
        ("imap", config.mail_connectors.imap),
        ("imaps", config.mail_connectors.imaps),
    ]

    for connector_type, connectors in mail_connectors:
        for instance_name, instance_config in connectors.items():
            logger.info(
                f"Processing mailbox instance: {instance_name} (Type: {connector_type})"
            )

            if not instance_config.enable:
                logger.info(
                    f"Mailbox instance '{instance_name}' is disabled. Skipping."
                )
                continue

            mailbox = classes.services.mailbox_service.Mailbox(
                config=instance_config,
                logger=logger,
                tmp_path=config.working_path,
            )

            logger.info(
                f"Attempting to login to mailbox: {instance_name} ({instance_config.login}@{instance_config.host})..."
            )

            try:
                mailbox.login()
            except ConnectionError as e:
                logger.error(
                    f"Failed to connect or login to mailbox '{instance_name}': {e}"
                )
            except KeyError as e:
                logger.error(
                    f"Configuration error for Mailbox '{instance_name}': Missing key {e}"
                )
            except Exception as e:
                logger.error(
                    f"An unexpected error occurred while setting up mailbox '{instance_name}': {e}",
                    exc_info=True,
                )
            else:
                mailboxes.append(mailbox)
                logger.info(
                    f"Successfully connected and logged into mailbox: {instance_name}."
                )

    if len(mailboxes) == 0:
        logger.warning(
            "No mailboxes were successfully set up. Check configuration and logs."
        )
    else:
        logger.info(f"Successfully set up {len(mailboxes)} mailbox(es).")

    return mailboxes
