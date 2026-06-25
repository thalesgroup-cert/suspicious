import logging
import classes.models.configs.main_config
import classes.models.configs.internals.imap
import classes.services.mailbox_service


def connector_items(config) -> dict:
    """All (name -> IMAPConfig) across the imap + imaps connector sections."""
    items: dict = {}
    for name, c in config.mail_connectors.imap.items():
        items[name] = c
    for name, c in config.mail_connectors.imaps.items():
        items[name] = c
    return items


_CONNECTOR_FIELDS = (
    "host", "port", "login", "password", "use_ssl",
    "certfile", "keyfile", "rootcafile", "mailbox_to_monitor",
)


def _connector_changed(a, b) -> bool:
    return any(getattr(a, f, None) != getattr(b, f, None) for f in _CONNECTOR_FIELDS)


def diff_mailbox_configs(old_config, new_config):
    """Return (to_start, to_stop) for a hot config reload.

    A *changed* connector appears in BOTH lists (stop the old config, start the
    new one) so the caller can replace it without tracking connector names on
    the live Mailbox objects. Pure function — the caller applies the diff
    (login the to_start configs, logout the to_stop ones).
    """
    old = connector_items(old_config)
    new = connector_items(new_config)
    to_start = []
    for name, c in new.items():
        o = old.get(name)
        changed = o is not None and o.enable and _connector_changed(o, c)
        if c.enable and (o is None or not o.enable or changed):
            to_start.append((name, c))
    to_stop = []
    for name, c in old.items():
        if not c.enable:
            continue
        n = new.get(name)
        changed = n is not None and _connector_changed(c, n)
        if n is None or not n.enable or changed:
            to_stop.append((name, c))
    return to_start, to_stop


def _mailbox_identity(cfg) -> tuple:
    return (cfg.login, cfg.host, cfg.port, cfg.mailbox_to_monitor)


def apply_mailbox_diff(current, to_start, to_stop, working_path, logger):
    """Apply a hot-reload diff: logout stopped mailboxes, login started ones.

    Stopped mailboxes are matched to live Mailbox objects by connection
    identity (login, host, port, mailbox). Returns the new mailbox list.
    Login failures are logged and skipped — they never abort the reload.
    """
    imap_logger = logging.getLogger("email-feeder.imap")
    stop_ids = {_mailbox_identity(c) for _, c in to_stop}

    kept = []
    for mb in current:
        if _mailbox_identity(mb.config) in stop_ids:
            try:
                mb.logout()
            except Exception as e:  # noqa: BLE001
                logger.warning("Logout failed during reload for %s: %s",
                               mb.config.login, e)
            logger.info("Stopped mailbox %s@%s", mb.config.login, mb.config.host)
        else:
            kept.append(mb)

    for name, c in to_start:
        mb = classes.services.mailbox_service.Mailbox(
            config=c, logger=imap_logger, tmp_path=working_path,
        )
        try:
            mb.login()
            kept.append(mb)
            logger.info("Started mailbox '%s' (%s@%s)", name, c.login, c.host)
        except Exception as e:  # noqa: BLE001
            logger.error("Failed to start mailbox '%s': %s", name, e)

    return kept


def setup_mailboxes(
    config: classes.models.configs.main_config.MainConfig,
    logger: logging.Logger,
) -> list[classes.services.mailbox_service.Mailbox]:
    # IMAP fetch/login/seen activity goes to the dedicated imap domain logger
    # (-> imap.log + json stdout). The passed-in `logger` (root email-feeder)
    # is still used for setup-level lifecycle messages.
    imap_logger = logging.getLogger("email-feeder.imap")
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
                logger=imap_logger,
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
