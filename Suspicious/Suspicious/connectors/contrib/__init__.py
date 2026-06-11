"""Built-in connectors. Each entry is "module.path:ClassName"; the registry
imports them lazily and records (instead of raising) load failures."""

BUILTIN_CONNECTOR_PATHS: tuple[str, ...] = (
    "connectors.contrib.misp.connector:MISPConnector",
    "connectors.contrib.thehive.connector:TheHiveConnector",
    "connectors.contrib.watcher.connector:WatcherConnector",
    "connectors.contrib.smtp_notify.connector:SmtpNotifyConnector",
)
