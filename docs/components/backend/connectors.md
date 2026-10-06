# connectors

Plugin framework every integration with an external system (TheHive, MISP,
Watcher, ChromaDB, SMTP notifications, the `ai_narration` LLM connector) is
built on: registry, event dispatch, retry + circuit breaker, and a
`ConnectorDelivery` audit ledger.

See [`Suspicious/Suspicious/connectors/README.md`](https://github.com/thalesgroup-cert/suspicious/blob/main/Suspicious/Suspicious/connectors/README.md)
for the framework internals and the built-in connector table, and
[Connectors (author guide)](../../connectors.md) for writing a new one.
