# S2A Durable Collector Transport

S2A introduces the enterprise transport foundation alongside the verified
legacy upload path.

## Guarantees in this slice

- A collector can persist its outbound batches in a local SQLite spool.
- The collector checkpoint advances only when a queued batch is acknowledged.
- Collector identity is persisted locally instead of being derived only from
  hostname.
- Remote analyzer URLs must use HTTPS. Plain HTTP is accepted only for loopback
  development.
- TLS certificate verification is enabled by default and can use an explicit CA
  bundle.
- Enterprise batches carry stable collector_id and batch_id values.
- The server writes the complete batch to collector_ingest_batches before
  returning HTTP 202.
- Retrying the same batch_id is idempotent.
- The HTTP request path does not run ML, correlation, or incident generation.

## Deliberate boundary

This is not the complete S2/S3 security model.

S2B will drain QUEUED batches into the existing event/detection pipeline outside
the request/ACK path and wire the live Windows collector to the durable spool.

S3 will add collector enrollment, per-device credentials/certificates,
revocation, heartbeat, and server-side rejection of unknown or revoked
collectors.

Until S3 is complete, the enterprise ingestion endpoint must be exposed only
through server-authenticated TLS and trusted network controls.
