# S3-4C — Final Collector / Device Security Closure

S3-4C closes S3 by wiring authenticated heartbeat cadence into the live Windows
collector and adding one final end-to-end security lifecycle proof.

## Live heartbeat cadence

The collector reads:

```text
collector_heartbeat_interval_seconds
```

The default is 30 seconds.

Heartbeat is enabled only when authenticated collector mode is enabled and a
heartbeat URL is configured.

The live collector attempts heartbeat after its normal collection / durable
delivery work for the current polling cycle. A network or validation failure in
heartbeat is logged and scheduled for the next interval; it does not delete
pending batches, move the ACK checkpoint, or terminate the collection loop.

The heartbeat scheduler uses a monotonic clock so wall-clock corrections do not
cause accidental bursts or long skips.

## Final S3 lifecycle proof

`tests/platform/test_s34_security_end_to_end.py` proves one collector through:

1. mTLS-bound enrollment;
2. authenticated heartbeat;
3. durable batch acceptance;
4. duplicate retry without duplicate persistence;
5. bearer credential rotation;
6. rejection of the old credential;
7. certificate rotation staging;
8. first successful use of the new certificate promotes it;
9. rejection of the old certificate;
10. persistent server-observed mTLS heartbeat state;
11. collector revocation;
12. heartbeat rejection after revocation;
13. batch rejection after revocation without persistence.

A separate restart test reopens the durable collector state and proves the same
collector identity, protected credential, ACK checkpoint, pending batch, and
staged certificate-transition state survive restart.

## Existing real TLS proof

S3-4C deliberately does not duplicate the real OpenSSL handshake test already
covered by `test_production_mtls_e2e.py`. That test remains the authoritative
proof that:

- no client certificate is rejected at TLS;
- a rogue-CA client certificate is rejected at TLS;
- a trusted bound certificate reaches the collector API.

## S3 completion condition

S3 is complete only after the S3-4C focused suite, the existing production mTLS
E2E, and the full project regression all pass on the exact staged state and the
result is merged into `product/integration`.
