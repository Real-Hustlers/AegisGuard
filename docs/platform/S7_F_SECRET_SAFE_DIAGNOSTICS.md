# S7-F — Collector Privacy Closure and Secret-Safe Diagnostics

S7-F closes the remaining collector-side privacy bypass and makes diagnostic
output safe for secret-bearing failures without changing ingestion semantics.

## Legacy entrypoint closure

`backend/collector/main.py` no longer writes `raw_output_file` directly.
Historical collection now calls the governed `save_raw_logs()` path introduced
in S7-D, so local raw persistence remains disabled unless an operator explicitly
opts in.

## Secret-safe diagnostics

Collector diagnostics now:

- redact secret-bearing JSON fields in Analyzer responses;
- redact secret-bearing exception text before console output;
- strip URL userinfo, query strings, and fragments from displayed endpoints;
- omit raw Windows Security event bodies when PowerShell JSON parsing fails;
- remove usernames from per-event live-console lines;
- sanitize durable upload errors before both SQLite persistence and console
  output.

Security telemetry wording such as `Failed password for alice` is not treated as
a credential by itself; actual credential/token fields are redacted.

## Packaging

The Windows collector PyInstaller specification explicitly includes the
diagnostic/privacy helper modules.

## Scope

S7-F does not alter collector authentication, retry/ACK semantics, detection,
classification, correlation, ML, canonical analyzer evidence, incident
semantics, audit integrity, or response execution.
