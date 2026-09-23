# S7-D — Governed Legacy Collector Raw Output

S7-D closes the plaintext raw-output gap in the legacy/manual Windows
collector. The durable collector path is unchanged.

## Default policy

Local raw-log persistence is disabled by default with
`raw_output_enabled: false`. The configured path remains available only for
explicit diagnostic opt-in.

## Opt-in controls

When explicitly enabled:

- output paths must be relative to the runtime directory;
- absolute paths and parent-directory traversal are rejected;
- writes use a temporary file followed by atomic replacement;
- owner-only POSIX mode is requested where supported.

These controls are defense in depth, not a substitute for deployment-level
disk encryption.

## Console minimization

The legacy collector no longer prints complete Windows Security event bodies,
and malformed PowerShell JSON no longer causes raw event output to be dumped
to the console.

## Scope

S7-D does not modify canonical analyzer evidence, durable collector spooling,
incident data, audit data, ML, detection, correlation, MITRE, or response
execution.
