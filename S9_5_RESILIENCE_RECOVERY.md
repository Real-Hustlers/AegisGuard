# S9.5 Resilience & Recovery Hardening

Flow:

Failure Detected
        |
        v
Recovery Decision
        |
        v
Recovery Action
        |
        v
Validation
        |
   +----+----+
   |         |
 READY    DEGRADED

Goals:
- Detect failures.
- Recover safely.
- Validate restored state.
- Preserve recovery evidence.
