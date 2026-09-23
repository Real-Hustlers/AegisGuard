# S13-A Performance Benchmark Foundation

## Purpose

S13-A establishes a reproducible measurement baseline for the merged AegisGuard Enterprise pipeline before any performance optimization is attempted.

The benchmark uses generated synthetic records only. It does not use customer logs and it does not alter collector authentication, mTLS, credential custody, RBAC, audit integrity, incident lifecycle, or response execution.

## Measured boundaries

The harness reports separate metrics for:

- collector durable-spool enqueue
- collector local durable ACK/checkpoint handling
- analyzer collector HTTP durable-ACK path using an in-process Flask client
- server durable-queue persistence
- server durable-queue claim/drain state transitions
- deterministic rule-engine processing
- governed ML inference
- correlation
- MITRE projection
- attack-story construction
- combined intelligence analysis
- `/api/intelligence` DB-read + analysis + JSON response through an in-process Flask client
- intelligence payload size
- collector/server SQLite storage growth and queue/backlog state

Every timed metric reports throughput plus p50, p95, and p99 latency. The report also records error count, process CPU time, an approximate host-normalized CPU percentage, Python allocation peak, and RSS before/after when `psutil` is already installed.

No performance threshold or product guarantee is encoded in the harness.

## Reproduction context

Each JSON report records:

- UTC run timestamp
- Python version and implementation
- operating system/platform
- machine/processor strings
- logical CPU count
- detected host memory
- relevant dependency versions
- synthetic dataset size
- event count
- batch size
- batch count
- iteration count
- warm-up count
- ML model name/version/feature schema and whether it came from a promoted registry

## Default baseline

From the repository root:

```powershell
python scripts/run_s13a_benchmark.py `
  --events 1000 `
  --batch-size 100 `
  --iterations 5 `
  --warmup 1
```

The default report is written under `output/benchmarks/`, which is already ignored by the repository.

Example with an explicit file:

```powershell
python scripts/run_s13a_benchmark.py `
  --events 1000 `
  --batch-size 100 `
  --iterations 5 `
  --warmup 1 `
  --output output/benchmarks/s13a-baseline.json
```

## Promoted governed model

For a machine that has a verified promoted Y11 model registry:

```powershell
python scripts/run_s13a_benchmark.py `
  --events 1000 `
  --batch-size 100 `
  --iterations 5 `
  --warmup 1 `
  --registry-root data/ml_registry `
  --model-name aegis-threat-classifier
```

When `--registry-root` is omitted, the benchmark uses a small deterministic synthetic RandomForest model only so that the benchmark foundation is runnable on clean development/CI environments. The report explicitly marks that model as non-production.

## Security and network limitation

The S13-A harness deliberately does **not** disable or bypass security in the production application.

The in-process collector HTTP fixture is created with collector authentication and mTLS disabled only inside the isolated benchmark Flask app. It is used to measure request parsing through durable queue persistence and the HTTP 202 ACK boundary without modifying production configuration.

Real TCP/TLS/mTLS latency, certificate validation cost, authenticated collector transport, and WAN/LAN behavior are not claimed by S13-A. Those measurements belong in the authorized isolated S11/S13-B validation environment using the same workload/reporting methodology.

Likewise, the server queue-drain benchmark uses a no-op processor to isolate durable queue claim/state-transition cost. Full intelligence analysis is measured separately.

## Interpretation

Benchmark results are measurements from the machine that produced the report. They are not universal AegisGuard throughput guarantees.

Compare runs only when the reproduction context and workload are sufficiently similar. S13-B should rerun the same baseline before and after any optimization and should optimize only measured bottlenecks.
