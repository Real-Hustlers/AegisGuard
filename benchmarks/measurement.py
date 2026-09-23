"""Measurement utilities for AegisGuard S13-A benchmarks."""

from __future__ import annotations

import ctypes
import importlib.metadata
import os
import platform
import statistics
import time
import tracemalloc
from datetime import datetime, timezone
from typing import Any, Callable, Iterable


def percentile(values: Iterable[float], percent: float) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * (float(percent) / 100.0)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def summarize_latencies(values: Iterable[float]) -> dict[str, float]:
    samples = [float(value) for value in values]
    if not samples:
        return {key: 0.0 for key in ("min", "mean", "p50", "p95", "p99", "max")}
    return {
        "min": round(min(samples), 4),
        "mean": round(statistics.fmean(samples), 4),
        "p50": round(percentile(samples, 50), 4),
        "p95": round(percentile(samples, 95), 4),
        "p99": round(percentile(samples, 99), 4),
        "max": round(max(samples), 4),
    }


def _rss_bytes() -> int | None:
    try:
        import psutil  # type: ignore
        return int(psutil.Process().memory_info().rss)
    except (ImportError, Exception):
        return None


def _host_memory_bytes() -> int | None:
    if os.name == "nt":
        class MemoryStatusEx(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        status = MemoryStatusEx()
        status.dwLength = ctypes.sizeof(MemoryStatusEx)
        try:
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.ullTotalPhys)
        except Exception:
            return None
        return None

    try:
        return int(os.sysconf("SC_PAGE_SIZE")) * int(os.sysconf("SC_PHYS_PAGES"))
    except (AttributeError, OSError, ValueError):
        return None


def reproduction_context() -> dict[str, Any]:
    packages = {}
    for name in ("flask", "requests", "pandas", "scikit-learn", "joblib", "psutil"):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = None
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpu_count": os.cpu_count(),
        "host_memory_bytes": _host_memory_bytes(),
        "dependencies": packages,
    }


def measure(
    name: str,
    operation: Callable[[int], int],
    *,
    iterations: int,
    warmup: int = 0,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if iterations < 1:
        raise ValueError("iterations must be at least 1")
    if warmup < 0:
        raise ValueError("warmup must be non-negative")

    for index in range(warmup):
        operation(-(index + 1))

    latencies_ms = []
    errors = []
    total_units = 0
    rss_before = _rss_bytes()
    cpu_started = time.process_time()
    wall_started = time.perf_counter()
    current_allocated = 0
    peak_allocated = 0
    tracemalloc.start()
    try:
        for index in range(iterations):
            started = time.perf_counter()
            try:
                units = int(operation(index))
                if units < 0:
                    raise ValueError("operation returned negative units")
                total_units += units
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
            finally:
                latencies_ms.append((time.perf_counter() - started) * 1000.0)
        current_allocated, peak_allocated = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    wall_seconds = time.perf_counter() - wall_started
    cpu_seconds = time.process_time() - cpu_started
    rss_after = _rss_bytes()
    cpu_count = max(1, int(os.cpu_count() or 1))

    return {
        "name": name,
        "iterations": iterations,
        "successful_iterations": iterations - len(errors),
        "error_count": len(errors),
        "errors": errors,
        "total_units": total_units,
        "throughput_units_per_second": round(
            total_units / wall_seconds if wall_seconds > 0 else 0.0,
            3,
        ),
        "latency_ms": summarize_latencies(latencies_ms),
        "wall_seconds": round(wall_seconds, 6),
        "process_cpu_seconds": round(cpu_seconds, 6),
        "host_cpu_percent_estimate": round(
            (cpu_seconds / wall_seconds / cpu_count) * 100.0
            if wall_seconds > 0 else 0.0,
            3,
        ),
        "python_allocated_bytes_end": int(current_allocated),
        "python_peak_allocated_bytes": int(peak_allocated),
        "rss_before_bytes": rss_before,
        "rss_after_bytes": rss_after,
        "rss_delta_bytes": (
            rss_after - rss_before
            if rss_before is not None and rss_after is not None
            else None
        ),
        "metadata": metadata or {},
    }
