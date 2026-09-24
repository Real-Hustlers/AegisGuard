"""Benchmark resource monitoring."""

from __future__ import annotations

import threading

import psutil

from .models import ResourceSnapshot


class ResourceMonitor:

    def __init__(self):
        self.cpu_samples = []
        self.running = False
        self.thread = None

    def _collect(self):
        while self.running:
            self.cpu_samples.append(
                psutil.cpu_percent(
                    interval=0.2
                )
            )

    def start(self):
        self.running = True

        self.thread = threading.Thread(
            target=self._collect,
            daemon=True,
        )

        self.thread.start()

    def stop(self):
        self.running = False

        if self.thread:
            self.thread.join()

    def result(self) -> ResourceSnapshot:

        cpu = 0.0

        if self.cpu_samples:
            cpu = (
                sum(self.cpu_samples)
                /
                len(self.cpu_samples)
            )

        memory = (
            psutil.Process()
            .memory_info()
            .rss
            /
            (1024 * 1024)
        )

        return ResourceSnapshot(
            cpu_percent=round(cpu, 2),
            memory_mb=round(memory, 2),
        )


def capture_resources() -> ResourceSnapshot:
    """
    Backward compatible resource snapshot.
    """

    process = psutil.Process()

    return ResourceSnapshot(
        cpu_percent=process.cpu_percent(),
        memory_mb=round(
            process.memory_info().rss
            /
            (1024 * 1024),
            2,
        ),
    )
