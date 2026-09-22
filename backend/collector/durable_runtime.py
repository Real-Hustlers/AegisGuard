"""Durable authenticated Windows collector runtime."""

import hashlib
import os
import secrets
import time
import uuid
from pathlib import Path
from typing import Callable, Optional

import requests

from backend.collector.state import CollectorState
from backend.collector.transport import (
    build_batch_payload,
    build_enrollment_payload,
    build_recovery_payload,
    build_rotation_payload,
    send_batch,
    send_enrollment,
    send_recovery,
    send_rotation,
    validate_analyzer_url,
    validate_batch_ack,
    validate_enrollment_response,
    validate_recovery_response,
    validate_rotation_response,
)


class DurableCollectorRuntime:
    def __init__(
        self,
        state: CollectorState,
        analyzer_url: str,
        ca_bundle=None,
        hostname: str = "",
        os_name: str = "",
        enrollment_url: str = None,
        enrollment_token: str = None,
        rotation_url: str = None,
        recovery_url: str = None,
        recovery_token: str = None,
        auth_required: bool = False,
        collector_version: str = None,
        sender: Callable = send_batch,
        enrollment_sender: Callable = send_enrollment,
        rotation_sender: Callable = send_rotation,
        recovery_sender: Callable = send_recovery,
        ack_validator: Callable = validate_batch_ack,
        enrollment_validator: Callable = validate_enrollment_response,
        rotation_validator: Callable = validate_rotation_response,
        recovery_validator: Callable = validate_recovery_response,
        credential_factory: Callable = None,
        rotation_id_factory: Callable = None,
        recovery_id_factory: Callable = None,
        retry_base_seconds: float = 2.0,
        retry_max_seconds: float = 60.0,
        retry_jitter_ratio: float = 0.2,
        clock: Callable[[], float] = time.time,
    ):
        validate_analyzer_url(analyzer_url)
        if enrollment_url:
            validate_analyzer_url(enrollment_url)
        if rotation_url:
            validate_analyzer_url(rotation_url)
        if recovery_url:
            validate_analyzer_url(recovery_url)

        retry_base_seconds = float(retry_base_seconds)
        retry_max_seconds = float(retry_max_seconds)
        retry_jitter_ratio = float(retry_jitter_ratio)

        if retry_base_seconds <= 0:
            raise ValueError("retry_base_seconds must be greater than zero")
        if retry_max_seconds < retry_base_seconds:
            raise ValueError(
                "retry_max_seconds must be greater than or equal to retry_base_seconds"
            )
        if not 0 <= retry_jitter_ratio <= 1:
            raise ValueError("retry_jitter_ratio must be between 0 and 1")

        self.state = state
        self.analyzer_url = analyzer_url
        self.ca_bundle = ca_bundle
        self.hostname = str(hostname)
        self.os_name = str(os_name)
        self.enrollment_url = str(enrollment_url or "").strip() or None
        self.enrollment_token = str(enrollment_token or "").strip() or None
        self.rotation_url = str(rotation_url or "").strip() or None
        self.recovery_url = str(recovery_url or "").strip() or None
        self.recovery_token = str(recovery_token or "").strip() or None
        self.auth_required = bool(auth_required)
        self.collector_version = (
            str(collector_version).strip()
            if collector_version not in (None, "")
            else None
        )
        self.sender = sender
        self.enrollment_sender = enrollment_sender
        self.rotation_sender = rotation_sender
        self.recovery_sender = recovery_sender
        self.ack_validator = ack_validator
        self.enrollment_validator = enrollment_validator
        self.rotation_validator = rotation_validator
        self.recovery_validator = recovery_validator
        self.credential_factory = credential_factory if credential_factory is not None else lambda: secrets.token_urlsafe(32)
        self.rotation_id_factory = rotation_id_factory if rotation_id_factory is not None else lambda: str(uuid.uuid4())
        self.recovery_id_factory = recovery_id_factory if recovery_id_factory is not None else lambda: str(uuid.uuid4())
        self.retry_base_seconds = retry_base_seconds
        self.retry_max_seconds = retry_max_seconds
        self.retry_jitter_ratio = retry_jitter_ratio
        self.clock = clock
        self.collector_id = state.get_or_create_collector_id()

        if self.auth_required and not self.enrollment_url:
            if not self.state.get_collector_credential():
                raise ValueError(
                    "collector_enrollment_url is required before first enrollment"
                )

    @classmethod
    def from_config(cls, config, config_path, hostname: str, os_name: str):
        analyzer_url = str(config.get("collector_ingest_url") or "").strip()
        if not analyzer_url:
            raise ValueError("collector_ingest_url is required")

        auth_required = bool(config.get("collector_auth_required", True))
        enrollment_url = str(
            config.get("collector_enrollment_url") or ""
        ).strip()
        rotation_url = str(
            config.get("collector_rotation_url") or ""
        ).strip()
        recovery_url = str(
            config.get("collector_recovery_url") or ""
        ).strip()

        config_path = Path(config_path)
        state_path = Path(
            str(config.get("collector_state_file") or "collector_state.db")
        )
        if not state_path.is_absolute():
            state_path = config_path.parent / state_path

        ca_bundle = config.get("ca_bundle")
        if ca_bundle:
            ca_path = Path(str(ca_bundle))
            if not ca_path.is_absolute():
                ca_path = config_path.parent / ca_path
            ca_bundle = str(ca_path)

        return cls(
            CollectorState(state_path),
            analyzer_url,
            ca_bundle=ca_bundle,
            hostname=hostname,
            os_name=os_name,
            enrollment_url=enrollment_url or None,
            enrollment_token=os.environ.get(
                "AEGISGUARD_COLLECTOR_ENROLLMENT_TOKEN"
            ),
            rotation_url=rotation_url or None,
            recovery_url=recovery_url or None,
            recovery_token=os.environ.get(
                "AEGISGUARD_COLLECTOR_RECOVERY_TOKEN"
            ),
            auth_required=auth_required,
            collector_version=config.get("collector_version"),
            retry_base_seconds=float(
                config.get("collector_retry_base_seconds", 2.0)
            ),
            retry_max_seconds=float(
                config.get("collector_retry_max_seconds", 60.0)
            ),
            retry_jitter_ratio=float(
                config.get("collector_retry_jitter_ratio", 0.2)
            ),
        )

    def initialize(
        self,
        explicit_record: Optional[int],
        latest_record_provider: Callable[[], int],
    ) -> int:
        if self.state.get_checkpoint() is None:
            existing_cursor = self.state.get_collection_cursor()
            if explicit_record is not None:
                baseline = int(explicit_record)
            elif existing_cursor is None:
                baseline = int(latest_record_provider())
            else:
                baseline = 0
            self.state.initialize_checkpoint(baseline)
        return self.collection_cursor()

    def collection_cursor(self) -> int:
        cursor = self.state.get_collection_cursor()
        return int(cursor) if cursor is not None else 0

    def checkpoint(self):
        return self.state.get_checkpoint()

    def ensure_enrolled(self) -> Optional[str]:
        if not self.auth_required:
            return None

        credential = self.state.get_collector_credential()
        if credential:
            return credential

        if not self.enrollment_url:
            raise ValueError("collector enrollment URL is unavailable")
        if not self.enrollment_token:
            raise ValueError(
                "collector is not enrolled and bootstrap token is unavailable"
            )

        payload = build_enrollment_payload(
            self.collector_id,
            self.hostname,
            self.os_name,
            version=self.collector_version,
        )
        response = self.enrollment_sender(
            self.enrollment_url,
            payload,
            self.enrollment_token,
            timeout=30,
            ca_bundle=self.ca_bundle,
        )
        body = self.enrollment_validator(response, payload)
        credential = str(body["credential"]).strip()
        self.state.store_collector_credential(credential)
        self.enrollment_token = None
        return credential

    def recover_credential(self):
        """Explicitly recover an enrolled credential through recovery trust."""

        if not self.auth_required:
            raise ValueError(
                "collector credential recovery requires authenticated mode"
            )
        if not self.recovery_url:
            raise ValueError("collector recovery URL is unavailable")
        if not self.recovery_token:
            raise ValueError("collector recovery token is unavailable")

        pending = self.state.get_pending_credential_recovery()

        if pending is None:
            new_credential = str(
                self.credential_factory() or ""
            ).strip()
            if not new_credential:
                raise ValueError(
                    "generated collector credential is empty"
                )

            recovery_id = str(
                self.recovery_id_factory() or ""
            ).strip()
            if not recovery_id:
                raise ValueError("generated recovery_id is empty")

            self.state.begin_credential_recovery(
                recovery_id,
                new_credential,
            )
        else:
            recovery_id = str(pending["recovery_id"])
            new_credential = str(pending["credential"])

        payload = build_recovery_payload(
            self.collector_id,
            self.hostname,
            recovery_id,
            new_credential,
        )
        response = self.recovery_sender(
            self.recovery_url,
            payload,
            self.recovery_token,
            timeout=30,
            ca_bundle=self.ca_bundle,
        )
        body = self.recovery_validator(response, payload)
        self.state.commit_credential_recovery(recovery_id)
        self.recovery_token = None
        return body

    def rotate_credential(self):
        """Rotate without lockout if the server response is lost."""

        if not self.auth_required:
            raise ValueError(
                "collector credential rotation requires authenticated mode"
            )
        if not self.rotation_url:
            raise ValueError("collector rotation URL is unavailable")

        current = self.ensure_enrolled()
        pending = self.state.get_pending_credential_rotation()

        if pending is None:
            new_credential = str(
                self.credential_factory() or ""
            ).strip()
            if not new_credential:
                raise ValueError(
                    "generated collector credential is empty"
                )
            if new_credential == current:
                raise ValueError(
                    "generated collector credential did not change"
                )

            rotation_id = str(
                self.rotation_id_factory() or ""
            ).strip()
            if not rotation_id:
                raise ValueError("generated rotation_id is empty")

            self.state.begin_credential_rotation(
                rotation_id,
                new_credential,
            )
        else:
            rotation_id = str(pending["rotation_id"])
            new_credential = str(pending["credential"])

        payload = build_rotation_payload(
            self.collector_id,
            self.hostname,
            rotation_id,
            new_credential,
        )

        response = self.rotation_sender(
            self.rotation_url,
            payload,
            credential=current,
            timeout=30,
            ca_bundle=self.ca_bundle,
        )

        if (
            getattr(response, "status_code", None) == 401
            and new_credential != current
        ):
            response = self.rotation_sender(
                self.rotation_url,
                payload,
                credential=new_credential,
                timeout=30,
                ca_bundle=self.ca_bundle,
            )

        body = self.rotation_validator(response, payload)
        self.state.commit_credential_rotation(rotation_id)
        return body

    def enqueue_logs(self, logs, record_ids) -> Optional[str]:
        if not logs:
            return None

        ids = [int(value) for value in record_ids]
        if not ids:
            raise ValueError("record_ids are required for a non-empty batch")

        payload = build_batch_payload(
            self.collector_id,
            self.hostname,
            self.os_name,
            list(logs),
        )
        return self.state.enqueue(payload, max(ids))

    def retry_delay_seconds(self, batch_id: str, attempts: int) -> float:
        attempt_number = max(1, int(attempts))
        exponent = attempt_number - 1
        uncapped = self.retry_base_seconds * (2 ** exponent)
        base_delay = min(self.retry_max_seconds, uncapped)

        if self.retry_jitter_ratio == 0:
            return float(base_delay)

        digest = hashlib.sha256(
            f"{batch_id}:{attempt_number}".encode("utf-8")
        ).digest()
        fraction = int.from_bytes(digest[:8], "big") / float((1 << 64) - 1)
        centered = (fraction * 2.0) - 1.0
        jittered = base_delay * (
            1.0 + (centered * self.retry_jitter_ratio)
        )
        return max(0.0, min(self.retry_max_seconds, jittered))

    def health_snapshot(self):
        snapshot = self.state.transport_health(now=self.clock())
        snapshot.update({
            "analyzer_url": self.analyzer_url,
            "auth_required": self.auth_required,
            "enrolled": bool(self.state.get_collector_credential()),
            "retry_base_seconds": self.retry_base_seconds,
            "retry_max_seconds": self.retry_max_seconds,
            "retry_jitter_ratio": self.retry_jitter_ratio,
        })
        return snapshot

    def flush_pending(self, limit: int = 20) -> bool:
        if int(limit) < 1:
            raise ValueError("limit must be at least 1")

        while True:
            pending = self.state.pending(limit=int(limit))
            if not pending:
                return True

            for item in pending:
                batch_id = str(item["batch_id"])
                payload = item["payload"]
                now = float(self.clock())
                next_attempt_at = item.get("next_attempt_at")

                if (
                    next_attempt_at is not None
                    and now < float(next_attempt_at)
                ):
                    retry_in = float(next_attempt_at) - now
                    print(
                        f"[DURABLE RETRY WAIT] batch={batch_id} "
                        f"retry_in={retry_in:.2f}s",
                        flush=True,
                    )
                    return False

                try:
                    credential = self.ensure_enrolled()
                    response = self.sender(
                        self.analyzer_url,
                        payload,
                        timeout=30,
                        ca_bundle=self.ca_bundle,
                        credential=credential,
                    )
                    self.ack_validator(response, payload)
                except (
                    requests.RequestException,
                    ValueError,
                    KeyError,
                    TypeError,
                ) as exc:
                    attempt_number = int(item.get("attempts") or 0) + 1
                    delay = self.retry_delay_seconds(
                        batch_id,
                        attempt_number,
                    )
                    next_time = now + delay
                    self.state.mark_attempt(
                        batch_id,
                        str(exc),
                        attempted_at=now,
                        next_attempt_at=next_time,
                    )
                    print(
                        f"[DURABLE UPLOAD] batch={batch_id} failed: {exc}; "
                        f"attempt={attempt_number} retry_in={delay:.2f}s",
                        flush=True,
                    )
                    return False

                self.state.mark_attempt(
                    batch_id,
                    None,
                    attempted_at=now,
                    next_attempt_at=None,
                )
                self.state.acknowledge(
                    batch_id,
                    acknowledged_at=now,
                )
                print(
                    f"[DURABLE ACK] batch={batch_id} "
                    f"checkpoint={self.state.get_checkpoint()}",
                    flush=True,
                )
