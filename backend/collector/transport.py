"""Collector transport primitives for the enterprise ingestion path."""

import ipaddress
import json
import socket
import uuid
from urllib.parse import urlparse

import requests


COLLECTOR_CREDENTIAL_HEADER = "X-AegisGuard-Collector-Credential"
ENROLLMENT_TOKEN_HEADER = "X-AegisGuard-Enrollment-Token"
RECOVERY_TOKEN_HEADER = "X-AegisGuard-Recovery-Token"


def _is_loopback_host(hostname: str) -> bool:
    if not hostname:
        return False
    if hostname.lower() == "localhost":
        return True

    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        pass

    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(hostname, None)
        }
    except OSError:
        return False

    for address in addresses:
        try:
            if ipaddress.ip_address(address).is_loopback:
                return True
        except ValueError:
            continue
    return bool(addresses)


def validate_analyzer_url(url: str) -> None:
    parsed = urlparse(str(url))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("analyzer URL must be an absolute http(s) URL")

    if parsed.scheme == "https":
        return

    if _is_loopback_host(parsed.hostname):
        return

    raise ValueError(
        "remote analyzer transport requires HTTPS; plain HTTP is allowed only for loopback development"
    )


def build_batch_payload(
    collector_id: str,
    hostname: str,
    os_name: str,
    logs,
    batch_id: str = None,
):
    if not collector_id:
        raise ValueError("collector_id is required")
    if not hostname:
        raise ValueError("hostname is required")
    if not isinstance(logs, list):
        raise ValueError("logs must be a list")

    return {
        "batch_id": batch_id or str(uuid.uuid4()),
        "collector_id": collector_id,
        "hostname": hostname,
        "os": os_name,
        "logs": logs,
    }


def build_enrollment_payload(
    collector_id: str,
    hostname: str,
    os_name: str,
    version: str = None,
):
    if not collector_id:
        raise ValueError("collector_id is required")
    if not hostname:
        raise ValueError("hostname is required")

    payload = {
        "collector_id": str(collector_id),
        "hostname": str(hostname),
        "metadata": {"os": str(os_name or "")},
    }
    if version:
        payload["version"] = str(version)
    return payload


def send_enrollment(
    enrollment_url: str,
    payload,
    bootstrap_token: str,
    timeout: int = 30,
    ca_bundle=None,
    session=None,
    client_cert=None,
):
    validate_analyzer_url(enrollment_url)

    token = str(bootstrap_token or "").strip()
    if not token:
        raise ValueError("collector enrollment token is required")

    body = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    verify = ca_bundle if ca_bundle else True
    client = session or requests
    return client.post(
        enrollment_url,
        data=body.encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            ENROLLMENT_TOKEN_HEADER: token,
        },
        timeout=timeout,
        verify=verify,
        cert=client_cert,
    )


def validate_enrollment_response(response, payload):
    if getattr(response, "status_code", None) != 201:
        raise ValueError(
            f"collector enrollment requires HTTP 201; got "
            f"{getattr(response, 'status_code', None)}"
        )

    try:
        body = response.json()
    except (TypeError, ValueError) as exc:
        raise ValueError("collector enrollment response must contain JSON") from exc

    if not isinstance(body, dict) or body.get("status") != "enrolled":
        raise ValueError("collector enrollment status must be enrolled")

    expected_collector = str(payload.get("collector_id") or "")
    expected_hostname = str(payload.get("hostname") or "")
    if str(body.get("collector_id") or "") != expected_collector:
        raise ValueError("collector enrollment collector_id mismatch")
    if str(body.get("hostname") or "") != expected_hostname:
        raise ValueError("collector enrollment hostname mismatch")

    credential = str(body.get("credential") or "").strip()
    if not credential:
        raise ValueError("collector enrollment credential is missing")

    return body


def build_heartbeat_payload(
    collector_id: str,
    hostname: str,
    version: str = None,
    health=None,
):
    if not collector_id:
        raise ValueError("collector_id is required")
    if not hostname:
        raise ValueError("hostname is required")

    payload = {
        "collector_id": str(collector_id),
        "hostname": str(hostname),
    }
    if version:
        payload["version"] = str(version)
    if health is not None:
        if not isinstance(health, dict):
            raise ValueError("heartbeat health must be a dictionary")
        payload["health"] = dict(health)
    return payload


def send_heartbeat(
    heartbeat_url: str,
    payload,
    credential: str,
    timeout: int = 30,
    ca_bundle=None,
    session=None,
    client_cert=None,
):
    validate_analyzer_url(heartbeat_url)

    credential_value = str(credential or "").strip()
    if not credential_value:
        raise ValueError("collector credential is required")

    body = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )

    verify = ca_bundle if ca_bundle else True
    client = session or requests
    return client.post(
        heartbeat_url,
        data=body.encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-AegisGuard-Collector-ID": payload["collector_id"],
            COLLECTOR_CREDENTIAL_HEADER: credential_value,
        },
        timeout=timeout,
        verify=verify,
        cert=client_cert,
    )


def validate_heartbeat_response(response, payload):
    if getattr(response, "status_code", None) != 200:
        raise ValueError(
            f"collector heartbeat requires HTTP 200; got "
            f"{getattr(response, 'status_code', None)}"
        )

    try:
        body = response.json()
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "collector heartbeat response must contain JSON"
        ) from exc

    if not isinstance(body, dict) or body.get("status") != "alive":
        raise ValueError("collector heartbeat status must be alive")

    expected_collector = str(payload.get("collector_id") or "")
    expected_hostname = str(payload.get("hostname") or "")
    if str(body.get("collector_id") or "") != expected_collector:
        raise ValueError("collector heartbeat collector_id mismatch")
    if str(body.get("hostname") or "") != expected_hostname:
        raise ValueError("collector heartbeat hostname mismatch")
    if not str(body.get("last_seen_at") or "").strip():
        raise ValueError("collector heartbeat last_seen_at is missing")

    return body


def build_recovery_payload(
    collector_id: str,
    hostname: str,
    recovery_id: str,
    new_credential: str,
):
    if not collector_id:
        raise ValueError("collector_id is required")
    if not hostname:
        raise ValueError("hostname is required")
    if not recovery_id:
        raise ValueError("recovery_id is required")
    if not new_credential:
        raise ValueError("new_credential is required")

    return {
        "collector_id": str(collector_id),
        "hostname": str(hostname),
        "recovery_id": str(recovery_id),
        "new_credential": str(new_credential),
    }


def send_recovery(
    recovery_url: str,
    payload,
    recovery_token: str,
    timeout: int = 30,
    ca_bundle=None,
    session=None,
    client_cert=None,
):
    validate_analyzer_url(recovery_url)

    token = str(recovery_token or "").strip()
    if not token:
        raise ValueError("collector recovery token is required")

    body = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )

    verify = ca_bundle if ca_bundle else True
    client = session or requests
    return client.post(
        recovery_url,
        data=body.encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            RECOVERY_TOKEN_HEADER: token,
        },
        timeout=timeout,
        verify=verify,
        cert=client_cert,
    )


def validate_recovery_response(response, payload):
    if getattr(response, "status_code", None) != 200:
        raise ValueError(
            f"collector credential recovery requires HTTP 200; got "
            f"{getattr(response, 'status_code', None)}"
        )

    try:
        body = response.json()
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "collector credential recovery response must contain JSON"
        ) from exc

    if not isinstance(body, dict) or body.get("status") != "recovered":
        raise ValueError(
            "collector credential recovery status must be recovered"
        )

    for field in ("collector_id", "hostname", "recovery_id"):
        expected = str(payload.get(field) or "")
        if str(body.get(field) or "") != expected:
            raise ValueError(
                f"collector credential recovery {field} mismatch"
            )

    return body


def certificate_fingerprint_from_client_cert(client_cert) -> str:
    import hashlib
    import ssl
    from pathlib import Path

    certificate_path = (
        client_cert[0]
        if isinstance(client_cert, (tuple, list))
        else client_cert
    )
    path = Path(str(certificate_path or ""))
    if not str(path):
        raise ValueError("client certificate path is required")

    pem = path.read_text(encoding="utf-8")
    try:
        der = ssl.PEM_cert_to_DER_cert(pem)
    except Exception as exc:
        raise ValueError("client certificate PEM is invalid") from exc
    return hashlib.sha256(der).hexdigest()


def build_certificate_rotation_payload(
    collector_id: str,
    hostname: str,
    rotation_id: str,
    new_certificate_fingerprint: str,
):
    if not collector_id:
        raise ValueError("collector_id is required")
    if not hostname:
        raise ValueError("hostname is required")
    if not rotation_id:
        raise ValueError("certificate rotation_id is required")

    fingerprint = str(new_certificate_fingerprint or "").strip().lower()
    if not fingerprint:
        raise ValueError("new certificate fingerprint is required")

    return {
        "collector_id": str(collector_id),
        "hostname": str(hostname),
        "certificate_rotation_id": str(rotation_id),
        "new_certificate_fingerprint": fingerprint,
    }


def send_certificate_rotation(
    rotation_url: str,
    payload,
    credential: str,
    timeout: int = 30,
    ca_bundle=None,
    session=None,
    client_cert=None,
):
    validate_analyzer_url(rotation_url)

    current = str(credential or "").strip()
    if not current:
        raise ValueError("current collector credential is required")

    body = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    verify = ca_bundle if ca_bundle else True
    client = session or requests
    return client.post(
        rotation_url,
        data=body.encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-AegisGuard-Collector-ID": payload["collector_id"],
            COLLECTOR_CREDENTIAL_HEADER: current,
        },
        timeout=timeout,
        verify=verify,
        cert=client_cert,
    )


def validate_certificate_rotation_response(response, payload):
    if getattr(response, "status_code", None) != 200:
        raise ValueError(
            f"collector certificate rotation requires HTTP 200; got "
            f"{getattr(response, 'status_code', None)}"
        )

    try:
        body = response.json()
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "collector certificate rotation response must contain JSON"
        ) from exc

    if (
        not isinstance(body, dict)
        or body.get("status") != "certificate_rotation_staged"
    ):
        raise ValueError(
            "collector certificate rotation status must be certificate_rotation_staged"
        )

    expected = {
        "collector_id": str(payload.get("collector_id") or ""),
        "certificate_rotation_id": str(
            payload.get("certificate_rotation_id") or ""
        ),
        "new_certificate_fingerprint": str(
            payload.get("new_certificate_fingerprint") or ""
        ).lower(),
    }
    for field, expected_value in expected.items():
        actual = str(body.get(field) or "")
        if actual.lower() != expected_value.lower():
            raise ValueError(
                f"collector certificate rotation {field} mismatch"
            )

    return body


def build_rotation_payload(
    collector_id: str,
    hostname: str,
    rotation_id: str,
    new_credential: str,
):
    if not collector_id:
        raise ValueError("collector_id is required")
    if not hostname:
        raise ValueError("hostname is required")
    if not rotation_id:
        raise ValueError("rotation_id is required")
    if not new_credential:
        raise ValueError("new_credential is required")

    return {
        "collector_id": str(collector_id),
        "hostname": str(hostname),
        "rotation_id": str(rotation_id),
        "new_credential": str(new_credential),
    }


def send_rotation(
    rotation_url: str,
    payload,
    credential: str,
    timeout: int = 30,
    ca_bundle=None,
    session=None,
    client_cert=None,
):
    validate_analyzer_url(rotation_url)

    current = str(credential or "").strip()
    if not current:
        raise ValueError("current collector credential is required")

    body = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )

    verify = ca_bundle if ca_bundle else True
    client = session or requests
    return client.post(
        rotation_url,
        data=body.encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-AegisGuard-Collector-ID": payload["collector_id"],
            COLLECTOR_CREDENTIAL_HEADER: current,
        },
        timeout=timeout,
        verify=verify,
        cert=client_cert,
    )


def validate_rotation_response(response, payload):
    if getattr(response, "status_code", None) != 200:
        raise ValueError(
            f"collector credential rotation requires HTTP 200; got "
            f"{getattr(response, 'status_code', None)}"
        )

    try:
        body = response.json()
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "collector credential rotation response must contain JSON"
        ) from exc

    if not isinstance(body, dict) or body.get("status") != "rotated":
        raise ValueError(
            "collector credential rotation status must be rotated"
        )

    for field in ("collector_id", "hostname", "rotation_id"):
        expected = str(payload.get(field) or "")
        if str(body.get(field) or "") != expected:
            raise ValueError(
                f"collector credential rotation {field} mismatch"
            )

    return body


def send_batch(
    analyzer_url: str,
    payload,
    timeout: int = 30,
    ca_bundle=None,
    session=None,
    credential=None,
    client_cert=None,
):
    validate_analyzer_url(analyzer_url)

    body = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )

    headers = {
        "Content-Type": "application/json",
        "X-AegisGuard-Collector-ID": payload["collector_id"],
        "X-AegisGuard-Batch-ID": payload["batch_id"],
    }
    credential_value = str(credential or "").strip()
    if credential_value:
        headers[COLLECTOR_CREDENTIAL_HEADER] = credential_value

    verify = ca_bundle if ca_bundle else True
    client = session or requests
    return client.post(
        analyzer_url,
        data=body.encode("utf-8"),
        headers=headers,
        timeout=timeout,
        verify=verify,
        cert=client_cert,
    )


def validate_batch_ack(response, payload):
    if getattr(response, "status_code", None) != 202:
        raise ValueError(
            f"durable collector ACK requires HTTP 202; got "
            f"{getattr(response, 'status_code', None)}"
        )

    try:
        body = response.json()
    except (TypeError, ValueError) as exc:
        raise ValueError("durable collector ACK must contain JSON") from exc

    if not isinstance(body, dict) or body.get("status") != "accepted":
        raise ValueError("durable collector ACK status must be accepted")

    expected_collector = str(payload.get("collector_id") or "")
    expected_batch = str(payload.get("batch_id") or "")
    if str(body.get("collector_id") or "") != expected_collector:
        raise ValueError("durable collector ACK collector_id mismatch")
    if str(body.get("batch_id") or "") != expected_batch:
        raise ValueError("durable collector ACK batch_id mismatch")

    return body
