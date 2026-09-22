"""Collector transport primitives for the enterprise ingestion path."""

import ipaddress
import json
import socket
import uuid
from urllib.parse import urlparse

import requests


COLLECTOR_CREDENTIAL_HEADER = "X-AegisGuard-Collector-Credential"
ENROLLMENT_TOKEN_HEADER = "X-AegisGuard-Enrollment-Token"


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


def send_batch(
    analyzer_url: str,
    payload,
    timeout: int = 30,
    ca_bundle=None,
    session=None,
    credential=None,
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
