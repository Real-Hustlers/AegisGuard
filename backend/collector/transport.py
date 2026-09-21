"""Collector transport primitives for the enterprise ingestion path."""

import ipaddress
import json
import socket
import uuid
from urllib.parse import urlparse

import requests


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


def send_batch(
    analyzer_url: str,
    payload,
    timeout: int = 30,
    ca_bundle=None,
    session=None,
):
    validate_analyzer_url(analyzer_url)

    body = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )

    verify = ca_bundle if ca_bundle else True
    client = session or requests
    return client.post(
        analyzer_url,
        data=body.encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-AegisGuard-Collector-ID": payload["collector_id"],
            "X-AegisGuard-Batch-ID": payload["batch_id"],
        },
        timeout=timeout,
        verify=verify,
    )
