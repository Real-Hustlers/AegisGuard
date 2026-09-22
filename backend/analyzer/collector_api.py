"""Enterprise collector enrollment and ingestion API.

S2 established the durable-ACK boundary. S3-1B adds an opt-in authenticated
mode around that boundary while preserving the legacy default until the
collector-side S3-1C wiring is ready.

Enrollment is disabled unless an explicit bootstrap token is configured.
Authenticated batch ingestion uses the authoritative S3 collector identity
registry and never stores plaintext collector credentials server-side.
"""

import hmac

from flask import Blueprint, jsonify, request

from backend.storage.collector_identity import (
    CollectorAuthenticationError,
    CollectorEnrollmentError,
    CollectorIdentityError,
    CollectorRevokedError,
    authenticate_collector,
    authenticate_collector_certificate,
    certificate_fingerprint_from_pem,
    normalize_certificate_fingerprint,
    enroll_collector,
    rotate_collector_credential,
    recover_collector_credential,
    CollectorRotationConflictError,
    CollectorRotationError,
    CollectorRecoveryConflictError,
    CollectorRecoveryError,
)
from backend.storage.collector_ingest import persist_collector_batch


COLLECTOR_CREDENTIAL_HEADER = "X-AegisGuard-Collector-Credential"
ENROLLMENT_TOKEN_HEADER = "X-AegisGuard-Enrollment-Token"
RECOVERY_TOKEN_HEADER = "X-AegisGuard-Recovery-Token"


def _verified_client_certificate_fingerprint():
    verification = str(
        request.environ.get("SSL_CLIENT_VERIFY") or ""
    ).upper()
    if verification != "SUCCESS":
        return None

    direct_fingerprint = request.environ.get(
        "SSL_CLIENT_FINGERPRINT"
    )
    if direct_fingerprint:
        return normalize_certificate_fingerprint(
            str(direct_fingerprint)
        )

    pem_certificate = request.environ.get("SSL_CLIENT_CERT")
    if not pem_certificate:
        return None

    return certificate_fingerprint_from_pem(
        str(pem_certificate)
    )


def _json_error(message, status_code):
    return jsonify({
        "status": "error",
        "message": message,
    }), status_code


def create_collector_blueprint(
    connection_factory,
    *,
    auth_required=False,
    enrollment_token=None,
    recovery_token=None,
    credential_factory=None,
    mtls_required=False,
    client_certificate_resolver=None,
):
    """Build the collector API blueprint.

    ``auth_required`` defaults to False so S3-1B can land without breaking the
    existing S2 collector. S3-1C will wire the collector credential and then
    enable this flag in the production app.

    ``enrollment_token`` is a bootstrap secret supplied by deployment/runtime
    configuration. When it is absent, enrollment is disabled rather than open.
    """

    blueprint = Blueprint("collector_ingest_v1", __name__)
    resolver = (
        client_certificate_resolver
        if client_certificate_resolver is not None
        else _verified_client_certificate_fingerprint
    )

    def require_client_certificate(collector_id=None):
        if not mtls_required:
            return None, None

        try:
            fingerprint = resolver()
        except CollectorIdentityError:
            return None, _json_error(
                "collector client certificate verification failed",
                401,
            )

        if not fingerprint:
            return None, _json_error(
                "collector client certificate verification failed",
                401,
            )

        if collector_id:
            conn = connection_factory()
            try:
                try:
                    authenticate_collector_certificate(
                        conn,
                        collector_id,
                        fingerprint,
                    )
                except CollectorRevokedError:
                    return None, _json_error(
                        "collector is revoked",
                        403,
                    )
                except (
                    CollectorAuthenticationError,
                    CollectorIdentityError,
                ):
                    return None, _json_error(
                        "collector client certificate verification failed",
                        401,
                    )
            finally:
                conn.close()

        return fingerprint, None

    @blueprint.post("/api/collector/v1/enroll")
    def enroll():
        configured_token = str(enrollment_token or "")
        if not configured_token:
            return _json_error("collector enrollment is disabled", 503)

        presented_token = str(
            request.headers.get(ENROLLMENT_TOKEN_HEADER) or ""
        )
        if (
            not presented_token
            or not hmac.compare_digest(configured_token, presented_token)
        ):
            return _json_error("collector enrollment authorization failed", 403)

        payload = request.get_json(silent=True) or {}
        collector_id = str(payload.get("collector_id") or "").strip()
        hostname = str(payload.get("hostname") or "").strip()

        certificate_fingerprint, certificate_error = (
            require_client_certificate()
        )
        if certificate_error is not None:
            return certificate_error

        conn = connection_factory()
        try:
            result = enroll_collector(
                conn,
                collector_id,
                hostname,
                version=payload.get("version"),
                display_name=payload.get("display_name"),
                metadata=payload.get("metadata"),
                credential_factory=credential_factory,
                certificate_fingerprint=certificate_fingerprint,
            )
        except CollectorEnrollmentError as exc:
            return _json_error(str(exc), 409)
        except CollectorIdentityError as exc:
            return _json_error(str(exc), 400)
        finally:
            conn.close()

        response = jsonify({
            "status": "enrolled",
            "collector_id": result["collector_id"],
            "hostname": result["hostname"],
            "collector_status": result["status"],
            "credential": result["credential"],
        })
        response.status_code = 201
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        return response

    @blueprint.post("/api/collector/v1/recover")
    def recover_credential():
        configured_token = str(recovery_token or "")
        if not configured_token:
            return _json_error("collector recovery is disabled", 503)

        presented_token = str(
            request.headers.get(RECOVERY_TOKEN_HEADER) or ""
        )
        if (
            not presented_token
            or not hmac.compare_digest(configured_token, presented_token)
        ):
            return _json_error(
                "collector recovery authorization failed",
                403,
            )

        payload = request.get_json(silent=True) or {}
        collector_id = str(payload.get("collector_id") or "").strip()
        hostname = str(payload.get("hostname") or "").strip()

        _certificate, certificate_error = require_client_certificate(
            collector_id
        )
        if certificate_error is not None:
            return certificate_error

        conn = connection_factory()
        try:
            try:
                result = recover_collector_credential(
                    conn,
                    collector_id,
                    hostname,
                    payload.get("new_credential"),
                    payload.get("recovery_id"),
                )
            except CollectorRevokedError:
                return _json_error("collector is revoked", 403)
            except CollectorRecoveryConflictError as exc:
                return _json_error(str(exc), 409)
            except CollectorRecoveryError as exc:
                return _json_error(str(exc), 400)
            except CollectorIdentityError as exc:
                return _json_error(str(exc), 400)
        finally:
            conn.close()

        response = jsonify({
            "status": "recovered",
            "collector_id": result["collector_id"],
            "hostname": result["hostname"],
            "recovery_id": result["recovery_id"],
            "duplicate": bool(result["duplicate"]),
            "recovered_at": result["recovered_at"],
        })
        response.status_code = 200
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        return response

    @blueprint.post("/api/collector/v1/rotate")
    def rotate_credential():
        payload = request.get_json(silent=True) or {}

        collector_id = str(
            request.headers.get("X-AegisGuard-Collector-ID") or ""
        ).strip()
        presented_credential = str(
            request.headers.get(COLLECTOR_CREDENTIAL_HEADER) or ""
        )

        if not collector_id or not presented_credential:
            return _json_error("collector authentication failed", 401)

        if str(payload.get("collector_id") or "").strip() != collector_id:
            return _json_error("collector_id header/body mismatch", 400)

        _certificate, certificate_error = require_client_certificate(
            collector_id
        )
        if certificate_error is not None:
            return certificate_error

        conn = connection_factory()
        try:
            try:
                result = rotate_collector_credential(
                    conn,
                    collector_id,
                    presented_credential,
                    payload.get("new_credential"),
                    payload.get("rotation_id"),
                    hostname=str(payload.get("hostname") or "").strip(),
                )
            except CollectorRevokedError:
                return _json_error("collector is revoked", 403)
            except CollectorRotationConflictError as exc:
                return _json_error(str(exc), 409)
            except CollectorAuthenticationError:
                return _json_error("collector authentication failed", 401)
            except CollectorRotationError as exc:
                return _json_error(str(exc), 400)
            except CollectorIdentityError as exc:
                return _json_error(str(exc), 400)
        finally:
            conn.close()

        response = jsonify({
            "status": "rotated",
            "collector_id": result["collector_id"],
            "hostname": result["hostname"],
            "rotation_id": result["rotation_id"],
            "duplicate": bool(result["duplicate"]),
            "rotated_at": result["rotated_at"],
        })
        response.status_code = 200
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        return response

    @blueprint.post("/api/collector/v1/batches")
    def accept_collector_batch():
        payload = request.get_json(silent=True) or {}

        header_collector_id = str(
            request.headers.get("X-AegisGuard-Collector-ID") or ""
        ).strip()
        header_batch_id = str(
            request.headers.get("X-AegisGuard-Batch-ID") or ""
        ).strip()

        if not header_collector_id or not header_batch_id:
            return _json_error(
                "collector and batch identity headers are required",
                400,
            )

        if str(payload.get("collector_id") or "").strip() != header_collector_id:
            return _json_error("collector_id header/body mismatch", 400)

        if str(payload.get("batch_id") or "").strip() != header_batch_id:
            return _json_error("batch_id header/body mismatch", 400)

        _certificate, certificate_error = require_client_certificate(
            header_collector_id
        )
        if certificate_error is not None:
            return certificate_error

        conn = connection_factory()
        try:
            if auth_required:
                presented_credential = str(
                    request.headers.get(COLLECTOR_CREDENTIAL_HEADER) or ""
                )
                if not presented_credential:
                    return _json_error("collector authentication failed", 401)

                try:
                    authenticate_collector(
                        conn,
                        header_collector_id,
                        presented_credential,
                        hostname=str(payload.get("hostname") or "").strip(),
                    )
                except CollectorRevokedError:
                    return _json_error("collector is revoked", 403)
                except CollectorAuthenticationError:
                    return _json_error("collector authentication failed", 401)
                except CollectorIdentityError:
                    return _json_error("collector authentication failed", 401)

            try:
                inserted, state = persist_collector_batch(
                    conn,
                    payload,
                    request.remote_addr,
                )
            except ValueError as exc:
                return _json_error(str(exc), 400)
        finally:
            conn.close()

        return jsonify({
            "status": "accepted",
            "batch_id": header_batch_id,
            "collector_id": header_collector_id,
            "duplicate": not inserted,
            "analysis_state": state,
        }), 202

    return blueprint
