import os
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

import requests
from flask import Flask

from backend.analyzer.collector_api import (
    COLLECTOR_CREDENTIAL_HEADER,
    ENROLLMENT_TOKEN_HEADER,
    create_collector_blueprint,
)
from backend.analyzer.mtls_server import create_mtls_server
from backend.storage.migrations import ensure_platform_schema


def _find_openssl():
    candidates = []

    direct = shutil.which("openssl")
    if direct:
        candidates.append(Path(direct))

    git = shutil.which("git")
    if git:
        git_path = Path(git).resolve()
        git_root = git_path.parent.parent
        candidates.extend([
            git_root / "usr" / "bin" / "openssl.exe",
            git_root / "mingw64" / "bin" / "openssl.exe",
            git_root / "usr" / "bin" / "openssl",
            git_root / "mingw64" / "bin" / "openssl",
        ])

    for variable in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(variable)
        if root:
            candidates.extend([
                Path(root) / "Git" / "usr" / "bin" / "openssl.exe",
                Path(root) / "Git" / "mingw64" / "bin" / "openssl.exe",
            ])

    for candidate in candidates:
        if candidate and candidate.is_file():
            return str(candidate)

    raise RuntimeError(
        "OpenSSL executable is required for the real mTLS E2E test. "
        "Install OpenSSL or Git for Windows with its OpenSSL binary."
    )


def _run(openssl, *args, cwd):
    completed = subprocess.run(
        [openssl, *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "OpenSSL command failed: "
            + " ".join(args)
            + "\nstdout:\n"
            + completed.stdout
            + "\nstderr:\n"
            + completed.stderr
        )


def _generate_ca(openssl, root, name):
    key = root / f"{name}.key"
    cert = root / f"{name}.crt"

    _run(
        openssl,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-nodes",
        "-keyout",
        str(key),
        "-out",
        str(cert),
        "-subj",
        f"/CN={name}",
        "-days",
        "2",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-addext",
        "subjectKeyIdentifier=hash",
        cwd=root,
    )
    return cert, key


def _issue_certificate(
    openssl,
    root,
    ca_cert,
    ca_key,
    name,
    serial,
    *,
    server=False,
):
    key = root / f"{name}.key"
    csr = root / f"{name}.csr"
    cert = root / f"{name}.crt"
    ext = root / f"{name}.ext"

    _run(
        openssl,
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key),
        "-out",
        str(csr),
        "-subj",
        f"/CN={name}",
        cwd=root,
    )

    if server:
        ext.write_text(
            "\n".join([
                "basicConstraints=critical,CA:FALSE",
                "keyUsage=critical,digitalSignature,keyEncipherment",
                "extendedKeyUsage=serverAuth",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "",
            ]),
            encoding="utf-8",
        )
    else:
        ext.write_text(
            "\n".join([
                "basicConstraints=critical,CA:FALSE",
                "keyUsage=critical,digitalSignature,keyEncipherment",
                "extendedKeyUsage=clientAuth",
                "",
            ]),
            encoding="utf-8",
        )

    _run(
        openssl,
        "x509",
        "-req",
        "-in",
        str(csr),
        "-CA",
        str(ca_cert),
        "-CAkey",
        str(ca_key),
        "-set_serial",
        str(serial),
        "-out",
        str(cert),
        "-days",
        "2",
        "-sha256",
        "-extfile",
        str(ext),
        cwd=root,
    )

    return cert, key


class ProductionMtlsEndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl = _find_openssl()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)

        cls.ca_cert, cls.ca_key = _generate_ca(
            cls.openssl,
            cls.root,
            "AegisGuard-Test-CA",
        )
        cls.rogue_ca_cert, cls.rogue_ca_key = _generate_ca(
            cls.openssl,
            cls.root,
            "AegisGuard-Rogue-CA",
        )

        cls.server_cert, cls.server_key = _issue_certificate(
            cls.openssl,
            cls.root,
            cls.ca_cert,
            cls.ca_key,
            "localhost",
            1001,
            server=True,
        )
        cls.client_a_cert, cls.client_a_key = _issue_certificate(
            cls.openssl,
            cls.root,
            cls.ca_cert,
            cls.ca_key,
            "collector-a",
            2001,
        )
        cls.client_b_cert, cls.client_b_key = _issue_certificate(
            cls.openssl,
            cls.root,
            cls.ca_cert,
            cls.ca_key,
            "collector-b",
            2002,
        )
        cls.rogue_client_cert, cls.rogue_client_key = _issue_certificate(
            cls.openssl,
            cls.root,
            cls.rogue_ca_cert,
            cls.rogue_ca_key,
            "rogue-collector",
            3001,
        )

        cls.db_path = cls.root / "server.db"

        def connection_factory():
            conn = sqlite3.connect(
                str(cls.db_path),
                timeout=30,
            )
            ensure_platform_schema(conn)
            return conn

        app = Flask(__name__)
        app.register_blueprint(
            create_collector_blueprint(
                connection_factory,
                auth_required=True,
                enrollment_token="bootstrap-secret",
                credential_factory=lambda: "device-secret-001",
                mtls_required=True,
            )
        )

        cls.server = create_mtls_server(
            app,
            {
                "host": "127.0.0.1",
                "port": 0,
                "server_certificate": str(cls.server_cert),
                "server_private_key": str(cls.server_key),
                "client_ca": str(cls.ca_cert),
            },
        )
        cls.thread = threading.Thread(
            target=cls.server.serve_forever,
            daemon=True,
        )
        cls.thread.start()

        cls.base_url = (
            f"https://127.0.0.1:{cls.server.server_port}"
        )

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=5)
        cls.server.server_close()
        cls.tmp.cleanup()

    @classmethod
    def _cert(cls, cert, key):
        return (str(cert), str(key))

    def _enroll(self, collector_id, cert_pair):
        return requests.post(
            self.base_url + "/api/collector/v1/enroll",
            json={
                "collector_id": collector_id,
                "hostname": "HOST01",
            },
            headers={
                ENROLLMENT_TOKEN_HEADER: "bootstrap-secret",
            },
            verify=str(self.ca_cert),
            cert=cert_pair,
            timeout=5,
        )

    def _batch(
        self,
        collector_id,
        batch_id,
        credential,
        cert_pair,
    ):
        return requests.post(
            self.base_url + "/api/collector/v1/batches",
            json={
                "batch_id": batch_id,
                "collector_id": collector_id,
                "hostname": "HOST01",
                "os": "Windows",
                "logs": [{"record_id": 101}],
            },
            headers={
                "X-AegisGuard-Collector-ID": collector_id,
                "X-AegisGuard-Batch-ID": batch_id,
                COLLECTOR_CREDENTIAL_HEADER: credential,
            },
            verify=str(self.ca_cert),
            cert=cert_pair,
            timeout=5,
        )

    def test_trusted_client_enrolls_and_receives_durable_batch_ack(self):
        collector_id = "collector-valid-e2e"

        enrollment = self._enroll(
            collector_id,
            self._cert(
                self.client_a_cert,
                self.client_a_key,
            ),
        )
        self.assertEqual(enrollment.status_code, 201)
        credential = enrollment.json()["credential"]

        batch = self._batch(
            collector_id,
            "batch-valid-e2e",
            credential,
            self._cert(
                self.client_a_cert,
                self.client_a_key,
            ),
        )

        self.assertEqual(batch.status_code, 202)
        body = batch.json()
        self.assertEqual(body["status"], "accepted")
        self.assertEqual(
            body["collector_id"],
            collector_id,
        )
        self.assertEqual(
            body["batch_id"],
            "batch-valid-e2e",
        )

    def test_different_trusted_certificate_is_rejected_by_identity_binding(self):
        collector_id = "collector-bound-e2e"

        enrollment = self._enroll(
            collector_id,
            self._cert(
                self.client_a_cert,
                self.client_a_key,
            ),
        )
        self.assertEqual(enrollment.status_code, 201)
        credential = enrollment.json()["credential"]

        response = self._batch(
            collector_id,
            "batch-wrong-trusted-cert",
            credential,
            self._cert(
                self.client_b_cert,
                self.client_b_key,
            ),
        )

        self.assertEqual(response.status_code, 401)

    def test_missing_client_certificate_is_rejected_during_tls_handshake(self):
        with self.assertRaises((
            requests.exceptions.SSLError,
            requests.exceptions.ConnectionError,
        )):
            requests.post(
                self.base_url + "/api/collector/v1/enroll",
                json={
                    "collector_id": "collector-no-cert",
                    "hostname": "HOST01",
                },
                headers={
                    ENROLLMENT_TOKEN_HEADER: "bootstrap-secret",
                },
                verify=str(self.ca_cert),
                timeout=5,
            )

    def test_rogue_ca_client_is_rejected_during_tls_handshake(self):
        with self.assertRaises((
            requests.exceptions.SSLError,
            requests.exceptions.ConnectionError,
        )):
            self._enroll(
                "collector-rogue-ca",
                self._cert(
                    self.rogue_client_cert,
                    self.rogue_client_key,
                ),
            )

    def test_windows_deployment_assets_do_not_embed_bootstrap_secrets(self):
        repo_root = Path(__file__).resolve().parents[2]

        runner = (
            repo_root
            / "deploy"
            / "windows"
            / "run_analyzer_mtls.ps1"
        ).read_text(encoding="utf-8")
        installer = (
            repo_root
            / "deploy"
            / "windows"
            / "install_analyzer_mtls.ps1"
        ).read_text(encoding="utf-8")
        collector = (
            repo_root
            / "deploy"
            / "windows"
            / "configure_collector_mtls.ps1"
        ).read_text(encoding="utf-8")

        combined = "\n".join([
            runner,
            installer,
            collector,
        ])

        self.assertIn(
            "backend.analyzer.mtls_server",
            runner,
        )
        self.assertIn(
            "collector_mtls_required",
            collector,
        )
        self.assertIn(
            "/api/collector/v1/batches",
            collector,
        )
        self.assertNotIn(
            "bootstrap-secret",
            combined,
        )
        self.assertNotIn(
            "device-secret-001",
            combined,
        )


if __name__ == "__main__":
    unittest.main()
