import hashlib
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from backend.analyzer.mtls_server import (
    VerifiedClientCertificateRequestHandler,
    build_mtls_ssl_context,
    inject_verified_client_certificate,
    load_mtls_server_config,
)


class ProductionMtlsBoundaryTests(unittest.TestCase):
    def test_verified_socket_certificate_sets_trusted_fingerprint(self):
        certificate_der = b"synthetic-client-certificate-der"
        connection = Mock()
        connection.getpeercert.return_value = certificate_der

        result = inject_verified_client_certificate(
            {
                "SSL_CLIENT_VERIFY": "SUCCESS",
                "SSL_CLIENT_FINGERPRINT": "attacker-controlled",
            },
            connection,
        )

        self.assertEqual(result["SSL_CLIENT_VERIFY"], "SUCCESS")
        self.assertEqual(
            result["SSL_CLIENT_FINGERPRINT"],
            hashlib.sha256(certificate_der).hexdigest(),
        )

    def test_missing_peer_certificate_fails_closed(self):
        connection = Mock()
        connection.getpeercert.return_value = None

        result = inject_verified_client_certificate(
            {
                "SSL_CLIENT_VERIFY": "SUCCESS",
                "SSL_CLIENT_FINGERPRINT": "untrusted",
            },
            connection,
        )

        self.assertEqual(result["SSL_CLIENT_VERIFY"], "FAILED")
        self.assertNotIn("SSL_CLIENT_FINGERPRINT", result)

    def test_tls_context_requires_client_certificate_and_tls12(self):
        context = Mock()

        with patch(
            "backend.analyzer.mtls_server.ssl.SSLContext",
            return_value=context,
        ) as factory:
            result = build_mtls_ssl_context(
                "server-cert.pem",
                "server-key.pem",
                "client-ca.pem",
            )

        self.assertIs(result, context)
        factory.assert_called_once_with(ssl.PROTOCOL_TLS_SERVER)
        self.assertEqual(
            context.minimum_version,
            ssl.TLSVersion.TLSv1_2,
        )
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        context.load_cert_chain.assert_called_once_with(
            certfile="server-cert.pem",
            keyfile="server-key.pem",
        )
        context.load_verify_locations.assert_called_once_with(
            cafile="client-ca.pem",
        )

    def test_config_requires_certificate_key_and_client_ca_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert = root / "server.pem"
            key = root / "server.key"
            ca = root / "client-ca.pem"
            for path in (cert, key, ca):
                path.write_text("fixture", encoding="utf-8")

            config = load_mtls_server_config({
                "AEGISGUARD_TLS_BIND_HOST": "0.0.0.0",
                "AEGISGUARD_TLS_PORT": "5443",
                "AEGISGUARD_TLS_CERT_FILE": str(cert),
                "AEGISGUARD_TLS_KEY_FILE": str(key),
                "AEGISGUARD_TLS_CLIENT_CA_FILE": str(ca),
            })

        self.assertEqual(config["host"], "0.0.0.0")
        self.assertEqual(config["port"], 5443)

    def test_missing_client_ca_refuses_startup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert = root / "server.pem"
            key = root / "server.key"
            cert.write_text("fixture", encoding="utf-8")
            key.write_text("fixture", encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError,
                "AEGISGUARD_TLS_CLIENT_CA_FILE",
            ):
                load_mtls_server_config({
                    "AEGISGUARD_TLS_CERT_FILE": str(cert),
                    "AEGISGUARD_TLS_KEY_FILE": str(key),
                })

    def test_custom_handler_overrides_make_environ(self):
        self.assertIn(
            "make_environ",
            VerifiedClientCertificateRequestHandler.__dict__,
        )


if __name__ == "__main__":
    unittest.main()
