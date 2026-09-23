import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask

from backend.analyzer.auth_api import (
    AUTH_CSRF_HEADER,
    AUTH_SESSION_COOKIE,
    create_auth_blueprint,
)
from backend.storage.migrations import ensure_platform_schema
from backend.storage.user_auth import (
    SessionAuthenticationError,
    UserAuthenticationError,
    authenticate_session,
    authenticate_user,
    create_session,
    create_user,
    session_token_fingerprint,
    set_user_active,
    verify_password,
)


class UserAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "auth.db"

    def tearDown(self):
        self.tmp.cleanup()

    def connection_factory(self):
        conn = sqlite3.connect(str(self.db_path))
        ensure_platform_schema(conn)
        return conn

    def create_test_user(
        self,
        username="analyst",
        password="correct-horse-battery",
        role="ANALYST",
    ):
        conn = self.connection_factory()
        try:
            return create_user(
                conn,
                username,
                password,
                role,
                user_id="user-1",
            )
        finally:
            conn.close()

    def make_client(self, *, cookie_secure=False, ttl=3600):
        app = Flask(__name__)
        app.register_blueprint(
            create_auth_blueprint(
                self.connection_factory,
                cookie_secure=cookie_secure,
                session_ttl_seconds=ttl,
            )
        )
        app.testing = True
        return app.test_client()

    def test_user_password_is_scrypt_hashed_and_not_plaintext(self):
        self.create_test_user()

        conn = self.connection_factory()
        try:
            row = conn.execute(
                """
                SELECT username, password_hash, role, active
                FROM users
                WHERE user_id='user-1'
                """
            ).fetchone()
        finally:
            conn.close()

        self.assertEqual(row[0], "analyst")
        self.assertTrue(str(row[1]).startswith("scrypt$"))
        self.assertNotIn("correct-horse-battery", str(row[1]))
        self.assertTrue(
            verify_password(
                "correct-horse-battery",
                row[1],
            )
        )
        self.assertEqual(row[2], "ANALYST")
        self.assertEqual(row[3], 1)

    def test_authenticate_user_rejects_wrong_password_and_inactive_user(self):
        user = self.create_test_user()

        conn = self.connection_factory()
        try:
            with self.assertRaises(UserAuthenticationError):
                authenticate_user(
                    conn,
                    "analyst",
                    "wrong-password-value",
                )

            self.assertTrue(
                set_user_active(
                    conn,
                    user["user_id"],
                    False,
                )
            )

            with self.assertRaises(UserAuthenticationError):
                authenticate_user(
                    conn,
                    "analyst",
                    "correct-horse-battery",
                )
        finally:
            conn.close()

    def test_session_persists_only_token_fingerprint(self):
        user = self.create_test_user()
        fixed_token = "x" * 64

        conn = self.connection_factory()
        try:
            session = create_session(
                conn,
                user["user_id"],
                ttl_seconds=3600,
                token_factory=lambda: fixed_token,
            )
            row = conn.execute(
                """
                SELECT token_hash
                FROM sessions
                WHERE session_id = ?
                """,
                (session["session_id"],),
            ).fetchone()
        finally:
            conn.close()

        self.assertEqual(session["token"], fixed_token)
        self.assertEqual(
            row[0],
            session_token_fingerprint(fixed_token),
        )
        self.assertNotEqual(row[0], fixed_token)

    def test_expired_session_is_rejected(self):
        user = self.create_test_user()
        start = datetime(
            2026,
            9,
            23,
            8,
            0,
            tzinfo=timezone.utc,
        )

        conn = self.connection_factory()
        try:
            session = create_session(
                conn,
                user["user_id"],
                ttl_seconds=60,
                now=start,
                token_factory=lambda: "y" * 64,
            )
            with self.assertRaises(SessionAuthenticationError):
                authenticate_session(
                    conn,
                    session["token"],
                    now=start + timedelta(seconds=61),
                )
        finally:
            conn.close()

    def test_login_me_logout_flow_and_restart_persistence(self):
        self.create_test_user()
        client = self.make_client()

        denied = client.post(
            "/api/auth/login",
            json={
                "username": "analyst",
                "password": "wrong-password-value",
            },
        )
        self.assertEqual(denied.status_code, 401)

        login = client.post(
            "/api/auth/login",
            json={
                "username": "Analyst",
                "password": "correct-horse-battery",
            },
        )
        self.assertEqual(login.status_code, 200)
        self.assertEqual(
            login.get_json()["user"]["role"],
            "ANALYST",
        )

        cookie = login.headers.get("Set-Cookie", "")
        self.assertIn(f"{AUTH_SESSION_COOKIE}=", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertNotIn("correct-horse-battery", cookie)

        current = client.get("/api/auth/me")
        self.assertEqual(current.status_code, 200)
        self.assertEqual(
            current.get_json()["user"]["username"],
            "analyst",
        )

        restarted = self.make_client()
        session_cookie = client.get_cookie(AUTH_SESSION_COOKIE)
        self.assertIsNotNone(session_cookie)
        restarted.set_cookie(
            AUTH_SESSION_COOKIE,
            session_cookie.value,
        )
        after_restart = restarted.get("/api/auth/me")
        self.assertEqual(after_restart.status_code, 200)

        csrf_token = after_restart.get_json()["csrf_token"]
        logout = restarted.post(
            "/api/auth/logout",
            headers={AUTH_CSRF_HEADER: csrf_token},
        )
        self.assertEqual(logout.status_code, 200)

        after_logout = restarted.get("/api/auth/me")
        self.assertEqual(after_logout.status_code, 401)

    def test_secure_cookie_flag_is_enabled_when_configured(self):
        self.create_test_user()
        client = self.make_client(cookie_secure=True)

        login = client.post(
            "/api/auth/login",
            json={
                "username": "analyst",
                "password": "correct-horse-battery",
            },
        )

        self.assertEqual(login.status_code, 200)
        cookie = login.headers.get("Set-Cookie", "")
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_inactive_user_invalidates_existing_session(self):
        user = self.create_test_user()
        conn = self.connection_factory()
        try:
            session = create_session(
                conn,
                user["user_id"],
                ttl_seconds=3600,
                token_factory=lambda: "z" * 64,
            )
            self.assertTrue(
                set_user_active(
                    conn,
                    user["user_id"],
                    False,
                )
            )
            with self.assertRaises(SessionAuthenticationError):
                authenticate_session(conn, session["token"])
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
