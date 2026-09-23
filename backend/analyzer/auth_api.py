"""Human-user authentication API for the AegisGuard web application."""

from flask import Blueprint, g, jsonify, request

from backend.storage.login_throttle import (
    DEFAULT_LOGIN_BLOCK_SECONDS,
    DEFAULT_LOGIN_FAILURE_LIMIT,
    DEFAULT_LOGIN_WINDOW_SECONDS,
    LoginThrottledError,
    check_login_allowed,
    clear_login_failures,
    record_login_failure,
)
from backend.storage.user_auth import (
    SessionAuthenticationError,
    UserAuthenticationError,
    UserValidationError,
    authenticate_session,
    authenticate_user,
    create_session,
    csrf_token_for_session_token,
    revoke_session,
    verify_session_csrf,
)


AUTH_SESSION_COOKIE = "aegisguard_session"
AUTH_CSRF_HEADER = "X-AegisGuard-CSRF"
DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60
DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS = 30 * 60


def _error(message, status_code):
    response = jsonify({
        "status": "error",
        "message": message,
    })
    response.status_code = int(status_code)
    return response


def create_auth_blueprint(
    connection_factory,
    *,
    cookie_secure=True,
    session_ttl_seconds=DEFAULT_SESSION_TTL_SECONDS,
    session_idle_timeout_seconds=DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS,
    login_failure_limit=DEFAULT_LOGIN_FAILURE_LIMIT,
    login_window_seconds=DEFAULT_LOGIN_WINDOW_SECONDS,
    login_block_seconds=DEFAULT_LOGIN_BLOCK_SECONDS,
):
    blueprint = Blueprint("aegisguard_user_auth", __name__)

    ttl = int(session_ttl_seconds)
    idle_timeout = int(session_idle_timeout_seconds)
    failure_limit = int(login_failure_limit)
    failure_window = int(login_window_seconds)
    block_seconds = int(login_block_seconds)

    if ttl <= 0:
        raise ValueError("session_ttl_seconds must be greater than zero")
    if idle_timeout <= 0:
        raise ValueError(
            "session_idle_timeout_seconds must be greater than zero"
        )
    if failure_limit <= 0 or failure_window <= 0 or block_seconds <= 0:
        raise ValueError("login throttle settings must be greater than zero")

    def _set_session_cookie(response, token):
        response.set_cookie(
            AUTH_SESSION_COOKIE,
            token,
            max_age=ttl,
            secure=bool(cookie_secure),
            httponly=True,
            samesite="Strict",
            path="/",
        )

    def _clear_session_cookie(response):
        response.delete_cookie(
            AUTH_SESSION_COOKIE,
            secure=bool(cookie_secure),
            httponly=True,
            samesite="Strict",
            path="/",
        )

    @blueprint.post("/api/auth/login")
    def login():
        payload = request.get_json(silent=True) or {}
        username = str(payload.get("username") or "")
        password = str(payload.get("password") or "")

        if not username.strip() or not password:
            return _error("username and password are required", 400)

        peer_ip = request.remote_addr
        conn = connection_factory()
        try:
            try:
                check_login_allowed(
                    conn,
                    username,
                    peer_ip,
                )
            except LoginThrottledError:
                return _error("too many login attempts", 429)

            try:
                user = authenticate_user(
                    conn,
                    username,
                    password,
                )
            except (
                UserAuthenticationError,
                UserValidationError,
            ):
                throttle = record_login_failure(
                    conn,
                    username,
                    peer_ip,
                    failure_limit=failure_limit,
                    window_seconds=failure_window,
                    block_seconds=block_seconds,
                )
                if throttle["blocked_until"] is not None:
                    return _error("too many login attempts", 429)
                return _error("invalid username or password", 401)

            clear_login_failures(
                conn,
                username,
                peer_ip,
            )
            session = create_session(
                conn,
                user["user_id"],
                ttl_seconds=ttl,
                peer_ip=peer_ip,
                user_agent=request.headers.get("User-Agent"),
            )
        finally:
            conn.close()

        g.aegisguard_audit_user = {
            "user_id": user["user_id"],
            "username": user["username"],
            "role": user["role"],
            "session_id": session["session_id"],
        }

        response = jsonify({
            "status": "authenticated",
            "user": {
                "user_id": user["user_id"],
                "username": user["username"],
                "role": user["role"],
            },
            "expires_at": session["expires_at"],
            "csrf_token": session["csrf_token"],
        })
        _set_session_cookie(response, session["token"])
        return response, 200

    @blueprint.get("/api/auth/me")
    def me():
        token = request.cookies.get(AUTH_SESSION_COOKIE)
        if not token:
            return _error("authentication required", 401)

        conn = connection_factory()
        try:
            try:
                session = authenticate_session(
                    conn,
                    token,
                    idle_timeout_seconds=idle_timeout,
                )
            except SessionAuthenticationError:
                return _error("authentication required", 401)
        finally:
            conn.close()

        return jsonify({
            "status": "authenticated",
            "user": {
                "user_id": session["user_id"],
                "username": session["username"],
                "role": session["role"],
            },
            "expires_at": session["expires_at"],
            "csrf_token": csrf_token_for_session_token(token),
        }), 200

    @blueprint.post("/api/auth/logout")
    def logout():
        token = request.cookies.get(AUTH_SESSION_COOKIE)
        if token:
            if not verify_session_csrf(
                token,
                request.headers.get(AUTH_CSRF_HEADER),
            ):
                return _error("csrf token required", 403)

            conn = connection_factory()
            try:
                try:
                    session = authenticate_session(
                        conn,
                        token,
                        idle_timeout_seconds=idle_timeout,
                    )
                    g.aegisguard_audit_user = {
                        "user_id": session["user_id"],
                        "username": session["username"],
                        "role": session["role"],
                        "session_id": session["session_id"],
                    }
                except SessionAuthenticationError:
                    session = None

                try:
                    revoke_session(conn, token)
                except SessionAuthenticationError:
                    pass
            finally:
                conn.close()

        response = jsonify({"status": "logged_out"})
        _clear_session_cookie(response)
        return response, 200

    return blueprint
