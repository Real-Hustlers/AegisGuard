"""Human-user authentication API for the AegisGuard web application."""

from flask import Blueprint, jsonify, request

from backend.storage.user_auth import (
    SessionAuthenticationError,
    UserAuthenticationError,
    UserValidationError,
    authenticate_session,
    authenticate_user,
    create_session,
    revoke_session,
)


AUTH_SESSION_COOKIE = "aegisguard_session"
DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60


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
):
    blueprint = Blueprint("aegisguard_user_auth", __name__)

    ttl = int(session_ttl_seconds)
    if ttl <= 0:
        raise ValueError("session_ttl_seconds must be greater than zero")

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

        conn = connection_factory()
        try:
            try:
                user = authenticate_user(
                    conn,
                    username,
                    password,
                )
                session = create_session(
                    conn,
                    user["user_id"],
                    ttl_seconds=ttl,
                    peer_ip=request.remote_addr,
                    user_agent=request.headers.get("User-Agent"),
                )
            except (
                UserAuthenticationError,
                UserValidationError,
            ):
                return _error("invalid username or password", 401)
        finally:
            conn.close()

        response = jsonify({
            "status": "authenticated",
            "user": {
                "user_id": user["user_id"],
                "username": user["username"],
                "role": user["role"],
            },
            "expires_at": session["expires_at"],
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
                session = authenticate_session(conn, token)
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
        }), 200

    @blueprint.post("/api/auth/logout")
    def logout():
        token = request.cookies.get(AUTH_SESSION_COOKIE)
        if token:
            conn = connection_factory()
            try:
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
