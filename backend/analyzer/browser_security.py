"""Browser-facing security headers for the AegisGuard application."""

from flask import request


CONTENT_SECURITY_POLICY = (
    "frame-ancestors 'none'; "
    "object-src 'none'; "
    "base-uri 'self'"
)


def install_browser_security_headers(app):
    """Install conservative headers without breaking existing inline UI code."""

    @app.after_request
    def add_browser_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            CONTENT_SECURITY_POLICY,
        )
        if request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000",
            )
        return response

    return add_browser_security_headers
