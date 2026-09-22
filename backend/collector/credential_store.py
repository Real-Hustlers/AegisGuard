"""Collector credential protection primitives.

The production Windows collector protects its device credential with Windows
DPAPI in CurrentUser scope before writing it to the collector-state database.
Non-Windows platforms deliberately have no insecure production fallback.
"""

import ctypes
import os
from ctypes import wintypes
from typing import Protocol


class CredentialProtectionError(RuntimeError):
    """Raised when a credential cannot be protected or recovered."""


class CredentialProtector(Protocol):
    def protect(self, plaintext: bytes) -> bytes:
        ...

    def unprotect(self, protected: bytes) -> bytes:
        ...


class UnavailableCredentialProtector:
    """Fail closed when the Windows protection backend is unavailable."""

    def protect(self, plaintext: bytes) -> bytes:
        raise CredentialProtectionError(
            "Windows DPAPI credential protection is unavailable on this platform"
        )

    def unprotect(self, protected: bytes) -> bytes:
        raise CredentialProtectionError(
            "Windows DPAPI credential protection is unavailable on this platform"
        )


if os.name == "nt":
    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]


    def _blob_from_bytes(data: bytes):
        value = bytes(data)
        if not value:
            return _DATA_BLOB(0, None), None

        buffer = ctypes.create_string_buffer(value, len(value))
        blob = _DATA_BLOB(
            len(value),
            ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
        )
        return blob, buffer


    class WindowsDPAPICredentialProtector:
        """Protect credentials with Windows DPAPI CurrentUser scope."""

        CRYPTPROTECT_UI_FORBIDDEN = 0x1

        def __init__(self):
            self._crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            self._crypt32.CryptProtectData.argtypes = [
                ctypes.POINTER(_DATA_BLOB),
                wintypes.LPCWSTR,
                ctypes.POINTER(_DATA_BLOB),
                wintypes.LPVOID,
                wintypes.LPVOID,
                wintypes.DWORD,
                ctypes.POINTER(_DATA_BLOB),
            ]
            self._crypt32.CryptProtectData.restype = wintypes.BOOL

            self._crypt32.CryptUnprotectData.argtypes = [
                ctypes.POINTER(_DATA_BLOB),
                ctypes.POINTER(wintypes.LPWSTR),
                ctypes.POINTER(_DATA_BLOB),
                wintypes.LPVOID,
                wintypes.LPVOID,
                wintypes.DWORD,
                ctypes.POINTER(_DATA_BLOB),
            ]
            self._crypt32.CryptUnprotectData.restype = wintypes.BOOL

            self._kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
            self._kernel32.LocalFree.restype = wintypes.HLOCAL

        def protect(self, plaintext: bytes) -> bytes:
            value = bytes(plaintext)
            if not value:
                raise CredentialProtectionError(
                    "credential plaintext must not be empty"
                )

            input_blob, input_buffer = _blob_from_bytes(value)
            output_blob = _DATA_BLOB()

            ok = self._crypt32.CryptProtectData(
                ctypes.byref(input_blob),
                "AegisGuard Collector Credential",
                None,
                None,
                None,
                self.CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(output_blob),
            )
            _ = input_buffer

            if not ok:
                error = ctypes.get_last_error()
                raise CredentialProtectionError(
                    f"Windows DPAPI protect failed with error {error}"
                )

            try:
                return ctypes.string_at(
                    output_blob.pbData,
                    output_blob.cbData,
                )
            finally:
                if output_blob.pbData:
                    self._kernel32.LocalFree(
                        ctypes.cast(output_blob.pbData, ctypes.c_void_p)
                    )

        def unprotect(self, protected: bytes) -> bytes:
            value = bytes(protected)
            if not value:
                raise CredentialProtectionError(
                    "protected credential must not be empty"
                )

            input_blob, input_buffer = _blob_from_bytes(value)
            output_blob = _DATA_BLOB()
            description = wintypes.LPWSTR()

            ok = self._crypt32.CryptUnprotectData(
                ctypes.byref(input_blob),
                ctypes.byref(description),
                None,
                None,
                None,
                self.CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(output_blob),
            )
            _ = input_buffer

            if not ok:
                error = ctypes.get_last_error()
                raise CredentialProtectionError(
                    f"Windows DPAPI unprotect failed with error {error}"
                )

            try:
                return ctypes.string_at(
                    output_blob.pbData,
                    output_blob.cbData,
                )
            finally:
                if description:
                    self._kernel32.LocalFree(
                        ctypes.cast(description, ctypes.c_void_p)
                    )
                if output_blob.pbData:
                    self._kernel32.LocalFree(
                        ctypes.cast(output_blob.pbData, ctypes.c_void_p)
                    )

else:
    WindowsDPAPICredentialProtector = None


def default_credential_protector():
    """Return the production protector for the Windows collector."""

    if os.name != "nt" or WindowsDPAPICredentialProtector is None:
        return UnavailableCredentialProtector()
    return WindowsDPAPICredentialProtector()
