import os
import secrets
import socket
from urllib.parse import urlparse

from fastapi import Header, HTTPException, status


DEFAULT_CORS_ORIGINS = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://192.168.4.105:3000",
)


def _discover_local_ipv4_addresses() -> set[str]:
    addresses: set[str] = set()
    try:
        host = socket.gethostname()
        for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            if family != socket.AF_INET:
                continue
            address = sockaddr[0]
            if not address or address.startswith("127."):
                continue
            addresses.add(address)
    except OSError:
        return set()
    return addresses


def _expand_origin_entry(entry: str) -> set[str]:
    raw = entry.strip().rstrip("/")
    if not raw:
        return set()

    candidate = raw if "://" in raw else f"http://{raw}"
    parsed = urlparse(candidate)
    host = parsed.hostname
    scheme = parsed.scheme or "http"
    port = parsed.port
    if not host:
        return set()

    origins = {f"{scheme}://{host}"}
    if port is not None:
        origins.add(f"{scheme}://{host}:{port}")
    else:
        # Most dev frontends run on 3000, so include it automatically to avoid exact-origin mismatch.
        origins.add(f"{scheme}://{host}:3000")
    return origins


def parse_cors_origins() -> list[str]:
    raw = os.getenv("CORS_ALLOW_ORIGINS", "")
    if raw.strip():
        expanded: set[str] = set()
        for item in raw.split(","):
            expanded.update(_expand_origin_entry(item))
        return sorted(expanded)
    discovered = {f"http://{address}:3000" for address in _discover_local_ipv4_addresses()}
    defaults: set[str] = set()
    for item in DEFAULT_CORS_ORIGINS:
        defaults.update(_expand_origin_entry(item))
    return sorted({*defaults, *discovered})


def _extract_api_key(x_api_key: str | None, authorization: str | None) -> str | None:
    if x_api_key and x_api_key.strip():
        return x_api_key.strip()
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        return token or None
    return None


def validate_api_key(x_api_key: str | None, authorization: str | None = None) -> None:
    expected_key = os.getenv("POSTURE_API_KEY", "").strip()
    if not expected_key:
        return

    provided = _extract_api_key(x_api_key, authorization) or ""
    if not provided:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
        )

    if not secrets.compare_digest(provided, expected_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )


def require_api_key(
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> None:
    validate_api_key(x_api_key, authorization)
