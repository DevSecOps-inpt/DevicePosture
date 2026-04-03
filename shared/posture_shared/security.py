import os
import secrets
import socket

from fastapi import Header, HTTPException, status


DEFAULT_CORS_ORIGINS = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
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


def parse_cors_origins() -> list[str]:
    raw = os.getenv("CORS_ALLOW_ORIGINS", "")
    if raw.strip():
        return [item.strip() for item in raw.split(",") if item.strip()]
    discovered = {f"http://{address}:3000" for address in _discover_local_ipv4_addresses()}
    return sorted({*DEFAULT_CORS_ORIGINS, *discovered})


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
