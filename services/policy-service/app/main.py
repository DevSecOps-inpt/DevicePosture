import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from uuid import uuid4

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Query, Request as FastAPIRequest, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import Base, engine, get_db
from app.models import (
    AuthProviderDirectoryGroupModel,
    AuthProviderModel,
    ConditionGroupModel,
    Policy,
    PolicyAssignmentModel,
    UserAccountModel,
)
from app.schemas import (
    AuthProviderCreate,
    AuthProviderResponse,
    AuthProviderUpdate,
    AuthSessionUser,
    AssignmentCreate,
    AssignmentResponse,
    ConditionGroupCreate,
    ConditionGroupResponse,
    ConditionGroupUpdate,
    DirectoryGroupResponse,
    DirectoryGroupSearchItem,
    DirectoryGroupSearchRequest,
    DirectoryGroupSearchResponse,
    EndpointAssignedPolicyResponse,
    EndpointDomainVerificationRequest,
    EndpointDomainVerificationResponse,
    LoginRequest,
    LoginResponse,
    ProviderConnectivityResult,
    ProviderCredentialsTestRequest,
    PolicyCreate,
    PolicyResponse,
    PolicyUpdate,
    UserAccountCreate,
    UserAccountResponse,
    UserAccountUpdate,
)
from posture_shared.security import parse_cors_origins, require_api_key
Base.metadata.create_all(bind=engine)

ALLOWED_CONDITION_GROUP_TYPES = {"allowed_os", "allowed_patches", "allowed_antivirus_families"}
DEFAULT_CONDITION_GROUPS: list[tuple[str, str, str]] = [
    ("Allowed OS", "allowed_os", "Baseline allow-list for operating system names"),
    ("Allowed Patches", "allowed_patches", "Baseline allow-list for Windows KB patch identifiers"),
    ("Allowed Antivirus Families", "allowed_antivirus_families", "Baseline allow-list for antivirus family names"),
]
SUPPORTED_AUTH_PROTOCOLS = {"ldap", "radius", "oidc", "oauth2", "saml"}
DEFAULT_ADMIN_USERNAME = os.getenv("DEFAULT_ADMIN_USERNAME", "admin").strip() or "admin"
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin123!ChangeMe")
RESET_DEFAULT_ADMIN_PASSWORD = os.getenv("RESET_DEFAULT_ADMIN_PASSWORD", "false").lower() == "true"
AUTH_TOKEN_TTL_MINUTES = int(os.getenv("AUTH_TOKEN_TTL_MINUTES", "720"))
AUTH_TOKEN_SECRET = (
    os.getenv("POSTURE_AUTH_TOKEN_SECRET", "").strip()
    or os.getenv("POSTURE_API_KEY", "").strip()
    or "dev-only-change-this-secret"
)
SESSION_COOKIE_NAME = "posture_session"
SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "lax")
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
logger = logging.getLogger("policy-service")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)
AUTH_RATE_LIMIT_PER_MINUTE = int(os.getenv("AUTH_RATE_LIMIT_PER_MINUTE", "60"))
_auth_rate_lock = threading.Lock()
_auth_rate_state: dict[str, list[float]] = {}


def ensure_policy_columns() -> None:
    inspector = inspect(engine)
    existing_columns = {column["name"] for column in inspector.get_columns("policies")}
    statements: list[str] = []
    if "policy_scope" not in existing_columns:
        statements.append("ALTER TABLE policies ADD COLUMN policy_scope VARCHAR(32) DEFAULT 'posture'")
    if "lifecycle_event_type" not in existing_columns:
        statements.append("ALTER TABLE policies ADD COLUMN lifecycle_event_type VARCHAR(64)")
    if "execution" not in existing_columns:
        statements.append("ALTER TABLE policies ADD COLUMN execution JSON")

    if statements:
        with engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))


ensure_policy_columns()


def ensure_user_columns() -> None:
    inspector = inspect(engine)
    existing_columns = {column["name"] for column in inspector.get_columns("user_accounts")}
    statements: list[str] = []
    if "external_provider_id" not in existing_columns:
        statements.append("ALTER TABLE user_accounts ADD COLUMN external_provider_id INTEGER")
    if statements:
        with engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))


ensure_user_columns()


def ensure_policy_indexes() -> None:
    statements = [
        "CREATE INDEX IF NOT EXISTS idx_policy_assignments_lookup ON policy_assignments(assignment_type, assignment_value, id DESC)",
        "CREATE INDEX IF NOT EXISTS idx_policies_scope_active ON policies(policy_scope, is_active, lifecycle_event_type)",
        "CREATE INDEX IF NOT EXISTS idx_condition_groups_type_name ON condition_groups(group_type, name)",
        "CREATE INDEX IF NOT EXISTS idx_auth_providers_enabled_priority ON auth_providers(is_enabled, priority, id)",
        "CREATE INDEX IF NOT EXISTS idx_auth_provider_directory_groups_provider_name ON auth_provider_directory_groups(provider_id, group_name)",
        "CREATE INDEX IF NOT EXISTS idx_auth_provider_directory_groups_provider_dn ON auth_provider_directory_groups(provider_id, group_dn)",
        "CREATE INDEX IF NOT EXISTS idx_user_accounts_source_subject ON user_accounts(auth_source, external_subject, is_active)",
        "CREATE INDEX IF NOT EXISTS idx_user_accounts_external_provider ON user_accounts(external_provider_id, auth_source, is_active)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


ensure_policy_indexes()


def ensure_default_condition_groups() -> None:
    with Session(engine) as db:
        for name, group_type, description in DEFAULT_CONDITION_GROUPS:
            existing = db.scalar(
                select(ConditionGroupModel).where(
                    ConditionGroupModel.name == name,
                    ConditionGroupModel.group_type == group_type,
                )
            )
            if existing is not None:
                continue
            db.add(
                ConditionGroupModel(
                    name=name,
                    group_type=group_type,
                    description=description,
                    values=[],
                )
            )
        db.commit()


ensure_default_condition_groups()

app = FastAPI(title="policy-service", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=parse_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1200, compresslevel=6)


@app.middleware("http")
async def request_observability_middleware(request: FastAPIRequest, call_next):
    request_id = request.headers.get("X-Request-ID", "").strip() or str(uuid4())
    started_at = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - started_at) * 1000
    response.headers["X-Request-ID"] = request_id
    logger.info(
        "request_id=%s method=%s path=%s status=%s duration_ms=%.2f",
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    return response


def normalize_condition_values(values: list[str]) -> list[str]:
    return [item.strip() for item in values if item and item.strip()]


def apply_auth_rate_limit(identity: str) -> None:
    now = time.monotonic()
    with _auth_rate_lock:
        history = _auth_rate_state.setdefault(identity, [])
        history[:] = [item for item in history if now - item <= 60.0]
        if len(history) >= AUTH_RATE_LIMIT_PER_MINUTE:
            raise HTTPException(status_code=429, detail="Too many authentication attempts")
        history.append(now)


def expand_condition_groups(conditions: list[dict], db: Session) -> list[dict]:
    expanded: list[dict] = []
    for condition in conditions:
        raw_value = condition.get("value")
        if not isinstance(raw_value, dict):
            expanded.append(condition)
            continue
        group_id = raw_value.get("group_id")
        group_name = raw_value.get("group_name")
        group_type = raw_value.get("group_type")
        group: ConditionGroupModel | None = None
        if isinstance(group_id, int):
            group = db.get(ConditionGroupModel, group_id)
        elif isinstance(group_name, str):
            query = select(ConditionGroupModel).where(ConditionGroupModel.name == group_name)
            if isinstance(group_type, str) and group_type.strip():
                query = query.where(ConditionGroupModel.group_type == group_type.strip())
            group = db.scalar(query)

        if group is None:
            expanded.append(condition)
            continue

        resolved = dict(condition)
        resolved["value"] = normalize_condition_values(group.values or [])
        expanded.append(resolved)
    return expanded


def _domain_suffix_from_base_dn(base_dn: str | None) -> str | None:
    text = (base_dn or "").strip()
    if not text:
        return None
    labels: list[str] = []
    for part in text.split(","):
        segment = part.strip()
        if segment.lower().startswith("dc="):
            value = segment[3:].strip().lower()
            if value:
                labels.append(value)
    if not labels:
        return None
    return ".".join(labels)


def _extract_ldap_tree_hints(settings: dict[str, Any]) -> tuple[str | None, list[str]]:
    raw_base_dn = (
        settings.get("base_dn")
        or settings.get("search_base_dn")
        or settings.get("domain_base_dn")
        or settings.get("root_dn")
        or settings.get("search_base")
        or ""
    )
    base_dn = str(raw_base_dn).strip() or None

    suffixes: set[str] = set()
    for key in ("domain_suffix", "domain_name", "domain", "dns_domain"):
        value = str(settings.get(key) or "").strip().lower()
        if value:
            suffixes.add(value)

    raw_suffixes = settings.get("domain_suffixes") or settings.get("tree_domain_suffixes") or []
    if isinstance(raw_suffixes, list):
        for item in raw_suffixes:
            value = str(item).strip().lower()
            if value:
                suffixes.add(value)

    derived_from_base_dn = _domain_suffix_from_base_dn(base_dn)
    if derived_from_base_dn:
        suffixes.add(derived_from_base_dn)

    return base_dn, sorted(suffixes)


def _matches_tree(
    *,
    domain_name: str,
    domain_dn: str,
    suffixes: list[str],
    base_dn: str | None,
) -> bool:
    normalized_suffixes = [item.strip().lower() for item in suffixes if item and item.strip()]
    normalized_base_dn = (base_dn or "").strip().lower()
    derived_suffix = _domain_suffix_from_base_dn(normalized_base_dn)
    if derived_suffix and derived_suffix not in normalized_suffixes:
        normalized_suffixes.append(derived_suffix)

    if normalized_suffixes and domain_name:
        for suffix in normalized_suffixes:
            if domain_name == suffix or domain_name.endswith(f".{suffix}"):
                return True

    if normalized_base_dn and domain_dn and domain_dn.endswith(normalized_base_dn):
        return True

    if not normalized_suffixes and not normalized_base_dn:
        return True

    return False


def enrich_domain_membership_condition(condition: dict[str, Any], db: Session) -> dict[str, Any]:
    condition_type = str(condition.get("type") or "").strip().lower()
    if condition_type != "domain_membership":
        return condition

    value = condition.get("value")
    if not isinstance(value, dict):
        raise HTTPException(
            status_code=422,
            detail="domain_membership condition requires an object value with provider_id or provider_name",
        )

    provider: AuthProviderModel | None = None
    provider_id = value.get("provider_id")
    provider_id_int: int | None = None
    if isinstance(provider_id, int):
        provider_id_int = provider_id
    elif isinstance(provider_id, str) and provider_id.strip().isdigit():
        provider_id_int = int(provider_id.strip())
    provider_name = value.get("provider_name")

    if provider_id_int is not None:
        provider = db.scalar(
            select(AuthProviderModel).where(
                AuthProviderModel.id == provider_id_int,
                AuthProviderModel.protocol == "ldap",
                AuthProviderModel.is_enabled.is_(True),
            )
        )
    elif isinstance(provider_name, str) and provider_name.strip():
        provider = db.scalar(
            select(AuthProviderModel).where(
                AuthProviderModel.name == provider_name.strip(),
                AuthProviderModel.protocol == "ldap",
                AuthProviderModel.is_enabled.is_(True),
            )
        )
    else:
        raise HTTPException(
            status_code=422,
            detail="domain_membership condition requires provider_id or provider_name",
        )

    if provider is None:
        raise HTTPException(
            status_code=422,
            detail="Selected LDAP provider must exist and be enabled",
        )

    base_dn, domain_suffixes = _extract_ldap_tree_hints(provider.settings or {})

    required_group_ids: list[int] = []
    raw_required_group_ids = value.get("required_group_ids")
    if isinstance(raw_required_group_ids, list):
        for item in raw_required_group_ids:
            if isinstance(item, int):
                required_group_ids.append(item)
            elif isinstance(item, str) and item.strip().isdigit():
                required_group_ids.append(int(item.strip()))
    elif isinstance(raw_required_group_ids, int):
        required_group_ids.append(raw_required_group_ids)

    required_group_dns = [
        _normalize_group_dn(item)
        for item in (value.get("required_group_dns") or [])
        if isinstance(item, str)
    ]
    required_group_dns = [item for item in required_group_dns if item]

    required_group_names = [
        str(item).strip()
        for item in (value.get("required_group_names") or [])
        if isinstance(item, str) and str(item).strip()
    ]

    if required_group_ids:
        groups = db.scalars(
            select(AuthProviderDirectoryGroupModel).where(
                AuthProviderDirectoryGroupModel.provider_id == provider.id,
                AuthProviderDirectoryGroupModel.id.in_(required_group_ids),
            )
        ).all()
        if not groups:
            raise HTTPException(status_code=422, detail="Selected LDAP groups were not found for provider")
        required_group_dns = [
            item.group_dn
            for item in groups
            if item.group_dn
        ]
        required_group_names = [item.group_name for item in groups if item.group_name]
        required_group_ids = [item.id for item in groups]
    elif required_group_names:
        groups = db.scalars(
            select(AuthProviderDirectoryGroupModel).where(
                AuthProviderDirectoryGroupModel.provider_id == provider.id,
                AuthProviderDirectoryGroupModel.group_name.in_(required_group_names),
            )
        ).all()
        if groups:
            required_group_dns = [
                item.group_dn
                for item in groups
                if item.group_dn
            ]
            required_group_names = [item.group_name for item in groups if item.group_name]
            required_group_ids = [item.id for item in groups]

    enriched_value = dict(value)
    enriched_value["provider_id"] = provider.id
    enriched_value["provider_name"] = provider.name
    enriched_value["provider_priority"] = provider.priority
    enriched_value["required_group_ids"] = required_group_ids
    enriched_value["required_group_dns"] = required_group_dns
    enriched_value["required_group_names"] = required_group_names
    if base_dn:
        enriched_value["provider_base_dn"] = base_dn
    if domain_suffixes:
        enriched_value["allowed_domain_suffixes"] = domain_suffixes

    enriched_condition = dict(condition)
    enriched_condition["value"] = enriched_value
    return enriched_condition


def enrich_policy_conditions_for_storage(conditions: list[dict[str, Any]], db: Session) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for condition in conditions:
        enriched.append(enrich_domain_membership_condition(condition, db))
    return enriched


def to_policy_response(policy: Policy, *, db: Session | None = None, resolve_groups: bool = False) -> PolicyResponse:
    conditions = policy.conditions
    if resolve_groups and db is not None:
        conditions = expand_condition_groups(policy.conditions, db)

    return PolicyResponse(
        id=policy.id,
        name=policy.name,
        description=policy.description,
        policy_scope=policy.policy_scope,
        lifecycle_event_type=policy.lifecycle_event_type,
        target_action=policy.target_action,
        is_active=policy.is_active,
        conditions=conditions,
        execution=policy.execution or None,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


def _dedupe_assignments(assignments: list[PolicyAssignmentModel]) -> list[PolicyAssignmentModel]:
    unique: list[PolicyAssignmentModel] = []
    seen: set[tuple[str, str]] = set()
    for assignment in assignments:
        key = (assignment.assignment_type, assignment.assignment_value)
        if key in seen:
            continue
        seen.add(key)
        unique.append(assignment)
    return unique


def resolve_assigned_policy(
    *,
    db: Session,
    endpoint_id: str,
    groups: list[str],
    scope: str,
    lifecycle_event_type: str | None = None,
) -> Policy | None:
    policies = resolve_assigned_policies(
        db=db,
        endpoint_id=endpoint_id,
        groups=groups,
        scope=scope,
        lifecycle_event_type=lifecycle_event_type,
    )
    return policies[0] if policies else None


def resolve_assigned_policies(
    *,
    db: Session,
    endpoint_id: str,
    groups: list[str],
    scope: str,
    lifecycle_event_type: str | None = None,
) -> list[Policy]:
    def _dedupe_by_policy_id(policies: list[Policy]) -> list[Policy]:
        deduped: list[Policy] = []
        seen_policy_ids: set[int] = set()
        for policy in policies:
            if policy.id in seen_policy_ids:
                continue
            seen_policy_ids.add(policy.id)
            deduped.append(policy)
        return deduped

    def _resolve_from_assignment_query(base_query) -> list[Policy]:
        query = base_query.where(
            Policy.is_active.is_(True),
            Policy.policy_scope == scope,
        )
        if scope == "lifecycle":
            query = query.where(Policy.lifecycle_event_type == lifecycle_event_type)
        query = query.order_by(PolicyAssignmentModel.id.desc(), Policy.id.desc())
        rows = db.scalars(query).all()
        return _dedupe_by_policy_id(rows)

    endpoint_policies = _resolve_from_assignment_query(
        select(Policy)
        .join(PolicyAssignmentModel, PolicyAssignmentModel.policy_id == Policy.id)
        .where(
            PolicyAssignmentModel.assignment_type == "endpoint",
            PolicyAssignmentModel.assignment_value == endpoint_id,
        )
    )

    group_policies: list[Policy] = []
    if groups:
        group_policies = _resolve_from_assignment_query(
            select(Policy)
            .join(PolicyAssignmentModel, PolicyAssignmentModel.policy_id == Policy.id)
            .where(
                PolicyAssignmentModel.assignment_type == "group",
                PolicyAssignmentModel.assignment_value.in_(groups),
            )
        )

    default_policies = _resolve_from_assignment_query(
        select(Policy)
        .join(PolicyAssignmentModel, PolicyAssignmentModel.policy_id == Policy.id)
        .where(PolicyAssignmentModel.assignment_type == "default")
    )
    return _dedupe_by_policy_id([
        *endpoint_policies,
        *group_policies,
        *default_policies,
    ])


def hash_password(password: str, *, iterations: int = 120_000) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${base64.urlsafe_b64encode(digest).decode('utf-8')}"


def verify_password(password: str, stored_hash: str | None) -> bool:
    if not stored_hash:
        return False
    parts = stored_hash.split("$")
    if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
        return False
    try:
        iterations = int(parts[1])
    except ValueError:
        return False
    salt = parts[2]
    expected = parts[3]
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
    candidate = base64.urlsafe_b64encode(digest).decode("utf-8")
    return secrets.compare_digest(candidate, expected)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padded = data + "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("utf-8"))


def issue_auth_token(user: UserAccountModel) -> tuple[str, datetime]:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=AUTH_TOKEN_TTL_MINUTES)
    payload = {
        "sub": user.username,
        "auth_source": user.auth_source,
        "roles": user.roles or [],
        "exp": int(expires_at.timestamp()),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_token = _b64url_encode(payload_bytes)
    signature = hmac.new(AUTH_TOKEN_SECRET.encode("utf-8"), payload_token.encode("utf-8"), hashlib.sha256).digest()
    token = f"{payload_token}.{_b64url_encode(signature)}"
    return token, expires_at


def decode_auth_token(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 2:
        raise HTTPException(status_code=401, detail="Invalid session token")
    payload_token, signature_token = parts
    expected_sig = hmac.new(AUTH_TOKEN_SECRET.encode("utf-8"), payload_token.encode("utf-8"), hashlib.sha256).digest()
    if not secrets.compare_digest(_b64url_encode(expected_sig), signature_token):
        raise HTTPException(status_code=401, detail="Invalid session token signature")

    payload = json.loads(_b64url_decode(payload_token).decode("utf-8"))
    expires_unix = int(payload.get("exp", 0))
    if time.time() > expires_unix:
        raise HTTPException(status_code=401, detail="Session token expired")
    return payload


def get_session_user(
    authorization: str | None = Header(default=None),
    posture_session: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> UserAccountModel:
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    elif posture_session:
        token = posture_session.strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing session token")
    payload = decode_auth_token(token)
    username = str(payload.get("sub") or "").strip()
    if not username:
        raise HTTPException(status_code=401, detail="Invalid session token payload")
    user = db.scalar(select(UserAccountModel).where(UserAccountModel.username == username))
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Session user is not active")
    return user


def require_admin_session(user: UserAccountModel = Depends(get_session_user)) -> UserAccountModel:
    roles = {item.lower() for item in (user.roles or [])}
    if "admin" not in roles:
        raise HTTPException(status_code=403, detail="Admin role is required")
    return user


def parse_host_port_from_uri(uri: str, default_port: int) -> tuple[str, int]:
    parsed = urlparse(uri)
    if parsed.scheme:
        host = parsed.hostname
        port = parsed.port or default_port
    else:
        if ":" in uri:
            host, raw_port = uri.rsplit(":", 1)
            port = int(raw_port)
        else:
            host, port = uri, default_port
    if not host:
        raise ValueError("Missing host")
    return host, port


def _normalize_group_dn(value: str | None) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    return text.lower()


def _is_probably_computer_group(*, group_name: str, group_dn: str | None) -> bool:
    normalized_name = group_name.strip().lower()
    normalized_dn = (group_dn or "").strip().lower()
    computer_markers = (
        "ou=computers",
        "ou=workstations",
        "ou=devices",
        "cn=computers",
    )
    if any(marker in normalized_dn for marker in computer_markers):
        return True
    return any(token in normalized_name for token in ("computer", "workstation", "device", "endpoint"))


def _build_group_search_bases(*, settings: dict[str, Any], explicit_search_base: str | None = None) -> list[str]:
    candidates: list[str] = []
    if explicit_search_base and explicit_search_base.strip():
        candidates.append(explicit_search_base.strip())

    configured_group_base = str(settings.get("group_base_dn") or "").strip()
    configured_base_dn = str(settings.get("base_dn") or "").strip()
    if configured_group_base:
        candidates.append(configured_group_base)
    if configured_base_dn:
        candidates.append(configured_base_dn)

    raw_extra_bases = settings.get("group_search_bases") or []
    if isinstance(raw_extra_bases, list):
        for item in raw_extra_bases:
            value = str(item or "").strip()
            if value:
                candidates.append(value)

    # Include default AD containers so built-in groups are discoverable
    # even when a narrow base is configured.
    if configured_base_dn:
        candidates.extend(
            [
                f"CN=Builtin,{configured_base_dn}",
                f"CN=Users,{configured_base_dn}",
                f"CN=Computers,{configured_base_dn}",
            ]
        )

    deduped: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        key = item.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(item.strip())
    return deduped


def _group_candidate_from_ldap_entry(*, entry: Any, name_attribute: str) -> dict[str, Any]:
    entry_json = entry.entry_attributes_as_dict
    candidate_name = (
        (entry_json.get(name_attribute) or [None])[0]
        or (entry_json.get("cn") or [None])[0]
        or (entry_json.get("name") or [None])[0]
        or str(entry.entry_dn)
    )
    group_dn = str(entry.entry_dn).strip().lower()
    normalized_name = str(candidate_name).strip() or group_dn
    return {
        "group_key": group_dn or normalized_name.lower(),
        "group_name": normalized_name,
        "group_dn": group_dn or None,
        "is_computer_group": _is_probably_computer_group(
            group_name=normalized_name,
            group_dn=group_dn,
        ),
    }


def _search_ldap_groups_across_bases(
    *,
    connection: Any,
    search_bases: list[str],
    search_filter: str,
    name_attribute: str,
    size_limit: int | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    candidates: list[dict[str, Any]] = []
    warnings: list[str] = []
    remaining = size_limit if isinstance(size_limit, int) and size_limit > 0 else None

    for search_base in search_bases:
        base_limit = remaining if remaining is not None else 0
        try:
            ok = connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=[name_attribute, "distinguishedName", "cn", "name", "sAMAccountName"],
                size_limit=base_limit,
            )
            if not ok:
                result = getattr(connection, "result", {}) or {}
                result_code = int(result.get("result", 1))
                # 0 = success, 4 = size limit exceeded (entries are still valid)
                if result_code not in {0, 4}:
                    warnings.append(
                        f"{search_base}: {result.get('description', 'search_failed')}"
                    )
                    continue

            for entry in connection.entries:
                candidates.append(_group_candidate_from_ldap_entry(entry=entry, name_attribute=name_attribute))
                if remaining is not None:
                    remaining -= 1
                    if remaining <= 0:
                        break
            if remaining is not None and remaining <= 0:
                break
        except Exception as exc:
            warnings.append(f"{search_base}: {exc}")

    deduped: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for item in candidates:
        key = str(item.get("group_key") or "").strip().lower()
        if not key or key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(item)
    return deduped, warnings


def list_provider_directory_groups(
    *,
    db: Session,
    provider_id: int,
    computer_only: bool = False,
) -> list[AuthProviderDirectoryGroupModel]:
    query = select(AuthProviderDirectoryGroupModel).where(AuthProviderDirectoryGroupModel.provider_id == provider_id)
    if computer_only:
        query = query.where(AuthProviderDirectoryGroupModel.is_computer_group.is_(True))
    query = query.order_by(AuthProviderDirectoryGroupModel.group_name, AuthProviderDirectoryGroupModel.id)
    return db.scalars(query).all()


def replace_provider_directory_groups(
    *,
    db: Session,
    provider: AuthProviderModel,
    groups: list[dict[str, Any]],
    clear_missing: bool = True,
) -> list[AuthProviderDirectoryGroupModel]:
    existing = db.scalars(
        select(AuthProviderDirectoryGroupModel).where(AuthProviderDirectoryGroupModel.provider_id == provider.id)
    ).all()
    existing_by_key = {item.group_key: item for item in existing}

    normalized_payload: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for raw in groups:
        group_name = str(raw.get("group_name") or raw.get("name") or "").strip()
        group_dn = _normalize_group_dn(raw.get("group_dn") or raw.get("dn"))
        if not group_name and not group_dn:
            continue
        group_key = str(raw.get("group_key") or group_dn or group_name.lower()).strip()
        if not group_key or group_key in seen_keys:
            continue
        seen_keys.add(group_key)
        normalized_payload.append(
            {
                "group_key": group_key,
                "group_name": group_name or (group_dn or group_key),
                "group_dn": group_dn,
                "is_computer_group": bool(
                    raw.get("is_computer_group")
                    if "is_computer_group" in raw
                    else _is_probably_computer_group(group_name=group_name or (group_dn or group_key), group_dn=group_dn)
                ),
            }
        )

    if clear_missing:
        kept_keys = {item["group_key"] for item in normalized_payload}
        for item in existing:
            if item.group_key not in kept_keys:
                db.delete(item)

    for payload in normalized_payload:
        item = existing_by_key.get(payload["group_key"])
        if item is None:
            item = AuthProviderDirectoryGroupModel(
                provider_id=provider.id,
                group_key=payload["group_key"],
                group_name=payload["group_name"],
                group_dn=payload["group_dn"],
                is_computer_group=payload["is_computer_group"],
            )
            db.add(item)
            continue
        item.group_name = payload["group_name"]
        item.group_dn = payload["group_dn"]
        item.is_computer_group = payload["is_computer_group"]

    db.flush()
    return list_provider_directory_groups(db=db, provider_id=provider.id)


def _groups_from_provider_settings(settings: dict[str, Any]) -> list[dict[str, Any]]:
    fallback_groups = settings.get("directory_groups_cache")
    if not isinstance(fallback_groups, list):
        fallback_groups = settings.get("test_groups")
    groups: list[dict[str, Any]] = []
    if isinstance(fallback_groups, list):
        for item in fallback_groups:
            if isinstance(item, dict):
                groups.append(item)
            elif isinstance(item, str):
                groups.append({"group_name": item, "group_dn": item})
    return groups


def _extract_ldap_member_groups(
    provider: AuthProviderModel,
    *,
    username: str,
    password: str,
) -> tuple[bool, list[str], list[str], str]:
    settings = provider.settings or {}
    try:
        from ldap3 import ALL, SUBTREE, Connection, Server
        from ldap3.utils.conv import escape_filter_chars
    except Exception as exc:
        return False, [], [], f"ldap3 dependency is missing: {exc}"

    server_uri = str(settings.get("server_uri") or "").strip()
    if not server_uri:
        return False, [], [], "Missing LDAP server_uri"

    timeout_seconds = float(settings.get("timeout_seconds", 5))
    bind_template = str(settings.get("bind_dn_template") or settings.get("user_bind_dn_template") or "").strip()
    service_bind_dn = str(settings.get("bind_dn") or settings.get("service_account_dn") or "").strip()
    service_bind_password = str(settings.get("bind_password") or settings.get("service_account_password") or "")
    user_search_base = str(settings.get("user_search_base") or settings.get("base_dn") or "").strip()
    user_search_filter = str(settings.get("user_search_filter") or "(|(uid={username})(sAMAccountName={username})(cn={username}))").strip()

    escaped_username = escape_filter_chars(username)
    user_filter = user_search_filter.replace("{username}", escaped_username)
    if "{username}" not in user_search_filter:
        user_filter = f"(&(objectClass=person){user_filter})"

    def _read_groups_from_entry(entry: Any) -> tuple[list[str], list[str]]:
        payload = entry.entry_attributes_as_dict
        raw_member_of = payload.get("memberOf", [])
        if not isinstance(raw_member_of, list):
            raw_member_of = [raw_member_of]
        group_dns = [
            str(item).strip().lower()
            for item in raw_member_of
            if str(item).strip()
        ]
        group_names: list[str] = []
        for group_dn in group_dns:
            match = re.search(r"cn=([^,]+)", group_dn, flags=re.IGNORECASE)
            if match:
                group_names.append(match.group(1).strip())
            else:
                group_names.append(group_dn)
        return group_names, group_dns

    try:
        server = Server(server_uri, get_info=ALL, connect_timeout=timeout_seconds)

        if bind_template:
            user_bind_dn = bind_template.replace("{username}", username)
            connection = Connection(server, user=user_bind_dn, password=password, auto_bind=True, receive_timeout=timeout_seconds)
            with connection:
                if user_search_base:
                    connection.search(
                        search_base=user_search_base,
                        search_filter=user_filter,
                        search_scope=SUBTREE,
                        attributes=["memberOf", "cn", "distinguishedName"],
                    )
                    if not connection.entries:
                        return True, [], [], "LDAP bind succeeded but user group membership is empty"
                    group_names, group_dns = _read_groups_from_entry(connection.entries[0])
                    return True, group_names, group_dns, "LDAP credentials accepted"
                return True, [], [], "LDAP credentials accepted"

        if service_bind_dn:
            service_connection = Connection(
                server,
                user=service_bind_dn,
                password=service_bind_password,
                auto_bind=True,
                receive_timeout=timeout_seconds,
            )
            with service_connection:
                if not user_search_base:
                    return False, [], [], "Missing LDAP user_search_base/base_dn for service-account flow"
                service_connection.search(
                    search_base=user_search_base,
                    search_filter=user_filter,
                    search_scope=SUBTREE,
                    attributes=["distinguishedName", "memberOf", "cn"],
                )
                if not service_connection.entries:
                    return False, [], [], "LDAP user was not found in directory"
                user_entry = service_connection.entries[0]
                user_dn = str(getattr(user_entry, "entry_dn", "")).strip()
                if not user_dn:
                    return False, [], [], "LDAP user DN could not be resolved"

                user_connection = Connection(
                    server,
                    user=user_dn,
                    password=password,
                    auto_bind=True,
                    receive_timeout=timeout_seconds,
                )
                with user_connection:
                    user_connection.search(
                        search_base=user_search_base,
                        search_filter=user_filter,
                        search_scope=SUBTREE,
                        attributes=["memberOf", "cn", "distinguishedName"],
                    )
                    target_entry = user_connection.entries[0] if user_connection.entries else user_entry
                    group_names, group_dns = _read_groups_from_entry(target_entry)
                    return True, group_names, group_dns, "LDAP credentials accepted"

        return False, [], [], "LDAP provider requires bind_dn_template or service account settings"
    except Exception as exc:
        return False, [], [], f"LDAP credential check failed: {exc}"


def _verify_endpoint_domain_membership(
    provider: AuthProviderModel,
    payload: EndpointDomainVerificationRequest,
) -> EndpointDomainVerificationResponse:
    settings = provider.settings or {}
    base_dn, domain_suffixes = _extract_ldap_tree_hints(settings)
    joined = bool((payload.domain_name or "").strip() or (payload.domain_dn or "").strip())
    domain_name = str(payload.domain_name or "").strip().lower()
    domain_dn = str(payload.domain_dn or "").strip().lower()
    in_tree = joined and _matches_tree(
        domain_name=domain_name,
        domain_dn=domain_dn,
        suffixes=domain_suffixes,
        base_dn=base_dn,
    )

    required_group_dns = sorted(
        {
            item.strip().lower()
            for item in payload.required_group_dns
            if item and item.strip()
        }
    )

    if not joined:
        return EndpointDomainVerificationResponse(
            ok=False,
            joined=False,
            in_tree=False,
            in_required_groups=False,
            provider_id=provider.id,
            provider_name=provider.name,
            endpoint_id=payload.endpoint_id,
            hostname=payload.hostname,
            domain_name=payload.domain_name,
            domain_dn=payload.domain_dn,
            computer_dn=None,
            member_group_dns=[],
            required_group_dns=required_group_dns,
            message="Endpoint is not domain-joined",
        )

    if not in_tree:
        return EndpointDomainVerificationResponse(
            ok=False,
            joined=True,
            in_tree=False,
            in_required_groups=False,
            provider_id=provider.id,
            provider_name=provider.name,
            endpoint_id=payload.endpoint_id,
            hostname=payload.hostname,
            domain_name=payload.domain_name,
            domain_dn=payload.domain_dn,
            computer_dn=None,
            member_group_dns=[],
            required_group_dns=required_group_dns,
            message="Endpoint domain is outside selected LDAP tree",
        )

    if not required_group_dns:
        return EndpointDomainVerificationResponse(
            ok=True,
            joined=True,
            in_tree=True,
            in_required_groups=True,
            provider_id=provider.id,
            provider_name=provider.name,
            endpoint_id=payload.endpoint_id,
            hostname=payload.hostname,
            domain_name=payload.domain_name,
            domain_dn=payload.domain_dn,
            computer_dn=None,
            member_group_dns=[],
            required_group_dns=[],
            message="Endpoint domain joined and within LDAP tree",
        )

    try:
        from ldap3 import ALL, SUBTREE, Connection, Server
        from ldap3.utils.conv import escape_filter_chars
    except Exception as exc:
        return EndpointDomainVerificationResponse(
            ok=False,
            joined=True,
            in_tree=True,
            in_required_groups=False,
            provider_id=provider.id,
            provider_name=provider.name,
            endpoint_id=payload.endpoint_id,
            hostname=payload.hostname,
            domain_name=payload.domain_name,
            domain_dn=payload.domain_dn,
            computer_dn=None,
            member_group_dns=[],
            required_group_dns=required_group_dns,
            message=f"LDAP verification dependency missing: {exc}",
        )

    server_uri = str(settings.get("server_uri") or "").strip()
    if not server_uri:
        return EndpointDomainVerificationResponse(
            ok=False,
            joined=True,
            in_tree=True,
            in_required_groups=False,
            provider_id=provider.id,
            provider_name=provider.name,
            endpoint_id=payload.endpoint_id,
            hostname=payload.hostname,
            domain_name=payload.domain_name,
            domain_dn=payload.domain_dn,
            computer_dn=None,
            member_group_dns=[],
            required_group_dns=required_group_dns,
            message="LDAP provider is missing server_uri",
        )

    bind_dn = str(settings.get("bind_dn") or settings.get("service_account_dn") or "").strip()
    bind_password = str(settings.get("bind_password") or settings.get("service_account_password") or "")
    search_base = str(settings.get("computer_search_base") or settings.get("base_dn") or "").strip()
    search_filter_template = str(
        settings.get("computer_search_filter")
        or "(&(objectClass=computer)(|(cn={hostname})(name={hostname})(sAMAccountName={hostname}$)))"
    ).strip()
    timeout_seconds = float(settings.get("timeout_seconds", 5))

    escaped_hostname = escape_filter_chars(payload.hostname)
    search_filter = search_filter_template.replace("{hostname}", escaped_hostname)

    try:
        server = Server(server_uri, get_info=ALL, connect_timeout=timeout_seconds)
        connection_kwargs: dict[str, Any] = {
            "auto_bind": True,
            "receive_timeout": timeout_seconds,
        }
        if bind_dn:
            connection_kwargs["user"] = bind_dn
            connection_kwargs["password"] = bind_password
        connection = Connection(server, **connection_kwargs)
        with connection:
            if not search_base:
                raise ValueError("Missing computer_search_base/base_dn")
            connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["distinguishedName", "memberOf", "cn", "dNSHostName", "name"],
            )
            if not connection.entries:
                return EndpointDomainVerificationResponse(
                    ok=False,
                    joined=True,
                    in_tree=True,
                    in_required_groups=False,
                    provider_id=provider.id,
                    provider_name=provider.name,
                    endpoint_id=payload.endpoint_id,
                    hostname=payload.hostname,
                    domain_name=payload.domain_name,
                    domain_dn=payload.domain_dn,
                    computer_dn=None,
                    member_group_dns=[],
                    required_group_dns=required_group_dns,
                    message="Endpoint computer object not found in LDAP directory",
                )

            entry = connection.entries[0]
            entry_payload = entry.entry_attributes_as_dict
            raw_member_of = entry_payload.get("memberOf", [])
            if not isinstance(raw_member_of, list):
                raw_member_of = [raw_member_of]
            member_group_dns = sorted(
                {
                    str(item).strip().lower()
                    for item in raw_member_of
                    if str(item).strip()
                }
            )
            in_required_groups = all(item in member_group_dns for item in required_group_dns)
            return EndpointDomainVerificationResponse(
                ok=in_required_groups,
                joined=True,
                in_tree=True,
                in_required_groups=in_required_groups,
                provider_id=provider.id,
                provider_name=provider.name,
                endpoint_id=payload.endpoint_id,
                hostname=payload.hostname,
                domain_name=payload.domain_name,
                domain_dn=payload.domain_dn,
                computer_dn=str(getattr(entry, "entry_dn", "")).strip() or None,
                member_group_dns=member_group_dns,
                required_group_dns=required_group_dns,
                message=(
                    "Endpoint computer is in required LDAP groups"
                    if in_required_groups
                    else "Endpoint computer is not in required LDAP groups"
                ),
            )
    except Exception as exc:
        return EndpointDomainVerificationResponse(
            ok=False,
            joined=True,
            in_tree=True,
            in_required_groups=False,
            provider_id=provider.id,
            provider_name=provider.name,
            endpoint_id=payload.endpoint_id,
            hostname=payload.hostname,
            domain_name=payload.domain_name,
            domain_dn=payload.domain_dn,
            computer_dn=None,
            member_group_dns=[],
            required_group_dns=required_group_dns,
            message=f"LDAP computer-group verification failed: {exc}",
        )


def sync_provider_directory_groups(
    *,
    db: Session,
    provider: AuthProviderModel,
    allow_cache_fallback: bool = False,
) -> tuple[list[AuthProviderDirectoryGroupModel], str]:
    if provider.protocol != "ldap":
        raise HTTPException(status_code=422, detail="Directory group sync is currently supported only for LDAP providers")

    settings = provider.settings or {}
    synced_groups: list[dict[str, Any]] = []
    sync_message = "Loaded directory groups from provider settings cache"
    sync_warnings: list[str] = []

    try:
        from ldap3 import ALL, SUBTREE, Connection, Server

        server_uri = str(settings.get("server_uri") or "").strip()
        if not server_uri:
            raise ValueError("Missing LDAP server_uri")
        search_bases = _build_group_search_bases(settings=settings)
        if not search_bases:
            raise ValueError("Missing LDAP base_dn/group_base_dn")
        bind_dn = str(settings.get("bind_dn") or settings.get("service_account_dn") or "").strip()
        bind_password = str(settings.get("bind_password") or settings.get("service_account_password") or "")
        name_attribute = str(settings.get("group_name_attribute") or "cn").strip() or "cn"
        search_filter = str(settings.get("group_search_filter") or "(objectClass=group)").strip() or "(objectClass=group)"
        timeout_seconds = float(settings.get("timeout_seconds", 5))

        server = Server(server_uri, get_info=ALL, connect_timeout=timeout_seconds)
        if bind_dn:
            connection = Connection(server, user=bind_dn, password=bind_password, auto_bind=True, receive_timeout=timeout_seconds)
        else:
            connection = Connection(server, auto_bind=True, receive_timeout=timeout_seconds)
        with connection:
            synced_groups, sync_warnings = _search_ldap_groups_across_bases(
                connection=connection,
                search_bases=search_bases,
                search_filter=search_filter,
                name_attribute=name_attribute,
            )
        sync_message = (
            f"Directory groups synchronized from LDAP ({len(synced_groups)} groups, {len(search_bases)} bases)"
        )
        if sync_warnings:
            logger.info(
                "provider_id=%s LDAP group sync warnings: %s",
                provider.id,
                "; ".join(sync_warnings),
            )
    except Exception as exc:
        logger.warning("failed to sync LDAP directory groups provider_id=%s: %s", provider.id, exc)
        if not allow_cache_fallback:
            raise HTTPException(status_code=502, detail=f"LDAP live sync failed: {exc}") from exc
        synced_groups = _groups_from_provider_settings(settings)
        if not synced_groups:
            raise HTTPException(
                status_code=502,
                detail=f"LDAP live sync failed and no cached groups are available: {exc}",
            ) from exc
        sync_message = f"LDAP live sync failed, using cached/test groups: {exc}"

    updated_groups = replace_provider_directory_groups(db=db, provider=provider, groups=synced_groups)
    provider_settings = dict(settings)
    provider_settings["directory_groups_last_sync"] = datetime.now(timezone.utc).isoformat()
    provider_settings["directory_groups_last_count"] = len(updated_groups)
    provider.settings = provider_settings
    db.flush()
    return updated_groups, sync_message


def _build_group_search_filter(*, ldap_filter: str, search: str | None) -> str:
    base_filter = ldap_filter.strip() or "(objectClass=group)"
    if not base_filter.startswith("(") or not base_filter.endswith(")"):
        raise ValueError("LDAP filter must be enclosed in parentheses")
    if not search:
        return base_filter
    escaped = re.sub(r"([\\()*\0])", lambda match: "\\" + format(ord(match.group(1)), "02x"), search.strip())
    free_text_filter = (
        f"(|(cn=*{escaped}*)(name=*{escaped}*)(sAMAccountName=*{escaped}*)(distinguishedName=*{escaped}*))"
    )
    return f"(&{base_filter}{free_text_filter})"


def search_provider_directory_groups(
    *,
    db: Session,
    provider: AuthProviderModel,
    payload: DirectoryGroupSearchRequest,
) -> DirectoryGroupSearchResponse:
    if provider.protocol != "ldap":
        raise HTTPException(status_code=422, detail="Directory group search is supported only for LDAP providers")

    settings = provider.settings or {}
    server_uri = str(settings.get("server_uri") or "").strip()
    if not server_uri:
        raise HTTPException(status_code=422, detail="LDAP provider is missing server_uri")
    search_base = str(payload.search_base or "").strip()
    search_bases = _build_group_search_bases(settings=settings, explicit_search_base=search_base)
    if not search_bases:
        raise HTTPException(status_code=422, detail="LDAP provider is missing base_dn/group_base_dn")

    bind_dn = str(settings.get("bind_dn") or settings.get("service_account_dn") or "").strip()
    bind_password = str(settings.get("bind_password") or settings.get("service_account_password") or "")
    name_attribute = str(settings.get("group_name_attribute") or "cn").strip() or "cn"
    timeout_seconds = float(settings.get("timeout_seconds", 5))

    try:
        from ldap3 import ALL, SUBTREE, Connection, Server
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"ldap3 dependency is missing: {exc}") from exc

    try:
        search_filter = _build_group_search_filter(
            ldap_filter=payload.ldap_filter,
            search=payload.search,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    candidates: list[dict[str, Any]] = []
    search_warnings: list[str] = []
    try:
        server = Server(server_uri, get_info=ALL, connect_timeout=timeout_seconds)
        if bind_dn:
            connection = Connection(server, user=bind_dn, password=bind_password, auto_bind=True, receive_timeout=timeout_seconds)
        else:
            connection = Connection(server, auto_bind=True, receive_timeout=timeout_seconds)
        with connection:
            candidates, search_warnings = _search_ldap_groups_across_bases(
                connection=connection,
                search_bases=search_bases,
                search_filter=search_filter,
                size_limit=payload.limit,
                name_attribute=name_attribute,
            )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LDAP group search failed: {exc}") from exc

    if payload.computer_only:
        candidates = [item for item in candidates if bool(item.get("is_computer_group"))]
    if search_warnings:
        logger.info(
            "provider_id=%s LDAP group search warnings: %s",
            provider.id,
            "; ".join(search_warnings),
        )

    existing = db.scalars(
        select(AuthProviderDirectoryGroupModel).where(AuthProviderDirectoryGroupModel.provider_id == provider.id)
    ).all()
    existing_by_key = {item.group_key: item for item in existing}

    imported_count = 0
    if payload.persist and candidates:
        updated_groups = replace_provider_directory_groups(
            db=db,
            provider=provider,
            groups=candidates,
            clear_missing=False,
        )
        db.flush()
        refreshed_by_key = {item.group_key: item for item in updated_groups}
        imported_count = sum(1 for item in candidates if item.get("group_key") in refreshed_by_key and item.get("group_key") not in existing_by_key)
        provider_settings = dict(settings)
        provider_settings["directory_groups_last_search"] = datetime.now(timezone.utc).isoformat()
        provider_settings["directory_groups_last_search_count"] = len(candidates)
        provider.settings = provider_settings
        db.commit()
        existing_by_key = {item.group_key: item for item in updated_groups}

    items: list[DirectoryGroupSearchItem] = []
    for item in candidates:
        key = str(item.get("group_key") or "").strip()
        cached = existing_by_key.get(key)
        items.append(
            DirectoryGroupSearchItem(
                id=cached.id if cached else None,
                group_key=key,
                group_name=str(item.get("group_name") or key),
                group_dn=item.get("group_dn"),
                is_computer_group=bool(item.get("is_computer_group")),
                already_cached=cached is not None,
            )
        )

    return DirectoryGroupSearchResponse(
        provider_id=provider.id,
        provider_name=provider.name,
        search_filter=search_filter,
        search_base=", ".join(search_bases),
        search=payload.search,
        matched_count=len(items),
        imported_count=imported_count,
        items=items,
        message=(
            ("LDAP groups imported into cache" if payload.persist else "LDAP groups preview returned")
            + (f" ({len(search_warnings)} base warnings)" if search_warnings else "")
        ),
    )


def provider_connectivity_check(provider: AuthProviderModel) -> ProviderConnectivityResult:
    protocol = provider.protocol
    settings = provider.settings or {}

    try:
        if protocol == "ldap":
            host, port = parse_host_port_from_uri(str(settings.get("server_uri") or ""), 389)
            with socket.create_connection((host, port), timeout=float(settings.get("timeout_seconds", 5))):
                pass
            return ProviderConnectivityResult(ok=True, message="LDAP server reachable", details={"host": host, "port": port})

        if protocol == "radius":
            host = str(settings.get("host") or "").strip()
            port = int(settings.get("auth_port", 1812))
            if not host:
                raise ValueError("Missing RADIUS host")
            with socket.create_connection((host, port), timeout=float(settings.get("timeout_seconds", 5))):
                pass
            return ProviderConnectivityResult(ok=True, message="RADIUS server reachable", details={"host": host, "port": port})

        if protocol in {"oidc", "oauth2"}:
            discovery_url = str(settings.get("discovery_url") or "").strip()
            issuer_url = str(settings.get("issuer_url") or "").strip()
            token_endpoint = str(settings.get("token_endpoint") or "").strip()
            target = discovery_url or (
                f"{issuer_url.rstrip('/')}/.well-known/openid-configuration" if issuer_url else token_endpoint
            )
            if not target:
                raise ValueError("Missing discovery_url, issuer_url, or token_endpoint")
            request = Request(target, method="GET")
            with urlopen(request, timeout=float(settings.get("timeout_seconds", 5))) as response:
                status_code = getattr(response, "status", 200)
            if int(status_code) >= 400:
                raise ValueError(f"Provider responded with HTTP {status_code}")
            return ProviderConnectivityResult(ok=True, message="OIDC/OAuth provider reachable", details={"url": target})

        if protocol == "saml":
            metadata_url = str(settings.get("metadata_url") or settings.get("idp_metadata_url") or "").strip()
            sso_url = str(settings.get("sso_url") or "").strip()
            target = metadata_url or sso_url
            if not target:
                raise ValueError("Missing metadata_url or sso_url")
            request = Request(target, method="GET")
            with urlopen(request, timeout=float(settings.get("timeout_seconds", 5))) as response:
                status_code = getattr(response, "status", 200)
            if int(status_code) >= 400:
                raise ValueError(f"Provider responded with HTTP {status_code}")
            return ProviderConnectivityResult(ok=True, message="SAML IdP reachable", details={"url": target})

        return ProviderConnectivityResult(ok=False, message=f"Unsupported provider protocol '{protocol}'")
    except Exception as exc:
        return ProviderConnectivityResult(ok=False, message=str(exc))


def _try_test_accounts(
    provider: AuthProviderModel,
    username: str,
    password: str,
) -> tuple[bool, list[str], str]:
    settings = provider.settings or {}
    test_accounts = settings.get("test_accounts", [])
    if isinstance(test_accounts, list):
        for item in test_accounts:
            if not isinstance(item, dict):
                continue
            account_username = str(item.get("username") or "").strip()
            account_password = str(item.get("password") or "")
            if username == account_username and secrets.compare_digest(password, account_password):
                groups = [str(group).strip() for group in item.get("groups", []) if str(group).strip()]
                return True, groups, "Credentials accepted via provider test_accounts"
    if bool(settings.get("accept_all_credentials_for_testing")) and username and password:
        return True, [], "Credentials accepted via accept_all_credentials_for_testing"
    return False, [], "Credentials rejected by provider test accounts"


def provider_test_credentials(
    provider: AuthProviderModel,
    username: str,
    password: str,
) -> ProviderConnectivityResult:
    connectivity = provider_connectivity_check(provider)
    if not connectivity.ok:
        return connectivity

    protocol = provider.protocol
    settings = provider.settings or {}

    if protocol == "ldap":
        ok, groups, group_dns, message = _extract_ldap_member_groups(
            provider,
            username=username,
            password=password,
        )
        if ok:
            return ProviderConnectivityResult(
                ok=True,
                message=message,
                details={"groups": groups, "group_dns": group_dns},
            )
        fallback_ok, fallback_groups, fallback_message = _try_test_accounts(provider, username, password)
        if fallback_ok:
            return ProviderConnectivityResult(
                ok=True,
                message=f"{fallback_message} (LDAP live check failed: {message})",
                details={"groups": fallback_groups, "group_dns": []},
            )
        return ProviderConnectivityResult(ok=False, message=message)

    if protocol == "oauth2":
        token_endpoint = str(settings.get("token_endpoint") or "").strip()
        client_id = str(settings.get("client_id") or "").strip()
        client_secret = str(settings.get("client_secret") or "").strip()
        if token_endpoint and client_id:
            body = (
                "grant_type=password"
                f"&username={username}"
                f"&password={password}"
                f"&client_id={client_id}"
            )
            if client_secret:
                body = f"{body}&client_secret={client_secret}"
            request = Request(
                token_endpoint,
                data=body.encode("utf-8"),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            try:
                with urlopen(request, timeout=float(settings.get("timeout_seconds", 5))) as response:
                    payload = json.loads(response.read().decode("utf-8") or "{}")
                if payload.get("access_token"):
                    return ProviderConnectivityResult(ok=True, message="OAuth2 credentials accepted")
            except Exception:
                pass

    ok, groups, message = _try_test_accounts(provider, username, password)
    return ProviderConnectivityResult(ok=ok, message=message, details={"groups": groups} if ok else {})


def ensure_default_admin_user() -> None:
    with Session(engine) as db:
        existing = db.scalar(select(UserAccountModel).where(UserAccountModel.username == DEFAULT_ADMIN_USERNAME))
        if existing is not None:
            if RESET_DEFAULT_ADMIN_PASSWORD:
                existing.local_password_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
                existing.is_active = True
                if "admin" not in (existing.roles or []):
                    existing.roles = sorted({*(existing.roles or []), "admin"})
                db.commit()
            return
        db.add(
            UserAccountModel(
                username=DEFAULT_ADMIN_USERNAME,
                full_name="Platform Administrator",
                is_active=True,
                auth_source="local",
                local_password_hash=hash_password(DEFAULT_ADMIN_PASSWORD),
                roles=["admin"],
                external_groups=[],
            )
        )
        db.commit()


def to_auth_provider_response(item: AuthProviderModel) -> AuthProviderResponse:
    sanitized_settings: dict = {}
    for key, value in (item.settings or {}).items():
        if key.lower() in {"client_secret", "bind_password", "shared_secret"} and value:
            sanitized_settings[key] = "********"
        else:
            sanitized_settings[key] = value
    return AuthProviderResponse(
        id=item.id,
        name=item.name,
        protocol=item.protocol,
        is_enabled=item.is_enabled,
        priority=item.priority,
        settings=sanitized_settings,
        created_at=item.created_at,
        updated_at=item.updated_at,
    )


def to_user_response(item: UserAccountModel) -> UserAccountResponse:
    return UserAccountResponse(
        id=item.id,
        username=item.username,
        full_name=item.full_name,
        email=item.email,
        is_active=item.is_active,
        auth_source=item.auth_source,
        external_provider_id=item.external_provider_id,
        external_subject=item.external_subject,
        external_groups=item.external_groups or [],
        roles=item.roles or [],
        created_at=item.created_at,
        updated_at=item.updated_at,
    )


ensure_default_admin_user()


@app.get("/healthz")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/policies", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
def create_policy(
    payload: PolicyCreate,
    _: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> PolicyResponse:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="name is required")

    duplicate = db.scalar(select(Policy).where(Policy.name == name))
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="Policy with this name already exists")

    normalized_conditions = [item.model_dump(mode="json") for item in payload.conditions]
    if payload.policy_scope == "lifecycle" and payload.lifecycle_event_type == "active_to_inactive":
        normalized_conditions = []
    else:
        normalized_conditions = enrich_policy_conditions_for_storage(normalized_conditions, db)

    policy = Policy(
        name=name,
        description=payload.description,
        policy_scope=payload.policy_scope,
        lifecycle_event_type=payload.lifecycle_event_type,
        target_action=payload.target_action,
        is_active=payload.is_active,
        conditions=normalized_conditions,
        execution=payload.execution.model_dump(mode="json") if payload.execution else {},
    )
    db.add(policy)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Policy with this name already exists")
    db.refresh(policy)
    return to_policy_response(policy, db=db)


@app.get("/policies", response_model=list[PolicyResponse])
def list_policies(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=100000),
    _: UserAccountModel = Depends(get_session_user),
    db: Session = Depends(get_db),
) -> list[PolicyResponse]:
    policies = db.scalars(select(Policy).order_by(Policy.id).offset(offset).limit(limit)).all()
    return [to_policy_response(policy, db=db) for policy in policies]


@app.get("/policies/{policy_id}", response_model=PolicyResponse)
def get_policy(
    policy_id: int,
    _: UserAccountModel = Depends(get_session_user),
    db: Session = Depends(get_db),
) -> PolicyResponse:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return to_policy_response(policy, db=db)


@app.put("/policies/{policy_id}", response_model=PolicyResponse)
def update_policy(
    policy_id: int,
    payload: PolicyUpdate,
    _: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> PolicyResponse:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")

    changes = payload.model_dump(exclude_unset=True)
    candidate_scope = changes.get("policy_scope", policy.policy_scope)
    candidate_event_type = changes.get("lifecycle_event_type", policy.lifecycle_event_type)
    if candidate_scope == "lifecycle" and candidate_event_type is None:
        raise HTTPException(status_code=422, detail="lifecycle_event_type is required when policy_scope is 'lifecycle'")
    if candidate_scope == "posture":
        changes["lifecycle_event_type"] = None

    if candidate_scope == "lifecycle" and candidate_event_type == "active_to_inactive":
        changes["conditions"] = []
    elif "conditions" in changes:
        normalized_conditions = [item.model_dump(mode="json") for item in payload.conditions or []]
        changes["conditions"] = enrich_policy_conditions_for_storage(normalized_conditions, db)
    if "execution" in changes and payload.execution is not None:
        changes["execution"] = payload.execution.model_dump(mode="json")
    if "name" in changes and changes["name"] is not None:
        normalized_name = str(changes["name"]).strip()
        if not normalized_name:
            raise HTTPException(status_code=422, detail="name is required")
        duplicate = db.scalar(
            select(Policy).where(
                Policy.id != policy_id,
                Policy.name == normalized_name,
            )
        )
        if duplicate is not None:
            raise HTTPException(status_code=409, detail="Policy with this name already exists")
        changes["name"] = normalized_name
    for key, value in changes.items():
        setattr(policy, key, value)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Policy with this name already exists")
    db.refresh(policy)
    return to_policy_response(policy, db=db)


@app.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(
    policy_id: int,
    _: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> None:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    db.delete(policy)
    db.commit()


@app.post("/policies/{policy_id}/assignments", response_model=AssignmentResponse, status_code=status.HTTP_201_CREATED)
def create_assignment(
    policy_id: int,
    payload: AssignmentCreate,
    _: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> AssignmentResponse:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")

    assignment_value = payload.assignment_value.strip()
    if payload.assignment_type == "default":
        assignment_value = "default"
    if not assignment_value:
        raise HTTPException(status_code=422, detail="assignment_value is required")

    existing = db.scalar(
        select(PolicyAssignmentModel)
        .where(
            PolicyAssignmentModel.policy_id == policy_id,
            PolicyAssignmentModel.assignment_type == payload.assignment_type,
            PolicyAssignmentModel.assignment_value == assignment_value,
        )
        .order_by(PolicyAssignmentModel.id.desc())
    )
    if existing is not None:
        return AssignmentResponse.model_validate(existing)

    assignment = PolicyAssignmentModel(
        policy_id=policy_id,
        assignment_type=payload.assignment_type,
        assignment_value=assignment_value,
    )
    db.add(assignment)
    db.commit()
    db.refresh(assignment)
    return AssignmentResponse.model_validate(assignment)


@app.get("/policies/{policy_id}/assignments", response_model=list[AssignmentResponse])
def list_assignments(
    policy_id: int,
    _: UserAccountModel = Depends(get_session_user),
    db: Session = Depends(get_db),
) -> list[AssignmentResponse]:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    assignments = db.scalars(
        select(PolicyAssignmentModel)
        .where(PolicyAssignmentModel.policy_id == policy_id)
        .order_by(PolicyAssignmentModel.id.desc())
    ).all()
    deduped = _dedupe_assignments(assignments)
    return [AssignmentResponse.model_validate(item) for item in deduped]


@app.get("/endpoints/{endpoint_id}/assigned-policies", response_model=list[EndpointAssignedPolicyResponse])
def list_endpoint_assigned_policies(
    endpoint_id: str,
    _: UserAccountModel = Depends(get_session_user),
    db: Session = Depends(get_db),
) -> list[EndpointAssignedPolicyResponse]:
    assignments = db.scalars(
        select(PolicyAssignmentModel)
        .where(
            PolicyAssignmentModel.assignment_type == "endpoint",
            PolicyAssignmentModel.assignment_value == endpoint_id,
        )
        .order_by(PolicyAssignmentModel.id.desc())
    ).all()
    responses: list[EndpointAssignedPolicyResponse] = []
    seen: set[tuple[int, str, str | None]] = set()
    for assignment in assignments:
        policy = db.get(Policy, assignment.policy_id)
        if policy is None:
            continue
        key = (policy.id, policy.policy_scope, policy.lifecycle_event_type)
        if key in seen:
            continue
        seen.add(key)
        responses.append(
            EndpointAssignedPolicyResponse(
                policy_id=policy.id,
                policy_name=policy.name,
                policy_scope=policy.policy_scope,
                lifecycle_event_type=policy.lifecycle_event_type,
                assignment_type=assignment.assignment_type,
                assignment_value=assignment.assignment_value,
            )
        )
    return responses


@app.get("/endpoints/assigned-policies-batch", response_model=dict[str, list[EndpointAssignedPolicyResponse]])
def list_endpoint_assigned_policies_batch(
    endpoint_id: list[str] = Query(default=[]),
    _: UserAccountModel = Depends(get_session_user),
    db: Session = Depends(get_db),
) -> dict[str, list[EndpointAssignedPolicyResponse]]:
    endpoint_ids = [item.strip() for item in endpoint_id if item.strip()]
    if not endpoint_ids:
        return {}
    assignments = db.scalars(
        select(PolicyAssignmentModel)
        .where(
            PolicyAssignmentModel.assignment_type == "endpoint",
            PolicyAssignmentModel.assignment_value.in_(endpoint_ids),
        )
        .order_by(PolicyAssignmentModel.assignment_value, PolicyAssignmentModel.id.desc())
    ).all()
    policy_ids = {item.policy_id for item in assignments}
    policies = db.scalars(select(Policy).where(Policy.id.in_(policy_ids))).all() if policy_ids else []
    policy_by_id = {item.id: item for item in policies}
    response: dict[str, list[EndpointAssignedPolicyResponse]] = {item: [] for item in endpoint_ids}
    seen_by_endpoint: dict[str, set[tuple[int, str, str | None]]] = {item: set() for item in endpoint_ids}
    for assignment in assignments:
        policy = policy_by_id.get(assignment.policy_id)
        if policy is None:
            continue
        dedupe_key = (policy.id, policy.policy_scope, policy.lifecycle_event_type)
        endpoint_seen = seen_by_endpoint.setdefault(assignment.assignment_value, set())
        if dedupe_key in endpoint_seen:
            continue
        endpoint_seen.add(dedupe_key)
        response.setdefault(assignment.assignment_value, []).append(
            EndpointAssignedPolicyResponse(
                policy_id=policy.id,
                policy_name=policy.name,
                policy_scope=policy.policy_scope,
                lifecycle_event_type=policy.lifecycle_event_type,
                assignment_type=assignment.assignment_type,
                assignment_value=assignment.assignment_value,
            )
        )
    return response


@app.get("/policy-match/{endpoint_id}", response_model=PolicyResponse | None)
def resolve_policy(
    endpoint_id: str,
    groups: list[str] = Query(default=[]),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> PolicyResponse | None:
    policy = resolve_assigned_policy(
        db=db,
        endpoint_id=endpoint_id,
        groups=groups,
        scope="posture",
    )
    if policy is not None:
        return to_policy_response(policy, db=db, resolve_groups=True)

    return None


@app.get("/policy-matches/{endpoint_id}", response_model=list[PolicyResponse])
def resolve_policies(
    endpoint_id: str,
    groups: list[str] = Query(default=[]),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> list[PolicyResponse]:
    policies = resolve_assigned_policies(
        db=db,
        endpoint_id=endpoint_id,
        groups=groups,
        scope="posture",
    )
    return [to_policy_response(policy, db=db, resolve_groups=True) for policy in policies]


@app.get("/policy-match-batch", response_model=dict[str, PolicyResponse | None])
def resolve_policy_batch(
    endpoint_id: list[str] = Query(default=[]),
    groups: list[str] = Query(default=[]),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> dict[str, PolicyResponse | None]:
    endpoint_ids = [item.strip() for item in endpoint_id if item.strip()]
    response: dict[str, PolicyResponse | None] = {}
    for item in endpoint_ids:
        policy = resolve_assigned_policy(
            db=db,
            endpoint_id=item,
            groups=groups,
            scope="posture",
        )
        response[item] = to_policy_response(policy, db=db, resolve_groups=True) if policy is not None else None
    return response


@app.get("/lifecycle-policy-match/{event_type}/{endpoint_id}", response_model=PolicyResponse | None)
def resolve_lifecycle_policy(
    event_type: str,
    endpoint_id: str,
    groups: list[str] = Query(default=[]),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> PolicyResponse | None:
    if event_type not in {"telemetry_received", "active_to_inactive"}:
        raise HTTPException(status_code=400, detail="Unsupported lifecycle event type")

    policy = resolve_assigned_policy(
        db=db,
        endpoint_id=endpoint_id,
        groups=groups,
        scope="lifecycle",
        lifecycle_event_type=event_type,
    )
    if policy is not None:
        return to_policy_response(policy, db=db, resolve_groups=True)
    return None


@app.get("/lifecycle-policy-matches/{event_type}/{endpoint_id}", response_model=list[PolicyResponse])
def resolve_lifecycle_policies(
    event_type: str,
    endpoint_id: str,
    groups: list[str] = Query(default=[]),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> list[PolicyResponse]:
    if event_type not in {"telemetry_received", "active_to_inactive"}:
        raise HTTPException(status_code=400, detail="Unsupported lifecycle event type")

    policies = resolve_assigned_policies(
        db=db,
        endpoint_id=endpoint_id,
        groups=groups,
        scope="lifecycle",
        lifecycle_event_type=event_type,
    )
    return [to_policy_response(policy, db=db, resolve_groups=True) for policy in policies]


@app.get("/condition-groups", response_model=list[ConditionGroupResponse])
def list_condition_groups(
    group_type: str | None = Query(default=None),
    _: UserAccountModel = Depends(get_session_user),
    db: Session = Depends(get_db),
) -> list[ConditionGroupResponse]:
    query = select(ConditionGroupModel).order_by(ConditionGroupModel.group_type, ConditionGroupModel.name)
    if group_type is not None:
        query = query.where(ConditionGroupModel.group_type == group_type)
    groups = db.scalars(query).all()
    return [ConditionGroupResponse.model_validate(item) for item in groups]


@app.post("/condition-groups", response_model=ConditionGroupResponse, status_code=status.HTTP_201_CREATED)
def create_condition_group(
    payload: ConditionGroupCreate,
    _: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> ConditionGroupResponse:
    normalized_name = payload.name.strip()
    if not normalized_name:
        raise HTTPException(status_code=422, detail="name is required")

    group_type = payload.group_type.strip()
    if group_type not in ALLOWED_CONDITION_GROUP_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"group_type must be one of {sorted(ALLOWED_CONDITION_GROUP_TYPES)}",
        )

    exists = db.scalar(
        select(ConditionGroupModel).where(
            ConditionGroupModel.name == normalized_name,
            ConditionGroupModel.group_type == group_type,
        )
    )
    if exists is not None:
        raise HTTPException(status_code=409, detail="Condition group with this name already exists for the group_type")

    item = ConditionGroupModel(
        name=normalized_name,
        group_type=group_type,
        description=payload.description,
        values=normalize_condition_values(payload.values),
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return ConditionGroupResponse.model_validate(item)


@app.put("/condition-groups/{group_id}", response_model=ConditionGroupResponse)
def update_condition_group(
    group_id: int,
    payload: ConditionGroupUpdate,
    _: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> ConditionGroupResponse:
    item = db.get(ConditionGroupModel, group_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Condition group not found")

    changes = payload.model_dump(exclude_unset=True)
    if "group_type" in changes and changes["group_type"] is not None:
        group_type = str(changes["group_type"]).strip()
        if group_type not in ALLOWED_CONDITION_GROUP_TYPES:
            raise HTTPException(
                status_code=422,
                detail=f"group_type must be one of {sorted(ALLOWED_CONDITION_GROUP_TYPES)}",
            )
        item.group_type = group_type
    if "name" in changes and changes["name"] is not None:
        normalized_name = str(changes["name"]).strip()
        if not normalized_name:
            raise HTTPException(status_code=422, detail="name is required")
        item.name = normalized_name
    if "description" in changes:
        item.description = changes["description"]
    if "values" in changes and changes["values"] is not None:
        item.values = normalize_condition_values(changes["values"])

    duplicate = db.scalar(
        select(ConditionGroupModel).where(
            ConditionGroupModel.id != item.id,
            ConditionGroupModel.name == item.name,
            ConditionGroupModel.group_type == item.group_type,
        )
    )
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="Condition group with this name already exists for the group_type")

    db.commit()
    db.refresh(item)
    return ConditionGroupResponse.model_validate(item)


@app.delete("/condition-groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_condition_group(
    group_id: int,
    _: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> None:
    item = db.get(ConditionGroupModel, group_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Condition group not found")
    db.delete(item)
    db.commit()


@app.get("/auth/providers", response_model=list[AuthProviderResponse])
def list_auth_providers(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=100000),
    _: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> list[AuthProviderResponse]:
    providers = db.scalars(
        select(AuthProviderModel).order_by(AuthProviderModel.priority, AuthProviderModel.id).offset(offset).limit(limit)
    ).all()
    return [to_auth_provider_response(item) for item in providers]


@app.get("/auth/providers/enabled", response_model=list[AuthProviderResponse])
def list_enabled_auth_providers(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=100000),
    db: Session = Depends(get_db),
) -> list[AuthProviderResponse]:
    providers = db.scalars(
        select(AuthProviderModel)
        .where(AuthProviderModel.is_enabled.is_(True))
        .order_by(AuthProviderModel.priority, AuthProviderModel.id)
        .offset(offset)
        .limit(limit)
    ).all()
    return [to_auth_provider_response(item) for item in providers]


@app.post("/auth/providers", response_model=AuthProviderResponse, status_code=status.HTTP_201_CREATED)
def create_auth_provider(
    payload: AuthProviderCreate,
    _: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> AuthProviderResponse:
    name = payload.name.strip()
    existing = db.scalar(select(AuthProviderModel).where(AuthProviderModel.name == name))
    if existing is not None:
        raise HTTPException(status_code=409, detail="Auth provider with this name already exists")

    provider = AuthProviderModel(
        name=name,
        protocol=payload.protocol,
        is_enabled=payload.is_enabled,
        priority=payload.priority,
        settings=payload.settings or {},
    )
    db.add(provider)
    db.commit()
    db.refresh(provider)
    return to_auth_provider_response(provider)


@app.put("/auth/providers/{provider_id}", response_model=AuthProviderResponse)
def update_auth_provider(
    provider_id: int,
    payload: AuthProviderUpdate,
    _: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> AuthProviderResponse:
    provider = db.get(AuthProviderModel, provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="Auth provider not found")
    changes = payload.model_dump(exclude_unset=True)
    if "name" in changes and changes["name"] is not None:
        name = str(changes["name"]).strip()
        if not name:
            raise HTTPException(status_code=422, detail="name is required")
        duplicate = db.scalar(select(AuthProviderModel).where(AuthProviderModel.id != provider_id, AuthProviderModel.name == name))
        if duplicate is not None:
            raise HTTPException(status_code=409, detail="Auth provider with this name already exists")
        provider.name = name
    if "protocol" in changes and changes["protocol"] is not None:
        provider.protocol = changes["protocol"]
    if "is_enabled" in changes and changes["is_enabled"] is not None:
        provider.is_enabled = bool(changes["is_enabled"])
    if "priority" in changes and changes["priority"] is not None:
        provider.priority = int(changes["priority"])
    if "settings" in changes and changes["settings"] is not None:
        current_settings = provider.settings or {}
        incoming = changes["settings"] or {}
        merged = {**current_settings, **incoming}
        for secret_key in ("client_secret", "bind_password", "shared_secret"):
            if secret_key in incoming and str(incoming[secret_key]).strip() == "********":
                merged[secret_key] = current_settings.get(secret_key, "")
        provider.settings = merged
    db.commit()
    db.refresh(provider)
    return to_auth_provider_response(provider)


@app.delete("/auth/providers/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_auth_provider(
    provider_id: int,
    _: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> None:
    provider = db.get(AuthProviderModel, provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="Auth provider not found")
    mapped_users = db.scalars(
        select(UserAccountModel).where(UserAccountModel.external_provider_id == provider_id)
    ).all()
    for user in mapped_users:
        user.external_provider_id = None
    directory_groups = db.scalars(
        select(AuthProviderDirectoryGroupModel).where(AuthProviderDirectoryGroupModel.provider_id == provider_id)
    ).all()
    for group in directory_groups:
        db.delete(group)
    db.delete(provider)
    db.commit()


@app.post("/auth/providers/{provider_id}/test-connectivity", response_model=ProviderConnectivityResult)
def test_auth_provider_connectivity(
    provider_id: int,
    _: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> ProviderConnectivityResult:
    provider = db.get(AuthProviderModel, provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="Auth provider not found")
    return provider_connectivity_check(provider)


@app.post("/auth/providers/{provider_id}/test-credentials", response_model=ProviderConnectivityResult)
def test_auth_provider_credentials(
    provider_id: int,
    payload: ProviderCredentialsTestRequest,
    _: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> ProviderConnectivityResult:
    provider = db.get(AuthProviderModel, provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="Auth provider not found")
    return provider_test_credentials(provider, payload.username.strip(), payload.password)


@app.get("/auth/providers/{provider_id}/directory-groups", response_model=list[DirectoryGroupResponse])
def get_auth_provider_directory_groups(
    provider_id: int,
    computer_only: bool = Query(default=False),
    sync: bool = Query(default=False),
    _: UserAccountModel = Depends(get_session_user),
    db: Session = Depends(get_db),
) -> list[DirectoryGroupResponse]:
    provider = db.get(AuthProviderModel, provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="Auth provider not found")
    if provider.protocol != "ldap":
        return []
    if sync:
        sync_provider_directory_groups(db=db, provider=provider)
        db.commit()
    groups = list_provider_directory_groups(db=db, provider_id=provider.id, computer_only=computer_only)
    return [DirectoryGroupResponse.model_validate(item) for item in groups]


@app.post("/auth/providers/{provider_id}/directory-groups/sync", response_model=list[DirectoryGroupResponse])
def sync_auth_provider_directory_groups(
    provider_id: int,
    _: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> list[DirectoryGroupResponse]:
    provider = db.get(AuthProviderModel, provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="Auth provider not found")
    groups, _ = sync_provider_directory_groups(db=db, provider=provider)
    db.commit()
    return [DirectoryGroupResponse.model_validate(item) for item in groups]


@app.post("/auth/providers/{provider_id}/directory-groups/search", response_model=DirectoryGroupSearchResponse)
def search_auth_provider_directory_groups(
    provider_id: int,
    payload: DirectoryGroupSearchRequest,
    _: UserAccountModel = Depends(get_session_user),
    db: Session = Depends(get_db),
) -> DirectoryGroupSearchResponse:
    provider = db.get(AuthProviderModel, provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="Auth provider not found")
    return search_provider_directory_groups(
        db=db,
        provider=provider,
        payload=payload,
    )


@app.get("/auth/directory-groups/ldap", response_model=list[DirectoryGroupResponse])
def list_ldap_directory_groups(
    computer_only: bool = Query(default=False),
    provider_id: list[int] = Query(default=[]),
    _: UserAccountModel = Depends(get_session_user),
    db: Session = Depends(get_db),
) -> list[DirectoryGroupResponse]:
    providers_query = select(AuthProviderModel).where(
        AuthProviderModel.protocol == "ldap",
        AuthProviderModel.is_enabled.is_(True),
    )
    if provider_id:
        providers_query = providers_query.where(AuthProviderModel.id.in_(provider_id))
    providers = db.scalars(providers_query.order_by(AuthProviderModel.priority, AuthProviderModel.id)).all()
    result: list[DirectoryGroupResponse] = []
    for provider in providers:
        groups = list_provider_directory_groups(db=db, provider_id=provider.id, computer_only=computer_only)
        for item in groups:
            result.append(DirectoryGroupResponse.model_validate(item))
    return result


@app.get("/admin/users", response_model=list[UserAccountResponse])
def list_users(
    limit: int = Query(default=200, ge=1, le=2000),
    offset: int = Query(default=0, ge=0, le=100000),
    _: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> list[UserAccountResponse]:
    users = db.scalars(select(UserAccountModel).order_by(UserAccountModel.username).offset(offset).limit(limit)).all()
    return [to_user_response(user) for user in users]


@app.post("/admin/users", response_model=UserAccountResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserAccountCreate,
    _: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> UserAccountResponse:
    username = payload.username.strip()
    if db.scalar(select(UserAccountModel).where(UserAccountModel.username == username)) is not None:
        raise HTTPException(status_code=409, detail="User with this username already exists")
    if payload.auth_source != "local" and payload.auth_source not in SUPPORTED_AUTH_PROTOCOLS:
        raise HTTPException(status_code=422, detail="Unsupported auth_source")
    if payload.auth_source == "local" and not payload.password:
        raise HTTPException(status_code=422, detail="password is required for local users")
    external_provider_id: int | None = payload.external_provider_id
    if payload.auth_source == "local":
        external_provider_id = None
    else:
        if external_provider_id is None:
            raise HTTPException(status_code=422, detail="external_provider_id is required for external auth users")
        provider = db.get(AuthProviderModel, external_provider_id)
        if provider is None:
            raise HTTPException(status_code=422, detail="Selected auth provider does not exist")
        if provider.protocol != payload.auth_source:
            raise HTTPException(status_code=422, detail="Selected auth provider protocol does not match auth_source")
    user = UserAccountModel(
        username=username,
        full_name=payload.full_name,
        email=payload.email,
        is_active=payload.is_active,
        auth_source=payload.auth_source,
        external_provider_id=external_provider_id,
        local_password_hash=hash_password(payload.password) if payload.password else None,
        external_subject=payload.external_subject,
        external_groups=[item.strip() for item in payload.external_groups if item.strip()],
        roles=[item.strip() for item in payload.roles if item.strip()],
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return to_user_response(user)


@app.put("/admin/users/{user_id}", response_model=UserAccountResponse)
def update_user(
    user_id: int,
    payload: UserAccountUpdate,
    _: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> UserAccountResponse:
    user = db.get(UserAccountModel, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    changes = payload.model_dump(exclude_unset=True)
    if "full_name" in changes:
        user.full_name = changes["full_name"]
    if "email" in changes:
        user.email = changes["email"]
    if "is_active" in changes and changes["is_active"] is not None:
        user.is_active = bool(changes["is_active"])
    if "external_provider_id" in changes:
        provider_id = changes["external_provider_id"]
        if user.auth_source == "local":
            user.external_provider_id = None
        elif provider_id is None:
            raise HTTPException(status_code=422, detail="external_provider_id is required for external auth users")
        else:
            provider = db.get(AuthProviderModel, int(provider_id))
            if provider is None:
                raise HTTPException(status_code=422, detail="Selected auth provider does not exist")
            if provider.protocol != user.auth_source:
                raise HTTPException(status_code=422, detail="Selected auth provider protocol does not match user auth_source")
            user.external_provider_id = int(provider_id)
    if "password" in changes and changes["password"]:
        user.local_password_hash = hash_password(changes["password"])
    if "external_subject" in changes:
        user.external_subject = changes["external_subject"]
    if "external_groups" in changes and changes["external_groups"] is not None:
        user.external_groups = [item.strip() for item in changes["external_groups"] if item.strip()]
    if "roles" in changes and changes["roles"] is not None:
        user.roles = [item.strip() for item in changes["roles"] if item.strip()]
    db.commit()
    db.refresh(user)
    return to_user_response(user)


@app.delete("/admin/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    current_user: UserAccountModel = Depends(require_admin_session),
    db: Session = Depends(get_db),
) -> None:
    user = db.get(UserAccountModel, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.username == current_user.username:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    db.delete(user)
    db.commit()


@app.post("/auth/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    response: Response,
    request: FastAPIRequest,
    db: Session = Depends(get_db),
) -> LoginResponse:
    username = payload.username.strip()
    password = payload.password
    source_ip = request.client.host if request.client else "unknown"
    apply_auth_rate_limit(f"{source_ip}:{username.lower()}")

    local_user = db.scalar(
        select(UserAccountModel).where(
            UserAccountModel.username == username,
            UserAccountModel.is_active.is_(True),
            UserAccountModel.auth_source == "local",
        )
    )
    if local_user is not None and verify_password(password, local_user.local_password_hash):
        token, expires_at = issue_auth_token(local_user)
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=token,
            httponly=True,
            secure=SESSION_COOKIE_SECURE,
            samesite=SESSION_COOKIE_SAMESITE,
            max_age=AUTH_TOKEN_TTL_MINUTES * 60,
            path="/",
        )
        logger.info("security_event=auth.login_success source=local username=%s", local_user.username)
        return LoginResponse(
            expires_at=expires_at,
            user=AuthSessionUser(
                username=local_user.username,
                full_name=local_user.full_name,
                auth_source=local_user.auth_source,
                roles=local_user.roles or [],
            ),
        )

    providers_query = (
        select(AuthProviderModel)
        .where(AuthProviderModel.is_enabled.is_(True))
        .order_by(AuthProviderModel.priority, AuthProviderModel.id)
    )
    providers = db.scalars(providers_query).all()

    for provider in providers:
        credentials = provider_test_credentials(provider, username, password)
        if not credentials.ok:
            continue
        external_user = db.scalar(
            select(UserAccountModel).where(
                UserAccountModel.is_active.is_(True),
                UserAccountModel.auth_source == provider.protocol,
                UserAccountModel.external_provider_id == provider.id,
                (UserAccountModel.external_subject == username) | (UserAccountModel.username == username),
            )
        )
        if external_user is None:
            external_user = db.scalar(
                select(UserAccountModel).where(
                    UserAccountModel.is_active.is_(True),
                    UserAccountModel.auth_source == provider.protocol,
                    UserAccountModel.external_provider_id.is_(None),
                    (UserAccountModel.external_subject == username) | (UserAccountModel.username == username),
                )
            )
        if external_user is None:
            continue
        required_groups = {item.strip().lower() for item in (external_user.external_groups or []) if item.strip()}
        provider_groups = {
            str(item).strip().lower()
            for item in credentials.details.get("groups", [])
            if str(item).strip()
        }
        provider_group_dns = {
            str(item).strip().lower()
            for item in credentials.details.get("group_dns", [])
            if str(item).strip()
        }
        if required_groups and not provider_groups.intersection(required_groups):
            if not provider_group_dns.intersection(required_groups):
                continue

        token, expires_at = issue_auth_token(external_user)
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=token,
            httponly=True,
            secure=SESSION_COOKIE_SECURE,
            samesite=SESSION_COOKIE_SAMESITE,
            max_age=AUTH_TOKEN_TTL_MINUTES * 60,
            path="/",
        )
        logger.info("security_event=auth.login_success source=%s username=%s", provider.protocol, external_user.username)
        return LoginResponse(
            expires_at=expires_at,
            user=AuthSessionUser(
                username=external_user.username,
                full_name=external_user.full_name,
                auth_source=external_user.auth_source,
                roles=external_user.roles or [],
            ),
        )

    logger.warning("security_event=auth.login_failed username=%s", username)
    raise HTTPException(status_code=401, detail="Invalid username/password or provider mapping")


@app.post("/domain-membership/verify", response_model=EndpointDomainVerificationResponse)
def verify_endpoint_domain_membership(
    payload: EndpointDomainVerificationRequest,
    provider_id: int = Query(..., ge=1),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> EndpointDomainVerificationResponse:
    provider = db.scalar(
        select(AuthProviderModel).where(
            AuthProviderModel.id == provider_id,
            AuthProviderModel.protocol == "ldap",
            AuthProviderModel.is_enabled.is_(True),
        )
    )
    if provider is None:
        raise HTTPException(status_code=404, detail="Enabled LDAP provider not found")
    return _verify_endpoint_domain_membership(provider, payload)


@app.get("/auth/me", response_model=AuthSessionUser)
def auth_me(user: UserAccountModel = Depends(get_session_user)) -> AuthSessionUser:
    return AuthSessionUser(
        username=user.username,
        full_name=user.full_name,
        auth_source=user.auth_source,
        roles=user.roles or [],
    )


@app.post("/auth/logout")
def auth_logout(response: Response) -> dict[str, str]:
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    return {"status": "logged_out"}
