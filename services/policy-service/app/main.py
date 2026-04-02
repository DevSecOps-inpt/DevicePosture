import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import time
import threading
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
from app.models import AuthProviderModel, ConditionGroupModel, Policy, PolicyAssignmentModel, UserAccountModel
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
    EndpointAssignedPolicyResponse,
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


def ensure_policy_indexes() -> None:
    statements = [
        "CREATE INDEX IF NOT EXISTS idx_policy_assignments_lookup ON policy_assignments(assignment_type, assignment_value, id DESC)",
        "CREATE INDEX IF NOT EXISTS idx_policies_scope_active ON policies(policy_scope, is_active, lifecycle_event_type)",
        "CREATE INDEX IF NOT EXISTS idx_condition_groups_type_name ON condition_groups(group_type, name)",
        "CREATE INDEX IF NOT EXISTS idx_auth_providers_enabled_priority ON auth_providers(is_enabled, priority, id)",
        "CREATE INDEX IF NOT EXISTS idx_user_accounts_source_subject ON user_accounts(auth_source, external_subject, is_active)",
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

    enriched_value = dict(value)
    enriched_value["provider_id"] = provider.id
    enriched_value["provider_name"] = provider.name
    enriched_value["provider_priority"] = provider.priority
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


def resolve_assigned_policy(
    *,
    db: Session,
    endpoint_id: str,
    groups: list[str],
    scope: str,
    lifecycle_event_type: str | None = None,
) -> Policy | None:
    endpoint_assignments = db.scalars(
        select(PolicyAssignmentModel)
        .where(
            PolicyAssignmentModel.assignment_type == "endpoint",
            PolicyAssignmentModel.assignment_value == endpoint_id,
        )
        .order_by(PolicyAssignmentModel.id.desc())
    ).all()
    for assignment in endpoint_assignments:
        policy = db.get(Policy, assignment.policy_id)
        if policy and policy.is_active and policy.policy_scope == scope:
            if scope != "lifecycle" or policy.lifecycle_event_type == lifecycle_event_type:
                return policy

    if groups:
        group_assignments = db.scalars(
            select(PolicyAssignmentModel)
            .where(
                PolicyAssignmentModel.assignment_type == "group",
                PolicyAssignmentModel.assignment_value.in_(groups),
            )
            .order_by(PolicyAssignmentModel.id.desc())
        ).all()
        for assignment in group_assignments:
            policy = db.get(Policy, assignment.policy_id)
            if policy and policy.is_active and policy.policy_scope == scope:
                if scope != "lifecycle" or policy.lifecycle_event_type == lifecycle_event_type:
                    return policy

    default_assignments = db.scalars(
        select(PolicyAssignmentModel)
        .where(PolicyAssignmentModel.assignment_type == "default")
        .order_by(PolicyAssignmentModel.id.desc())
    ).all()
    for assignment in default_assignments:
        policy = db.get(Policy, assignment.policy_id)
        if policy and policy.is_active and policy.policy_scope == scope:
            if scope != "lifecycle" or policy.lifecycle_event_type == lifecycle_event_type:
                return policy

    return None


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

    if "conditions" in changes:
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
    return [AssignmentResponse.model_validate(item) for item in policy.assignments]


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
    for assignment in assignments:
        policy = db.get(Policy, assignment.policy_id)
        if policy is None:
            continue
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
    for assignment in assignments:
        policy = policy_by_id.get(assignment.policy_id)
        if policy is None:
            continue
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
    if event_type not in {"telemetry_received", "inactive_to_active", "active_to_inactive", "first_seen", "repeat_seen"}:
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
    user = UserAccountModel(
        username=username,
        full_name=payload.full_name,
        email=payload.email,
        is_active=payload.is_active,
        auth_source=payload.auth_source,
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
        if required_groups and not provider_groups.intersection(required_groups):
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
