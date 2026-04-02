from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import Base, engine, get_db
from app.models import ConditionGroupModel, Policy, PolicyAssignmentModel
from app.schemas import (
    AssignmentCreate,
    AssignmentResponse,
    ConditionGroupCreate,
    ConditionGroupResponse,
    ConditionGroupUpdate,
    PolicyCreate,
    PolicyResponse,
    PolicyUpdate,
)
Base.metadata.create_all(bind=engine)

ALLOWED_CONDITION_GROUP_TYPES = {"allowed_os", "allowed_patches", "allowed_antivirus_families"}
DEFAULT_CONDITION_GROUPS: list[tuple[str, str, str]] = [
    ("Allowed OS", "allowed_os", "Baseline allow-list for operating system names"),
    ("Allowed Patches", "allowed_patches", "Baseline allow-list for Windows KB patch identifiers"),
    ("Allowed Antivirus Families", "allowed_antivirus_families", "Baseline allow-list for antivirus family names"),
]


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
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def normalize_condition_values(values: list[str]) -> list[str]:
    return [item.strip() for item in values if item and item.strip()]


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


@app.get("/healthz")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/policies", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
def create_policy(payload: PolicyCreate, db: Session = Depends(get_db)) -> PolicyResponse:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="name is required")

    duplicate = db.scalar(select(Policy).where(Policy.name == name))
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="Policy with this name already exists")

    policy = Policy(
        name=name,
        description=payload.description,
        policy_scope=payload.policy_scope,
        lifecycle_event_type=payload.lifecycle_event_type,
        target_action=payload.target_action,
        is_active=payload.is_active,
        conditions=[item.model_dump(mode="json") for item in payload.conditions],
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
def list_policies(db: Session = Depends(get_db)) -> list[PolicyResponse]:
    policies = db.scalars(select(Policy).order_by(Policy.id)).all()
    return [to_policy_response(policy, db=db) for policy in policies]


@app.get("/policies/{policy_id}", response_model=PolicyResponse)
def get_policy(policy_id: int, db: Session = Depends(get_db)) -> PolicyResponse:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return to_policy_response(policy, db=db)


@app.put("/policies/{policy_id}", response_model=PolicyResponse)
def update_policy(policy_id: int, payload: PolicyUpdate, db: Session = Depends(get_db)) -> PolicyResponse:
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
        changes["conditions"] = [item.model_dump(mode="json") for item in payload.conditions or []]
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
def delete_policy(policy_id: int, db: Session = Depends(get_db)) -> None:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    db.delete(policy)
    db.commit()


@app.post("/policies/{policy_id}/assignments", response_model=AssignmentResponse, status_code=status.HTTP_201_CREATED)
def create_assignment(
    policy_id: int,
    payload: AssignmentCreate,
    db: Session = Depends(get_db),
) -> AssignmentResponse:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")

    assignment = PolicyAssignmentModel(
        policy_id=policy_id,
        assignment_type=payload.assignment_type,
        assignment_value=payload.assignment_value,
    )
    db.add(assignment)
    db.commit()
    db.refresh(assignment)
    return AssignmentResponse.model_validate(assignment)


@app.get("/policies/{policy_id}/assignments", response_model=list[AssignmentResponse])
def list_assignments(policy_id: int, db: Session = Depends(get_db)) -> list[AssignmentResponse]:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return [AssignmentResponse.model_validate(item) for item in policy.assignments]


@app.get("/policy-match/{endpoint_id}", response_model=PolicyResponse | None)
def resolve_policy(
    endpoint_id: str,
    groups: list[str] = Query(default=[]),
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


@app.get("/lifecycle-policy-match/{event_type}/{endpoint_id}", response_model=PolicyResponse | None)
def resolve_lifecycle_policy(
    event_type: str,
    endpoint_id: str,
    groups: list[str] = Query(default=[]),
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
    db: Session = Depends(get_db),
) -> list[ConditionGroupResponse]:
    query = select(ConditionGroupModel).order_by(ConditionGroupModel.group_type, ConditionGroupModel.name)
    if group_type is not None:
        query = query.where(ConditionGroupModel.group_type == group_type)
    groups = db.scalars(query).all()
    return [ConditionGroupResponse.model_validate(item) for item in groups]


@app.post("/condition-groups", response_model=ConditionGroupResponse, status_code=status.HTTP_201_CREATED)
def create_condition_group(payload: ConditionGroupCreate, db: Session = Depends(get_db)) -> ConditionGroupResponse:
    group_type = payload.group_type.strip()
    if group_type not in ALLOWED_CONDITION_GROUP_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"group_type must be one of {sorted(ALLOWED_CONDITION_GROUP_TYPES)}",
        )

    exists = db.scalar(
        select(ConditionGroupModel).where(
            ConditionGroupModel.name == payload.name.strip(),
            ConditionGroupModel.group_type == group_type,
        )
    )
    if exists is not None:
        raise HTTPException(status_code=409, detail="Condition group with this name already exists for the group_type")

    item = ConditionGroupModel(
        name=payload.name.strip(),
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
        item.name = str(changes["name"]).strip()
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
def delete_condition_group(group_id: int, db: Session = Depends(get_db)) -> None:
    item = db.get(ConditionGroupModel, group_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Condition group not found")
    db.delete(item)
    db.commit()
