from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import IpGroupMemberModel, IpGroupModel, IpObjectModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_name(value: str) -> str:
    return value.strip()


def ensure_ip_object(
    *,
    db: Session,
    name: str,
    object_type: str,
    value: str,
    description: str | None = None,
    managed_by: str = "manual",
) -> IpObjectModel:
    normalized_value = value.strip()
    existing = db.scalar(
        select(IpObjectModel).where(
            IpObjectModel.object_type == object_type,
            IpObjectModel.value == normalized_value,
        )
    )
    if existing is not None:
        return existing

    obj = IpObjectModel(
        object_id=f"ipobj-{uuid4().hex[:10]}",
        name=_normalize_name(name),
        object_type=object_type,
        value=normalized_value,
        description=description,
        managed_by=managed_by,
    )
    existing_name = db.scalar(select(IpObjectModel).where(IpObjectModel.name == obj.name))
    if existing_name is not None:
        obj.name = f"{obj.name}-{uuid4().hex[:6]}"
    db.add(obj)
    db.flush()
    return obj


def ensure_ip_group(db: Session, name: str, description: str | None = None) -> IpGroupModel:
    normalized_name = _normalize_name(name)
    group = db.scalar(select(IpGroupModel).where(IpGroupModel.name == normalized_name))
    if group is not None:
        return group

    group = IpGroupModel(
        group_id=f"ipgrp-{uuid4().hex[:10]}",
        name=normalized_name,
        description=description,
    )
    db.add(group)
    db.flush()
    return group


def add_object_to_group(*, db: Session, group: IpGroupModel, ip_object: IpObjectModel) -> bool:
    existing_member = db.scalar(
        select(IpGroupMemberModel).where(
            IpGroupMemberModel.group_ref == group.id,
            IpGroupMemberModel.object_ref == ip_object.id,
        )
    )
    if existing_member is not None:
        return False

    member = IpGroupMemberModel(group_ref=group.id, object_ref=ip_object.id)
    db.add(member)
    group.updated_at = _utcnow()
    db.flush()
    return True


def remove_object_from_group(*, db: Session, group: IpGroupModel, ip_object: IpObjectModel) -> bool:
    existing_member = db.scalar(
        select(IpGroupMemberModel).where(
            IpGroupMemberModel.group_ref == group.id,
            IpGroupMemberModel.object_ref == ip_object.id,
        )
    )
    if existing_member is None:
        return False

    db.delete(existing_member)
    group.updated_at = _utcnow()
    db.flush()
    return True


def find_object_by_id(db: Session, object_id: str) -> IpObjectModel | None:
    return db.scalar(select(IpObjectModel).where(IpObjectModel.object_id == object_id))


def find_group_by_name(db: Session, group_name: str) -> IpGroupModel | None:
    return db.scalar(select(IpGroupModel).where(IpGroupModel.name == group_name))


def find_ip_host_object(db: Session, ip_address: str) -> IpObjectModel | None:
    return db.scalar(
        select(IpObjectModel).where(
            IpObjectModel.object_type == "host",
            IpObjectModel.value == ip_address.strip(),
        )
    )


def list_group_host_ips(db: Session, group: IpGroupModel) -> list[str]:
    members = db.scalars(select(IpGroupMemberModel).where(IpGroupMemberModel.group_ref == group.id)).all()
    ips: list[str] = []
    for member in members:
        if member.ip_object.object_type == "host":
            ips.append(member.ip_object.value)
    return sorted(set(ips))
