from __future__ import annotations

import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import AuditEventModel, IpGroupMemberModel, IpObjectModel
from app.object_store import add_object_to_group, ensure_ip_group, ensure_ip_object
from app import main
from posture_shared.models.evaluation import ComplianceDecision


class ManualObjectApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine, autoflush=False, autocommit=False, future=True)

        def override_get_db():
            db = self.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        main.app.dependency_overrides[main.get_db] = override_get_db
        self._original_warning = main.build_policy_managed_warning
        main.build_policy_managed_warning = lambda _group: None
        self.client = TestClient(main.app)

    def tearDown(self) -> None:
        main.app.dependency_overrides.clear()
        main.build_policy_managed_warning = self._original_warning
        self.engine.dispose()

    def _seed_member(self) -> tuple[str, str]:
        with self.SessionLocal() as db:
            assert isinstance(db, Session)
            group = ensure_ip_group(db, "TEST_GROUP")
            ip_object = ensure_ip_object(
                db=db,
                name="manual-host",
                object_type="host",
                value="192.168.10.10",
                managed_by="manual",
            )
            add_object_to_group(db=db, group=group, ip_object=ip_object)
            db.commit()
            return group.group_id, ip_object.object_id

    def test_delete_group_member_removes_existing_membership(self) -> None:
        group_id, object_id = self._seed_member()

        response = self.client.delete(f"/objects/ip-groups/{group_id}/members/{object_id}")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["operation"], "removed")
        with self.SessionLocal() as db:
            self.assertEqual(len(db.scalars(select(IpGroupMemberModel)).all()), 0)
            event = db.scalar(select(AuditEventModel).where(AuditEventModel.event_type == "object.group_member.manual_remove"))
            self.assertIsNotNone(event)

    def test_delete_group_member_twice_returns_already_absent(self) -> None:
        group_id, object_id = self._seed_member()

        self.client.delete(f"/objects/ip-groups/{group_id}/members/{object_id}")
        response = self.client.delete(f"/objects/ip-groups/{group_id}/members/{object_id}")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["operation"], "already_absent")

    def test_delete_group_member_unknown_group_returns_404(self) -> None:
        _, object_id = self._seed_member()

        response = self.client.delete(f"/objects/ip-groups/missing-group/members/{object_id}")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "IP group not found")

    def test_delete_group_member_unknown_object_returns_404(self) -> None:
        group_id, _ = self._seed_member()

        response = self.client.delete(f"/objects/ip-groups/{group_id}/members/missing-object")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "IP object not found")

    def test_delete_object_without_memberships_succeeds(self) -> None:
        with self.SessionLocal() as db:
            ip_object = ensure_ip_object(
                db=db,
                name="standalone",
                object_type="host",
                value="192.168.10.11",
                managed_by="manual",
            )
            db.commit()
            object_id = ip_object.object_id

        response = self.client.delete(f"/objects/ip-objects/{object_id}")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["operation"], "deleted")
        with self.SessionLocal() as db:
            self.assertIsNone(db.scalar(select(IpObjectModel).where(IpObjectModel.object_id == object_id)))

    def test_delete_object_with_memberships_requires_force(self) -> None:
        _, object_id = self._seed_member()

        response = self.client.delete(f"/objects/ip-objects/{object_id}")

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["detail"], "Object is still a member of groups")

    def test_delete_object_with_force_removes_memberships_and_audits(self) -> None:
        _, object_id = self._seed_member()

        response = self.client.delete(f"/objects/ip-objects/{object_id}?force=true")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["operation"], "deleted")
        self.assertEqual(len(payload["removed_memberships"]), 1)
        with self.SessionLocal() as db:
            self.assertEqual(len(db.scalars(select(IpGroupMemberModel)).all()), 0)
            self.assertIsNone(db.scalar(select(IpObjectModel).where(IpObjectModel.object_id == object_id)))
            event = db.scalar(select(AuditEventModel).where(AuditEventModel.event_type == "object.manual_delete"))
            self.assertIsNotNone(event)

    def test_policy_reconciliation_removes_non_compliant_group_after_compliance(self) -> None:
        with self.SessionLocal() as db:
            group = ensure_ip_group(db, "NON_COMPLIANT_ENDPOINTS")
            db.commit()
            plan = {
                "trigger_type": "telemetry_received",
                "object_group": group.name,
                "managed_groups": [{"group_id": group.group_id, "group_name": group.name}],
                "on_non_compliant": [
                    {
                        "action_type": "object.add_ip_to_group",
                        "enabled": True,
                        "parameters": {"group_id": group.group_id, "group_name": group.name},
                    }
                ],
                "on_compliant": [],
                "actions": [],
            }

            non_compliant = ComplianceDecision(
                endpoint_id="endpoint-1",
                endpoint_ip="10.10.10.1",
                policy_id=1,
                policy_name="Antivirus policy",
                trigger_type="telemetry_received",
                compliant=False,
                reasons=[],
                execution_plan=plan,
            )
            add_results = main.execute_policy_plan(non_compliant, db)
            self.assertIn("added", [item.get("operation") for item in add_results])
            self.assertEqual(len(db.scalars(select(IpGroupMemberModel)).all()), 1)

            compliant = non_compliant.model_copy(update={"compliant": True})
            remove_results = main.execute_policy_plan(compliant, db)
            self.assertIn("removed", [item.get("operation") for item in remove_results])
            self.assertEqual(len(db.scalars(select(IpGroupMemberModel)).all()), 0)
            event = db.scalar(select(AuditEventModel).where(AuditEventModel.event_type == "policy.group_reconcile.removed"))
            self.assertIsNotNone(event)


if __name__ == "__main__":
    unittest.main()
