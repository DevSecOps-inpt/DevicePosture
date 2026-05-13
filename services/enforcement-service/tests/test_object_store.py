from __future__ import annotations

import unittest

from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.db import Base
from app.models import IpGroupMemberModel
from app.object_store import add_object_to_group, ensure_ip_group, ensure_ip_object, remove_object_from_group


class ObjectStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine("sqlite:///:memory:", future=True)
        Base.metadata.create_all(self.engine)
        with self.engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE UNIQUE INDEX ux_test_ip_group_members_group_object "
                    "ON ip_group_members(group_ref, object_ref)"
                )
            )
        self.SessionLocal = sessionmaker(bind=self.engine, future=True)

    def test_group_membership_add_and_remove_are_idempotent(self) -> None:
        with self.SessionLocal() as db:
            assert isinstance(db, Session)
            group = ensure_ip_group(db, "NON_COMPLIANT_ENDPOINTS")
            ip_object = ensure_ip_object(
                db=db,
                name="endpoint-1",
                object_type="host",
                value="10.10.10.1",
                managed_by="policy",
            )

            self.assertTrue(add_object_to_group(db=db, group=group, ip_object=ip_object))
            self.assertFalse(add_object_to_group(db=db, group=group, ip_object=ip_object))
            self.assertEqual(db.scalar(select(func.count()).select_from(IpGroupMemberModel)), 1)

            self.assertTrue(remove_object_from_group(db=db, group=group, ip_object=ip_object))
            self.assertFalse(remove_object_from_group(db=db, group=group, ip_object=ip_object))
            self.assertEqual(db.scalar(select(func.count()).select_from(IpGroupMemberModel)), 0)


if __name__ == "__main__":
    unittest.main()
