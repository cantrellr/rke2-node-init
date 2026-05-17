from __future__ import annotations

from pathlib import Path

from sqlalchemy import select

from ipam.database import build_engine, build_session_factory, init_db, session_scope
from ipam.models import IPAssignment, Site, ValidationIssue
from ipam.services.validation import rebuild_validation_issues


def test_duplicate_ip_validation_issue(tmp_path: Path) -> None:
    database_url = f"sqlite:///{(tmp_path / 'ipam.db').as_posix()}"
    engine = build_engine(database_url)
    session_factory = build_session_factory(engine=engine)
    init_db(engine)

    with session_scope(session_factory) as session:
        site = Site(name="COTPA")
        session.add(site)
        session.flush()
        session.add_all(
            [
                IPAssignment(site_id=site.id, ip_address="172.16.15.101", hostname="cotpa-ctrl01", status="assigned"),
                IPAssignment(site_id=site.id, ip_address="172.16.15.101", hostname="cotpa-k801", status="assigned"),
            ]
        )
        issue_count = rebuild_validation_issues(session)
        assert issue_count == 1

    with session_scope(session_factory) as session:
        issues = session.scalars(select(ValidationIssue)).all()
        assert len(issues) == 1
        assert issues[0].category == "duplicate-ip"
        assert "172.16.15.101" in issues[0].title
