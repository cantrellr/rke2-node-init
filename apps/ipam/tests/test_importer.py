from __future__ import annotations

from pathlib import Path

from openpyxl import Workbook
from sqlalchemy import select

from ipam.database import build_engine, build_session_factory, init_db, session_scope
from ipam.models import IPAssignment, Network, Site
from ipam.services.importer import import_workbook
from ipam.services.validation import rebuild_validation_issues


def build_sample_workbook(path: Path) -> None:
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = "DC1"
    worksheet.append(
        [
            "Site Name",
            "Environment",
            "Network",
            "Subnet Mask",
            "VLAN ID",
            "IP Address",
            "Hostname",
            "Gateway",
            "DNS Servers",
            "Search Domains",
            "Role",
            "Notes",
        ]
    )
    worksheet.append(
        [
            "Preprod",
            "preprod",
            "10.1.1.0",
            "24",
            "100",
            "10.1.1.215",
            "dc1manager-ctrl01",
            "10.1.1.1",
            "4.2.2.2",
            "dev.kube, dev.local",
            "control-plane",
            "Primary control-plane node",
        ]
    )
    worksheet.append(
        [
            None,
            None,
            None,
            None,
            None,
            "10.1.1.218",
            "dc1manager-work01",
            None,
            None,
            None,
            "worker",
            "Worker node",
        ]
    )
    workbook.save(path)


def test_import_workbook_normalizes_rows(tmp_path: Path) -> None:
    workbook_path = tmp_path / "network.xlsx"
    build_sample_workbook(workbook_path)

    database_url = f"sqlite:///{(tmp_path / 'ipam.db').as_posix()}"
    engine = build_engine(database_url)
    session_factory = build_session_factory(engine=engine)
    init_db(engine)

    with session_scope(session_factory) as session:
        summary = import_workbook(session, workbook_path)
        issue_count = rebuild_validation_issues(session)
        assert summary.imported_rows == 2
        assert issue_count == 0

    with session_scope(session_factory) as session:
        assert len(session.scalars(select(Site)).all()) == 1
        assert len(session.scalars(select(Network)).all()) == 1
        assignments = session.scalars(select(IPAssignment).order_by(IPAssignment.ip_address)).all()
        assert len(assignments) == 2
        assert assignments[0].hostname == "dc1manager-ctrl01"
        assert assignments[1].hostname == "dc1manager-work01"
        assert assignments[0].network is not None
        assert assignments[0].network.cidr == "10.1.1.0/24"
