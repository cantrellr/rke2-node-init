from __future__ import annotations

from io import BytesIO
from pathlib import Path

from fastapi.testclient import TestClient
from openpyxl import Workbook

from ipam.config import Settings
from ipam.main import create_app


def workbook_bytes() -> bytes:
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = "COTPA"
    worksheet.append(["Site Name", "Network", "Subnet Mask", "IP Address", "Hostname", "Role"])
    worksheet.append(["COTPA", "172.16.15.0", "24", "172.16.15.101", "cotpa-ctrl01", "control-plane"])

    output = BytesIO()
    workbook.save(output)
    return output.getvalue()


def test_upload_route_imports_workbook(tmp_path: Path) -> None:
    settings = Settings(
        app_name="Test IPAM",
        data_dir=tmp_path / "data",
        upload_dir=tmp_path / "data" / "uploads",
        database_url=f"sqlite:///{(tmp_path / 'data' / 'ipam.db').as_posix()}",
        host="127.0.0.1",
        port=8091,
        secret_key="test-key",
    )
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)

    client = TestClient(create_app(settings=settings))
    response = client.post(
        "/imports/upload",
        files={"workbook": ("sample.xlsx", workbook_bytes(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Imported 1 rows from sample.xlsx" in response.text
    assignments = client.get("/assignments")
    assert assignments.status_code == 200
    assert "172.16.15.101" in assignments.text
