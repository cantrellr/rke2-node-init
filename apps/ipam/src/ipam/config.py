from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import os
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_DATA_DIR = REPO_ROOT / "apps" / "ipam" / "data"


@dataclass(frozen=True)
class Settings:
    app_name: str
    data_dir: Path
    upload_dir: Path
    database_url: str
    host: str
    port: int
    secret_key: str


def _sqlite_url(db_path: Path) -> str:
    return f"sqlite:///{db_path.as_posix()}"


@lru_cache(maxsize=1)
def load_settings() -> Settings:
    data_dir = Path(os.environ.get("RKE2_IPAM_DATA_DIR", DEFAULT_DATA_DIR))
    upload_dir = Path(os.environ.get("RKE2_IPAM_UPLOAD_DIR", data_dir / "uploads"))
    db_path = Path(os.environ.get("RKE2_IPAM_DB_PATH", data_dir / "ipam.db"))

    data_dir.mkdir(parents=True, exist_ok=True)
    upload_dir.mkdir(parents=True, exist_ok=True)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    database_url = os.environ.get("RKE2_IPAM_DATABASE_URL", _sqlite_url(db_path))
    return Settings(
        app_name=os.environ.get("RKE2_IPAM_APP_NAME", "RKE2 IPAM"),
        data_dir=data_dir,
        upload_dir=upload_dir,
        database_url=database_url,
        host=os.environ.get("RKE2_IPAM_HOST", "127.0.0.1"),
        port=int(os.environ.get("RKE2_IPAM_PORT", "8091")),
        secret_key=os.environ.get("RKE2_IPAM_SECRET_KEY", "rke2-ipam-dev-key"),
    )
