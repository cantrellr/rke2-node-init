from __future__ import annotations

import datetime as dt

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ipam.database import Base


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class TimestampMixin:
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Site(TimestampMixin, Base):
    __tablename__ = "sites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    location: Mapped[str | None] = mapped_column(String(200), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(100), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    networks: Mapped[list[Network]] = relationship(back_populates="site", cascade="all, delete-orphan")
    assignments: Mapped[list[IPAssignment]] = relationship(back_populates="site")


class ImportBatch(Base):
    __tablename__ = "import_batches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    filename: Mapped[str] = mapped_column(String(255), index=True)
    original_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    sheet_names: Mapped[list[str]] = mapped_column(JSON, default=list)
    total_rows: Mapped[int] = mapped_column(Integer, default=0)
    imported_rows: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[dict] = mapped_column(JSON, default=dict)
    imported_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    networks: Mapped[list[Network]] = relationship(back_populates="source_batch")
    assignments: Mapped[list[IPAssignment]] = relationship(back_populates="source_batch")


class Network(TimestampMixin, Base):
    __tablename__ = "networks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True)
    source_batch_id: Mapped[int | None] = mapped_column(ForeignKey("import_batches.id", ondelete="SET NULL"), nullable=True)
    source_file: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    source_sheet: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_row: Mapped[int | None] = mapped_column(Integer, nullable=True)
    name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    cidr: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    vlan_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    gateway: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dns_servers: Mapped[list[str]] = mapped_column(JSON, default=list)
    search_domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_payload: Mapped[dict] = mapped_column(JSON, default=dict)

    site: Mapped[Site | None] = relationship(back_populates="networks")
    assignments: Mapped[list[IPAssignment]] = relationship(back_populates="network")
    source_batch: Mapped[ImportBatch | None] = relationship(back_populates="networks")


class IPAssignment(TimestampMixin, Base):
    __tablename__ = "ip_assignments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True)
    network_id: Mapped[int | None] = mapped_column(ForeignKey("networks.id", ondelete="SET NULL"), nullable=True, index=True)
    source_batch_id: Mapped[int | None] = mapped_column(ForeignKey("import_batches.id", ondelete="SET NULL"), nullable=True)
    source_file: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    source_sheet: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_row: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ip_address: Mapped[str] = mapped_column(String(64), index=True)
    hostname: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    interface_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    role: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(64), default="assigned", index=True)
    gateway: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dns_servers: Mapped[list[str]] = mapped_column(JSON, default=list)
    search_domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_payload: Mapped[dict] = mapped_column(JSON, default=dict)

    site: Mapped[Site | None] = relationship(back_populates="assignments")
    network: Mapped[Network | None] = relationship(back_populates="assignments")
    source_batch: Mapped[ImportBatch | None] = relationship(back_populates="assignments")


class ValidationIssue(Base):
    __tablename__ = "validation_issues"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    category: Mapped[str] = mapped_column(String(100), index=True)
    severity: Mapped[str] = mapped_column(String(32), default="warning", index=True)
    title: Mapped[str] = mapped_column(String(255))
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
