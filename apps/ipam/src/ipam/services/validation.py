from __future__ import annotations

import hashlib
import ipaddress
from collections import defaultdict

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, selectinload

from ipam.models import IPAssignment, Network, ValidationIssue


def _fingerprint(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()


def rebuild_validation_issues(session: Session) -> int:
    session.execute(delete(ValidationIssue))
    session.flush()

    issues: list[ValidationIssue] = []

    assignments = session.scalars(
        select(IPAssignment).options(selectinload(IPAssignment.site), selectinload(IPAssignment.network))
    ).all()
    duplicate_map: dict[str, list[IPAssignment]] = {}
    for assignment in assignments:
        duplicate_map.setdefault(assignment.ip_address, []).append(assignment)

    for ip_address, dupes in duplicate_map.items():
        if len(dupes) < 2:
            continue
        detail_text = "; ".join(
            " / ".join(
                filter(
                    None,
                    [
                        item.hostname or "unknown-host",
                        item.site.name if item.site else None,
                        item.network.cidr if item.network else None,
                    ],
                )
            )
            for item in dupes
        )
        issues.append(
            ValidationIssue(
                category="duplicate-ip",
                severity="error",
                title=f"Duplicate IP address detected: {ip_address}",
                details=detail_text,
                resource_type="assignment",
                fingerprint=_fingerprint("duplicate-ip", ip_address),
            )
        )

    networks = session.scalars(select(Network).options(selectinload(Network.site))).all()
    parsed_networks: list[tuple[Network, ipaddress._BaseNetwork]] = []
    for network in networks:
        if not network.cidr:
            issues.append(
                ValidationIssue(
                    category="missing-cidr",
                    severity="warning",
                    title=f"Network is missing CIDR: {network.name or 'unnamed network'}",
                    details=network.site.name if network.site else None,
                    resource_type="network",
                    resource_id=network.id,
                    fingerprint=_fingerprint("missing-cidr", str(network.id)),
                )
            )
            continue
        try:
            parsed_networks.append((network, ipaddress.ip_network(network.cidr, strict=False)))
        except ValueError:
            issues.append(
                ValidationIssue(
                    category="invalid-cidr",
                    severity="error",
                    title=f"Invalid CIDR on network: {network.cidr}",
                    details=network.name,
                    resource_type="network",
                    resource_id=network.id,
                    fingerprint=_fingerprint("invalid-cidr", str(network.id), network.cidr),
                )
            )

    duplicate_cidrs: dict[tuple[int | None, str], list[Network]] = defaultdict(list)
    for network, parsed_network in parsed_networks:
        duplicate_cidrs[(network.site_id, str(parsed_network))].append(network)

    for (site_id, cidr), group in duplicate_cidrs.items():
        if len(group) < 2:
            continue
        site_label = group[0].site.name if group[0].site else "unknown site"
        issue_details = "; ".join(filter(None, [item.name or f"network-{item.id}" for item in group]))
        issues.append(
            ValidationIssue(
                category="duplicate-network-cidr",
                severity="warning",
                title=f"Duplicate network CIDR at {site_label}: {cidr}",
                details=issue_details,
                resource_type="network",
                resource_id=group[0].id,
                fingerprint=_fingerprint("duplicate-network-cidr", str(site_id), cidr),
            )
        )

    for assignment in assignments:
        if assignment.network is None or not assignment.network.cidr:
            continue
        try:
            if ipaddress.ip_address(assignment.ip_address) not in ipaddress.ip_network(assignment.network.cidr, strict=False):
                issues.append(
                    ValidationIssue(
                        category="ip-outside-network",
                        severity="error",
                        title=f"IP outside network: {assignment.ip_address}",
                        details=f"Assignment does not fit {assignment.network.cidr}",
                        resource_type="assignment",
                        resource_id=assignment.id,
                        fingerprint=_fingerprint("ip-outside-network", str(assignment.id), assignment.ip_address),
                    )
                )
        except ValueError:
            issues.append(
                ValidationIssue(
                    category="invalid-ip",
                    severity="error",
                    title=f"Invalid IP assignment: {assignment.ip_address}",
                    details=assignment.hostname,
                    resource_type="assignment",
                    resource_id=assignment.id,
                    fingerprint=_fingerprint("invalid-ip", str(assignment.id), assignment.ip_address),
                )
            )

    session.add_all(issues)
    session.flush()
    return len(issues)
