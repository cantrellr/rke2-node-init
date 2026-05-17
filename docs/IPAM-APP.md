# Internal IPAM App

**Last Updated:** May 17, 2026

## Overview

The repository now includes an internal IP and site tracking application under `apps/ipam/`.

The app is intended to solve a narrow operational problem that sits next to, but outside of, the core `rke2nodeinit.sh` provisioning workflow:

- ingest spreadsheet-based IP assignment inventories
- normalize sites, networks, and individual IP assignments into a searchable database
- flag duplicate IPs and conflicting CIDR definitions
- provide a shared browser-based dashboard for edits and exports
- expose normalized address payloads that can later feed `rkeprep/v2` node manifests

This first implementation does **not** directly generate or rewrite YAML under `configs/*/nodes/`, and it does **not** change the current boot ISO workflow.

## Location

- Application code: `apps/ipam/`
- Python package root: `apps/ipam/src/ipam/`
- Tests: `apps/ipam/tests/`
- Default SQLite database: `apps/ipam/data/ipam.db`

## Current Capabilities

- Upload an Excel workbook from the browser
- Auto-detect likely header rows and common field aliases
- Normalize data into sites, networks, and IP assignments
- Fill down repeated spreadsheet context for site and subnet metadata
- Search and filter assignments by text, site, and status
- Create and edit sites, networks, and assignments from the UI
- Export current data as CSV or Excel
- Surface validation issues for duplicate IPs, invalid CIDRs, duplicate network CIDRs, and IPs outside their network
- Expose a read-only JSON payload at `/api/node-payloads` for future RKE2 manifest integration

## Run Locally

Install the app dependencies:

```bash
make ipam-install
```

Run the server:

```bash
make ipam-run
```

Then browse to `http://127.0.0.1:8091`.

## Import Workflow

Option 1: use the web UI.

1. Open `/imports`
2. Upload the workbook
3. Review import history and current validation issues

Option 2: import from the CLI.

```bash
make ipam-import WORKBOOK=/absolute/path/to/workbook.xlsx
```

## Data Model

The application stores four operational entities and one validation entity:

- `Site`: logical location, environment, and site metadata
- `Network`: subnet/VLAN data such as CIDR, gateway, DNS, and search domains
- `IPAssignment`: individual IP records, hostnames, interfaces, roles, and notes
- `ImportBatch`: workbook import history and per-run metadata
- `ValidationIssue`: persisted duplicate, overlap, and malformed-data findings

## Boundary With Provisioning

The current downstream RKE2 contract still lives in the existing node manifest files, for example:

- `spec.nodeIp`
- `spec.bindAddress`
- `spec.advertiseAddress`
- `spec.interfaces[].ip`
- `spec.interfaces[].gateway`
- `spec.interfaces[].dns`
- `spec.interfaces[].searchDomains`

The app’s `/api/node-payloads` endpoint is the initial seam for future automation. A later phase can translate or map selected records into YAML that the existing boot ISO workflow already expects.

## Validation

Run the application tests with:

```bash
make ipam-test
```

## Operational Notes

- The importer is intentionally heuristic-driven because workbook structures may change over time.
- Re-importing the same workbook filename replaces previously imported rows from that filename, but does not remove manual CRUD records.
- SQLite is the default storage backend for simplicity. If concurrency or operational needs grow, the SQLAlchemy layer is intentionally narrow enough to migrate later.
