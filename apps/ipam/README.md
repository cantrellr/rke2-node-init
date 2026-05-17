# RKE2 IPAM App

This directory contains the internal IP and site tracking web application for `rke2-node-init`.

## Stack

- FastAPI for the web application
- Jinja2 templates for the UI
- SQLAlchemy with SQLite for persistence
- OpenPyXL for Excel import and export

## Quick Start

```bash
python -m pip install -e ./apps/ipam[dev]
PYTHONPATH=apps/ipam/src python -m uvicorn ipam.main:app --host 127.0.0.1 --port 8091 --reload
```

## CLI Usage

Initialize the database:

```bash
PYTHONPATH=apps/ipam/src python -m ipam.cli init-db
```

Import a workbook:

```bash
PYTHONPATH=apps/ipam/src python -m ipam.cli import-workbook /absolute/path/to/workbook.xlsx
```

## Tests

```bash
PYTHONPATH=apps/ipam/src python -m pytest apps/ipam/tests
```
