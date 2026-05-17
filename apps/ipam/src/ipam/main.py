from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload
from starlette.middleware.sessions import SessionMiddleware

from ipam.config import Settings, load_settings
from ipam.database import build_engine, build_session_factory, init_db
from ipam.models import IPAssignment, ImportBatch, Network, Site, ValidationIssue
from ipam.services.exporter import export_assignments_csv, export_workbook
from ipam.services.importer import import_workbook, split_multi_value
from ipam.services.validation import rebuild_validation_issues


PACKAGE_ROOT = Path(__file__).resolve().parent
TEMPLATE_ROOT = PACKAGE_ROOT / "templates"
STATIC_ROOT = PACKAGE_ROOT / "static"


def flash(request: Request, message: str, level: str = "info") -> None:
    flashes = request.session.setdefault("flashes", [])
    flashes.append({"message": message, "level": level})
    request.session["flashes"] = flashes


def pop_flashes(request: Request) -> list[dict[str, str]]:
    flashes = request.session.pop("flashes", [])
    return flashes


def render(request: Request, template_name: str, context: dict, status_code: int = 200) -> HTMLResponse:
    full_context = {
        "request": request,
        "app_name": request.app.state.settings.app_name,
        "flashes": pop_flashes(request),
    }
    full_context.update(context)
    return request.app.state.templates.TemplateResponse(
        request=request,
        name=template_name,
        context=full_context,
        status_code=status_code,
    )


def get_session(request: Request) -> Session:
    return request.app.state.session_factory()


def parse_text_list(value: str | None) -> list[str]:
    return split_multi_value(value)


def parse_site_form(form_data) -> dict:
    return {
        "name": form_data.get("name", "").strip(),
        "code": form_data.get("code", "").strip() or None,
        "location": form_data.get("location", "").strip() or None,
        "environment": form_data.get("environment", "").strip() or None,
        "notes": form_data.get("notes", "").strip() or None,
    }


def parse_network_form(form_data) -> dict:
    site_id = form_data.get("site_id")
    return {
        "site_id": int(site_id) if site_id else None,
        "name": form_data.get("name", "").strip() or None,
        "cidr": form_data.get("cidr", "").strip() or None,
        "vlan_id": form_data.get("vlan_id", "").strip() or None,
        "gateway": form_data.get("gateway", "").strip() or None,
        "dns_servers": parse_text_list(form_data.get("dns_servers", "")),
        "search_domains": parse_text_list(form_data.get("search_domains", "")),
        "notes": form_data.get("notes", "").strip() or None,
    }


def parse_assignment_form(form_data) -> dict:
    site_id = form_data.get("site_id")
    network_id = form_data.get("network_id")
    return {
        "site_id": int(site_id) if site_id else None,
        "network_id": int(network_id) if network_id else None,
        "ip_address": form_data.get("ip_address", "").strip(),
        "hostname": form_data.get("hostname", "").strip() or None,
        "interface_name": form_data.get("interface_name", "").strip() or None,
        "role": form_data.get("role", "").strip() or None,
        "status": (form_data.get("status", "assigned") or "assigned").strip().lower(),
        "gateway": form_data.get("gateway", "").strip() or None,
        "dns_servers": parse_text_list(form_data.get("dns_servers", "")),
        "search_domains": parse_text_list(form_data.get("search_domains", "")),
        "description": form_data.get("description", "").strip() or None,
    }


def build_dashboard(session: Session) -> dict:
    total_sites = session.scalar(select(func.count()).select_from(Site)) or 0
    total_networks = session.scalar(select(func.count()).select_from(Network)) or 0
    total_assignments = session.scalar(select(func.count()).select_from(IPAssignment)) or 0
    total_issues = session.scalar(select(func.count()).select_from(ValidationIssue)) or 0

    recent_issues = session.scalars(select(ValidationIssue).order_by(ValidationIssue.created_at.desc()).limit(8)).all()
    recent_imports = session.scalars(select(ImportBatch).order_by(ImportBatch.imported_at.desc()).limit(5)).all()
    site_summary = session.execute(
        select(Site.name, func.count(IPAssignment.id))
        .select_from(Site)
        .join(IPAssignment, IPAssignment.site_id == Site.id, isouter=True)
        .group_by(Site.id)
        .order_by(func.count(IPAssignment.id).desc(), Site.name.asc())
        .limit(10)
    ).all()

    return {
        "stats": {
            "sites": total_sites,
            "networks": total_networks,
            "assignments": total_assignments,
            "issues": total_issues,
        },
        "recent_issues": recent_issues,
        "recent_imports": recent_imports,
        "site_summary": site_summary,
    }


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or load_settings()
    app = FastAPI(title=app_settings.app_name)
    app.add_middleware(SessionMiddleware, secret_key=app_settings.secret_key)
    app.mount("/static", StaticFiles(directory=STATIC_ROOT), name="static")
    app.state.settings = app_settings
    app.state.templates = Jinja2Templates(directory=str(TEMPLATE_ROOT))
    app.state.engine = build_engine(app_settings.database_url)
    app.state.session_factory = build_session_factory(engine=app.state.engine)
    init_db(app.state.engine)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        session = get_session(request)
        try:
            context = build_dashboard(session)
            return render(request, "dashboard.html", context)
        finally:
            session.close()

    @app.get("/imports", response_class=HTMLResponse)
    def imports_page(request: Request):
        session = get_session(request)
        try:
            imports = session.scalars(select(ImportBatch).order_by(ImportBatch.imported_at.desc())).all()
            issues = session.scalars(select(ValidationIssue).order_by(ValidationIssue.created_at.desc()).limit(12)).all()
            return render(request, "imports.html", {"imports": imports, "issues": issues})
        finally:
            session.close()

    @app.post("/imports/upload")
    async def upload_import(request: Request, workbook: UploadFile = File(...)):
        if not workbook.filename:
            flash(request, "Select an Excel workbook to import.", "error")
            return RedirectResponse("/imports", status_code=303)

        session = get_session(request)
        tmp_file = None
        try:
            suffix = Path(workbook.filename).suffix or ".xlsx"
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as handle:
                tmp_file = Path(handle.name)
                shutil.copyfileobj(workbook.file, handle)

            target_path = request.app.state.settings.upload_dir / workbook.filename
            shutil.copy2(tmp_file, target_path)

            summary = import_workbook(session, target_path)
            issue_count = rebuild_validation_issues(session)
            session.commit()
            flash(
                request,
                f"Imported {summary.imported_rows} rows from {summary.batch.filename}. Validation issues: {issue_count}.",
                "success",
            )
        except Exception as exc:
            session.rollback()
            flash(request, f"Import failed: {exc}", "error")
        finally:
            session.close()
            if tmp_file and tmp_file.exists():
                tmp_file.unlink(missing_ok=True)
            await workbook.close()

        return RedirectResponse("/imports", status_code=303)

    @app.get("/sites", response_class=HTMLResponse)
    def list_sites(request: Request):
        session = get_session(request)
        try:
            sites = session.scalars(select(Site).order_by(Site.name)).all()
            site_counts = {
                site.id: {
                    "networks": session.scalar(select(func.count()).select_from(Network).where(Network.site_id == site.id)) or 0,
                    "assignments": session.scalar(select(func.count()).select_from(IPAssignment).where(IPAssignment.site_id == site.id)) or 0,
                }
                for site in sites
            }
            return render(request, "sites.html", {"sites": sites, "site_counts": site_counts})
        finally:
            session.close()

    @app.get("/sites/new", response_class=HTMLResponse)
    def new_site(request: Request):
        return render(request, "site_form.html", {"site": None, "action": "/sites"})

    @app.get("/sites/{site_id}", response_class=HTMLResponse)
    def site_detail(request: Request, site_id: int):
        session = get_session(request)
        try:
            site = session.get(Site, site_id)
            if site is None:
                flash(request, "Site not found.", "error")
                return RedirectResponse("/sites", status_code=303)
            networks = session.scalars(select(Network).where(Network.site_id == site_id).order_by(Network.cidr, Network.name)).all()
            assignments = session.scalars(
                select(IPAssignment)
                .where(IPAssignment.site_id == site_id)
                .options(selectinload(IPAssignment.network))
                .order_by(IPAssignment.ip_address)
            ).all()
            return render(request, "site_detail.html", {"site": site, "networks": networks, "assignments": assignments})
        finally:
            session.close()

    @app.get("/sites/{site_id}/edit", response_class=HTMLResponse)
    def edit_site(request: Request, site_id: int):
        session = get_session(request)
        try:
            site = session.get(Site, site_id)
            if site is None:
                flash(request, "Site not found.", "error")
                return RedirectResponse("/sites", status_code=303)
            return render(request, "site_form.html", {"site": site, "action": f"/sites/{site_id}"})
        finally:
            session.close()

    @app.post("/sites")
    async def create_site(request: Request):
        form_data = await request.form()
        payload = parse_site_form(form_data)
        session = get_session(request)
        try:
            if not payload["name"]:
                flash(request, "Site name is required.", "error")
                return RedirectResponse("/sites/new", status_code=303)
            session.add(Site(**payload))
            session.commit()
            flash(request, f"Created site {payload['name']}.", "success")
            return RedirectResponse("/sites", status_code=303)
        except Exception as exc:
            session.rollback()
            flash(request, f"Failed to create site: {exc}", "error")
            return RedirectResponse("/sites/new", status_code=303)
        finally:
            session.close()

    @app.post("/sites/{site_id}")
    async def update_site(request: Request, site_id: int):
        form_data = await request.form()
        payload = parse_site_form(form_data)
        session = get_session(request)
        try:
            site = session.get(Site, site_id)
            if site is None:
                flash(request, "Site not found.", "error")
                return RedirectResponse("/sites", status_code=303)
            for key, value in payload.items():
                setattr(site, key, value)
            session.commit()
            flash(request, f"Updated site {site.name}.", "success")
            return RedirectResponse(f"/sites/{site_id}", status_code=303)
        except Exception as exc:
            session.rollback()
            flash(request, f"Failed to update site: {exc}", "error")
            return RedirectResponse(f"/sites/{site_id}/edit", status_code=303)
        finally:
            session.close()

    @app.get("/networks", response_class=HTMLResponse)
    def list_networks(request: Request):
        session = get_session(request)
        try:
            networks = session.scalars(select(Network).options(selectinload(Network.site)).order_by(Network.cidr, Network.name)).all()
            return render(request, "networks.html", {"networks": networks})
        finally:
            session.close()

    @app.get("/networks/new", response_class=HTMLResponse)
    def new_network(request: Request):
        session = get_session(request)
        try:
            sites = session.scalars(select(Site).order_by(Site.name)).all()
            return render(request, "network_form.html", {"network": None, "sites": sites, "action": "/networks"})
        finally:
            session.close()

    @app.get("/networks/{network_id}", response_class=HTMLResponse)
    def network_detail(request: Request, network_id: int):
        session = get_session(request)
        try:
            network = session.get(Network, network_id)
            if network is None:
                flash(request, "Network not found.", "error")
                return RedirectResponse("/networks", status_code=303)
            assignments = session.scalars(
                select(IPAssignment).where(IPAssignment.network_id == network_id).order_by(IPAssignment.ip_address)
            ).all()
            return render(request, "network_detail.html", {"network": network, "assignments": assignments})
        finally:
            session.close()

    @app.get("/networks/{network_id}/edit", response_class=HTMLResponse)
    def edit_network(request: Request, network_id: int):
        session = get_session(request)
        try:
            network = session.get(Network, network_id)
            if network is None:
                flash(request, "Network not found.", "error")
                return RedirectResponse("/networks", status_code=303)
            sites = session.scalars(select(Site).order_by(Site.name)).all()
            return render(request, "network_form.html", {"network": network, "sites": sites, "action": f"/networks/{network_id}"})
        finally:
            session.close()

    @app.post("/networks")
    async def create_network(request: Request):
        form_data = await request.form()
        payload = parse_network_form(form_data)
        session = get_session(request)
        try:
            session.add(Network(**payload))
            session.commit()
            rebuild_validation_issues(session)
            session.commit()
            flash(request, "Created network.", "success")
            return RedirectResponse("/networks", status_code=303)
        except Exception as exc:
            session.rollback()
            flash(request, f"Failed to create network: {exc}", "error")
            return RedirectResponse("/networks/new", status_code=303)
        finally:
            session.close()

    @app.post("/networks/{network_id}")
    async def update_network(request: Request, network_id: int):
        form_data = await request.form()
        payload = parse_network_form(form_data)
        session = get_session(request)
        try:
            network = session.get(Network, network_id)
            if network is None:
                flash(request, "Network not found.", "error")
                return RedirectResponse("/networks", status_code=303)
            for key, value in payload.items():
                setattr(network, key, value)
            session.commit()
            rebuild_validation_issues(session)
            session.commit()
            flash(request, "Updated network.", "success")
            return RedirectResponse(f"/networks/{network_id}", status_code=303)
        except Exception as exc:
            session.rollback()
            flash(request, f"Failed to update network: {exc}", "error")
            return RedirectResponse(f"/networks/{network_id}/edit", status_code=303)
        finally:
            session.close()

    @app.get("/assignments", response_class=HTMLResponse)
    def list_assignments(request: Request, q: str | None = None, site_id: int | None = None, status: str | None = None):
        session = get_session(request)
        try:
            query = select(IPAssignment).options(selectinload(IPAssignment.site), selectinload(IPAssignment.network))
            if site_id:
                query = query.where(IPAssignment.site_id == site_id)
            if status:
                query = query.where(IPAssignment.status == status)
            if q:
                like = f"%{q.lower()}%"
                query = query.where(
                    func.lower(IPAssignment.ip_address).like(like)
                    | func.lower(func.coalesce(IPAssignment.hostname, "")).like(like)
                    | func.lower(func.coalesce(IPAssignment.role, "")).like(like)
                    | func.lower(func.coalesce(IPAssignment.description, "")).like(like)
                )

            assignments = session.scalars(query.order_by(IPAssignment.ip_address)).all()
            sites = session.scalars(select(Site).order_by(Site.name)).all()
            return render(
                request,
                "assignments.html",
                {
                    "assignments": assignments,
                    "sites": sites,
                    "filters": {"q": q or "", "site_id": site_id, "status": status or ""},
                },
            )
        finally:
            session.close()

    @app.get("/assignments/new", response_class=HTMLResponse)
    def new_assignment(request: Request):
        session = get_session(request)
        try:
            sites = session.scalars(select(Site).order_by(Site.name)).all()
            networks = session.scalars(select(Network).options(selectinload(Network.site)).order_by(Network.cidr, Network.name)).all()
            return render(
                request,
                "assignment_form.html",
                {"assignment": None, "sites": sites, "networks": networks, "action": "/assignments"},
            )
        finally:
            session.close()

    @app.get("/assignments/{assignment_id}/edit", response_class=HTMLResponse)
    def edit_assignment(request: Request, assignment_id: int):
        session = get_session(request)
        try:
            assignment = session.get(IPAssignment, assignment_id)
            if assignment is None:
                flash(request, "Assignment not found.", "error")
                return RedirectResponse("/assignments", status_code=303)
            sites = session.scalars(select(Site).order_by(Site.name)).all()
            networks = session.scalars(select(Network).options(selectinload(Network.site)).order_by(Network.cidr, Network.name)).all()
            return render(
                request,
                "assignment_form.html",
                {"assignment": assignment, "sites": sites, "networks": networks, "action": f"/assignments/{assignment_id}"},
            )
        finally:
            session.close()

    @app.post("/assignments")
    async def create_assignment(request: Request):
        form_data = await request.form()
        payload = parse_assignment_form(form_data)
        session = get_session(request)
        try:
            if not payload["ip_address"]:
                flash(request, "IP address is required.", "error")
                return RedirectResponse("/assignments/new", status_code=303)
            if payload["network_id"] and not payload["site_id"]:
                network = session.get(Network, payload["network_id"])
                if network is not None:
                    payload["site_id"] = network.site_id
            session.add(IPAssignment(**payload, source_payload={"origin": "manual"}))
            session.commit()
            rebuild_validation_issues(session)
            session.commit()
            flash(request, "Created IP assignment.", "success")
            return RedirectResponse("/assignments", status_code=303)
        except Exception as exc:
            session.rollback()
            flash(request, f"Failed to create assignment: {exc}", "error")
            return RedirectResponse("/assignments/new", status_code=303)
        finally:
            session.close()

    @app.post("/assignments/{assignment_id}")
    async def update_assignment(request: Request, assignment_id: int):
        form_data = await request.form()
        payload = parse_assignment_form(form_data)
        session = get_session(request)
        try:
            assignment = session.get(IPAssignment, assignment_id)
            if assignment is None:
                flash(request, "Assignment not found.", "error")
                return RedirectResponse("/assignments", status_code=303)
            if payload["network_id"] and not payload["site_id"]:
                network = session.get(Network, payload["network_id"])
                if network is not None:
                    payload["site_id"] = network.site_id
            for key, value in payload.items():
                setattr(assignment, key, value)
            assignment.source_payload = {**(assignment.source_payload or {}), "origin": "manual"}
            session.commit()
            rebuild_validation_issues(session)
            session.commit()
            flash(request, "Updated IP assignment.", "success")
            return RedirectResponse("/assignments", status_code=303)
        except Exception as exc:
            session.rollback()
            flash(request, f"Failed to update assignment: {exc}", "error")
            return RedirectResponse(f"/assignments/{assignment_id}/edit", status_code=303)
        finally:
            session.close()

    @app.post("/assignments/{assignment_id}/delete")
    def delete_assignment(request: Request, assignment_id: int):
        session = get_session(request)
        try:
            assignment = session.get(IPAssignment, assignment_id)
            if assignment is None:
                flash(request, "Assignment not found.", "error")
                return RedirectResponse("/assignments", status_code=303)
            session.delete(assignment)
            session.commit()
            rebuild_validation_issues(session)
            session.commit()
            flash(request, "Deleted IP assignment.", "success")
            return RedirectResponse("/assignments", status_code=303)
        except Exception as exc:
            session.rollback()
            flash(request, f"Failed to delete assignment: {exc}", "error")
            return RedirectResponse("/assignments", status_code=303)
        finally:
            session.close()

    @app.get("/exports/assignments.csv")
    def export_csv(request: Request):
        session = get_session(request)
        try:
            payload = export_assignments_csv(session)
            return Response(
                payload,
                media_type="text/csv",
                headers={"Content-Disposition": 'attachment; filename="rke2-ipam-assignments.csv"'},
            )
        finally:
            session.close()

    @app.get("/exports/workbook.xlsx")
    def export_excel(request: Request):
        session = get_session(request)
        try:
            payload = export_workbook(session)
            return Response(
                payload,
                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                headers={"Content-Disposition": 'attachment; filename="rke2-ipam-export.xlsx"'},
            )
        finally:
            session.close()

    @app.get("/api/node-payloads")
    def node_payloads(request: Request):
        session = get_session(request)
        try:
            assignments = session.scalars(
                select(IPAssignment).options(selectinload(IPAssignment.site), selectinload(IPAssignment.network)).order_by(IPAssignment.hostname, IPAssignment.ip_address)
            ).all()
            payload = [
                {
                    "hostname": item.hostname,
                    "site": item.site.name if item.site else None,
                    "ip_address": item.ip_address,
                    "gateway": item.gateway or (item.network.gateway if item.network else None),
                    "dns_servers": item.dns_servers or (item.network.dns_servers if item.network else []),
                    "search_domains": item.search_domains or (item.network.search_domains if item.network else []),
                    "network": item.network.name if item.network else None,
                    "cidr": item.network.cidr if item.network else None,
                    "vlan_id": item.network.vlan_id if item.network else None,
                    "interface_name": item.interface_name,
                    "role": item.role,
                }
                for item in assignments
            ]
            return JSONResponse(payload)
        finally:
            session.close()

    return app


app = create_app()