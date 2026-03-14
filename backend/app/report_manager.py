"""
ReportManager — generates reports, saves to disk, persists metadata to PostgreSQL.
"""

import os
import json
import shutil
from datetime import datetime, timezone
from typing import Optional, List

from sqlalchemy.orm import Session

from .models import Report, Scan, ScanHost, ReportFormat
from .database import SessionLocal
from .email_service import EmailService

REPORTS_DIR = os.getenv("REPORTS_DIR", "/app/reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

email_svc = EmailService()


async def generate_on_demand(report_id: str, scan_id: str,
                              user_id: str, fmt: str, email_to: list,
                              send_email: bool, notes: Optional[str] = None):
    """Generate a report from a completed scan. Opens its own DB session."""
    db = SessionLocal()
    try:
        _update_report(db, report_id, status="generating")
        scan_data = _load_scan_data(db, scan_id, user_id)
        if not scan_data:
            _update_report(db, report_id, status="error"); return

        path = _write_report(report_id, scan_data, fmt, notes)
        fname = os.path.basename(path)
        _update_report(db, report_id, status="ready", file_path=path, file_name=fname)

        if send_email and email_to:
            subject = f"PQC Report — {scan_data['domain']}"
            body    = email_svc.build_report_email(scan_data, fmt)
            ok, msg = await email_svc.send_report(email_to, subject, body, path, fname)
            _update_report(db, report_id,
                           emailed_to=email_to,
                           email_status="sent" if ok else f"failed: {msg}")
    except Exception as e:
        _update_report(db, report_id, status="error")
    finally:
        db.close()


async def generate_for_job(db: Session, report_id: str, scan_data: dict,
                            user_id: str, fmt: str, email_to: list,
                            send_email: bool, report_type: str):
    """Called by scheduler after a scan completes."""
    _update_report(db, report_id, status="generating")
    try:
        path  = _write_report(report_id, scan_data, fmt)
        fname = os.path.basename(path)
        _update_report(db, report_id, status="ready", file_path=path, file_name=fname)

        if send_email and email_to:
            subject = f"PQC {report_type.title()} Report — {scan_data['domain']} ({datetime.now().strftime('%Y-%m-%d')})"
            body    = email_svc.build_report_email(scan_data, fmt)
            ok, msg = await email_svc.send_report(email_to, subject, body, path, fname)
            _update_report(db, report_id, emailed_to=email_to,
                           email_status="sent" if ok else f"failed: {msg}")
    except Exception as e:
        _update_report(db, report_id, status="error")


def _write_report(report_id: str, scan_data: dict, fmt: str,
                  notes: Optional[str] = None) -> str:
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = scan_data.get("domain", "unknown").replace(".", "_")

    if fmt == "html":
        fname = f"{report_id}_{domain}_{ts}.html"
        path  = os.path.join(REPORTS_DIR, fname)
        # Try reusing cached scan HTML
        existing = os.path.join(REPORTS_DIR, f"scan_{scan_data.get('id', report_id)}.html")
        if os.path.exists(existing):
            shutil.copy(existing, path)
        else:
            from .scanner import build_html_report
            content = build_html_report(
                scan_data["domain"], scan_data.get("results", []),
                scan_data.get("elapsed", 0),
                scan_data.get("started_at", datetime.now(timezone.utc).isoformat())
            )
            if notes:
                content = content.replace("</body>",
                    f'<div style="padding:20px;font-family:sans-serif">'
                    f'<b>Notes:</b><p>{notes}</p></div></body>')
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)

    elif fmt == "json":
        fname = f"{report_id}_{domain}_{ts}.json"
        path  = os.path.join(REPORTS_DIR, fname)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "meta":    {"domain": scan_data["domain"], "scan_id": scan_data.get("id"),
                            "generated": datetime.now(timezone.utc).isoformat(), "notes": notes},
                "summary": scan_data.get("summary", {}),
                "hosts":   scan_data.get("results", []),
            }, f, indent=2, default=str)

    elif fmt == "cbom":
        fname = f"{report_id}_{domain}_{ts}.cdx.json"
        path  = os.path.join(REPORTS_DIR, fname)
        existing = os.path.join(REPORTS_DIR, f"scan_{scan_data.get('id', report_id)}.cdx.json")
        if os.path.exists(existing):
            shutil.copy(existing, path)
        else:
            from .scanner import export_cyclonedx_cbom
            cbom = export_cyclonedx_cbom(scan_data["domain"], scan_data.get("results", []),
                                         scan_data.get("started_at", ""), scan_data.get("elapsed", 0))
            with open(path, "w", encoding="utf-8") as f:
                json.dump(cbom, f, indent=2)
    else:
        raise ValueError(f"Unsupported format: {fmt}")

    return path


def _load_scan_data(db: Session, scan_id: str, user_id: str) -> Optional[dict]:
    scan  = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user_id).first()
    if not scan:
        return None
    hosts = db.query(ScanHost).filter(ScanHost.scan_id == scan_id).all()
    return {
        "id":         scan.id,
        "domain":     scan.domain,
        "summary":    scan.summary or {},
        "results":    [h.data for h in hosts],
        "elapsed":    scan.elapsed,
        "started_at": scan.started_at.isoformat() if scan.started_at else "",
    }


def _update_report(db: Session, report_id: str, **kwargs):
    try:
        r = db.query(Report).filter(Report.id == report_id).first()
        if r:
            for k, v in kwargs.items():
                setattr(r, k, v)
            db.commit()
    except Exception:
        db.rollback()


def list_reports(db: Session, user_id: str, limit: int = 50) -> list:
    reports = db.query(Report).filter(
        Report.user_id == user_id
    ).order_by(Report.created_at.desc()).limit(limit).all()
    return [{
        "id":           r.id,
        "scan_id":      r.scan_id,
        "report_type":  r.report_type,
        "format":       r.format.value if r.format else "html",
        "status":       r.status,
        "file_name":    r.file_name,
        "email_status": r.email_status,
        "emailed_to":   r.emailed_to or [],
        "created_at":   r.created_at.isoformat() if r.created_at else None,
    } for r in reports]
