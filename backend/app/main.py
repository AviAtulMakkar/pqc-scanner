"""
PQC CBOM Scanner — FastAPI Application
Auth + Scans + Reports + Jobs + Analytics
"""

import os
import uuid
import asyncio
import json
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Query
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .database  import get_db, create_tables
from .models    import User, Scan, ScanStatus, Report, ScheduledJob
from .auth      import hash_password, verify_password, create_token, get_current_user
from .schemas   import (
    RegisterRequest, LoginRequest, TokenResponse,
    ScanRequest, OnDemandReportRequest,
    ScheduledReportRequest, FrequencyReportRequest,
)
from .scan_manager   import start_scan_background, get_scan_with_hosts, get_scan_events, list_scans
from .report_manager import generate_on_demand, list_reports
from .scheduler      import scheduler

app = FastAPI(title="PQC CBOM Scanner", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REPORTS_DIR = os.getenv("REPORTS_DIR", "/app/reports")


@app.on_event("startup")
async def startup():
    create_tables()
    await scheduler.start()

@app.on_event("shutdown")
async def shutdown():
    await scheduler.stop()


# ══════════════════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════════════════

@app.post("/auth/register", response_model=TokenResponse, tags=["Auth"])
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(400, "Email already registered")
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(400, "Username already taken")
    user = User(
        id=str(uuid.uuid4()),
        email=req.email,
        username=req.username,
        full_name=req.full_name,
        hashed_password=hash_password(req.password),
        is_admin=db.query(User).count() == 0,  # first user is admin
    )
    db.add(user); db.commit(); db.refresh(user)
    token = create_token(user.id, user.username)
    return TokenResponse(access_token=token, user_id=user.id,
                         username=user.username, email=user.email,
                         is_admin=user.is_admin)


@app.post("/auth/login", response_model=TokenResponse, tags=["Auth"])
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(401, "Invalid username or password")
    if not user.is_active:
        raise HTTPException(403, "Account deactivated")
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    token = create_token(user.id, user.username)
    return TokenResponse(access_token=token, user_id=user.id,
                         username=user.username, email=user.email,
                         is_admin=user.is_admin)


@app.get("/auth/me", tags=["Auth"])
def me(current_user: User = Depends(get_current_user)):
    return {
        "id":         current_user.id,
        "username":   current_user.username,
        "email":      current_user.email,
        "full_name":  current_user.full_name,
        "is_admin":   current_user.is_admin,
        "created_at": current_user.created_at.isoformat(),
    }


# ══════════════════════════════════════════════════════════════
#  SCANS
# ══════════════════════════════════════════════════════════════

@app.post("/scan", tags=["Scans"])
def start_scan(
    req: ScanRequest,
    bg:  BackgroundTasks,
    db:  Session       = Depends(get_db),
    user: User         = Depends(get_current_user),
):
    scan = Scan(
        id=str(uuid.uuid4()), user_id=user.id,
        domain=req.domain, status=ScanStatus.queued,
        ports_config=req.ports, threads=req.threads,
    )
    db.add(scan); db.commit()
    bg.add_task(
        start_scan_background,
        scan.id, user.id, req.domain,
        req.ports, req.threads, req.include_subdomains
    )
    return {"scan_id": scan.id, "status": "queued", "domain": req.domain}


@app.get("/scan/{scan_id}", tags=["Scans"])
def get_scan(
    scan_id: str,
    db:      Session = Depends(get_db),
    user:    User    = Depends(get_current_user),
):
    data = get_scan_with_hosts(db, scan_id, user.id)
    if not data:
        raise HTTPException(404, "Scan not found")
    return data


@app.get("/scan/{scan_id}/status", tags=["Scans"])
def scan_status(
    scan_id: str,
    db:      Session = Depends(get_db),
    user:    User    = Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {
        "scan_id":  scan.id,
        "status":   scan.status.value,
        "progress": scan.progress,
        "message":  scan.message,
        "domain":   scan.domain,
        "elapsed":  scan.elapsed,
    }


@app.get("/scan/{scan_id}/stream", tags=["Scans"])
async def stream_scan(
    scan_id: str,
    token:   str     = Query(..., description="JWT token (passed as query param for SSE)"),
    db:      Session = Depends(get_db),
):
    """SSE endpoint — token passed as query param because EventSource can't set headers."""
    from .auth import decode_token
    payload = decode_token(token)
    user_id = payload.get("sub")
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    async def generate():
        last_idx = 0
        while True:
            fresh = db.query(Scan).filter(Scan.id == scan_id).first()
            if not fresh:
                break
            events = fresh.events or []
            for ev in events[last_idx:]:
                yield f"data: {json.dumps(ev)}\n\n"
            last_idx = len(events)
            if fresh.status in (ScanStatus.complete, ScanStatus.error):
                yield f"data: {json.dumps({'type':'done','status':fresh.status.value})}\n\n"
                break
            await asyncio.sleep(1)

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/scans", tags=["Scans"])
def get_scans(
    limit: int   = Query(50, le=200),
    db:    Session = Depends(get_db),
    user:  User    = Depends(get_current_user),
):
    return list_scans(db, user.id, limit)


# ══════════════════════════════════════════════════════════════
#  ANALYTICS
# ══════════════════════════════════════════════════════════════

@app.get("/analytics/overview", tags=["Analytics"])
def analytics_overview(
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """Aggregate analytics across all of a user's scans."""
    scans = db.query(Scan).filter(
        Scan.user_id == user.id,
        Scan.status  == ScanStatus.complete
    ).order_by(Scan.started_at).all()

    if not scans:
        return {"scans": [], "totals": {}, "trends": [], "cipher_totals": {}, "tls_totals": {}, "port_totals": {}}

    # Risk trend over time
    trends = []
    for s in scans:
        sm = s.summary or {}
        trends.append({
            "date":       s.started_at.isoformat() if s.started_at else None,
            "domain":     s.domain,
            "risk_score": sm.get("quantum_risk_score", 0),
            "fully_safe": sm.get("fully_quantum_safe", 0),
            "pqc_ready":  sm.get("pqc_ready", 0),
            "not_safe":   sm.get("not_quantum_safe", 0),
            "total_hosts":sm.get("total_hosts", 0),
        })

    # Aggregate cipher breakdown across all scans
    cipher_totals: dict = {}
    tls_totals:    dict = {}
    port_totals:   dict = {}
    for s in scans:
        sm = s.summary or {}
        for c, n in (sm.get("cipher_breakdown") or {}).items():
            cipher_totals[c] = cipher_totals.get(c, 0) + n
        for v, n in (sm.get("tls_version_breakdown") or {}).items():
            tls_totals[v] = tls_totals.get(v, 0) + n
        for p, n in (sm.get("port_frequency") or {}).items():
            port_totals[p] = port_totals.get(p, 0) + n

    latest = scans[-1].summary or {} if scans else {}

    return {
        "total_scans":   len(scans),
        "latest_summary": latest,
        "trends":        trends,
        "cipher_totals": dict(sorted(cipher_totals.items(), key=lambda x: -x[1])[:12]),
        "tls_totals":    tls_totals,
        "port_totals":   dict(sorted(port_totals.items(), key=lambda x: -x[1])[:10]),
        "scans":         [{"id": s.id, "domain": s.domain,
                           "date": s.started_at.isoformat() if s.started_at else None,
                           "risk": (s.summary or {}).get("quantum_risk_score", 0)}
                          for s in scans],
    }


@app.get("/analytics/domain/{domain}", tags=["Analytics"])
def analytics_domain(
    domain: str,
    db:     Session = Depends(get_db),
    user:   User    = Depends(get_current_user),
):
    """Risk trend for a specific domain over time."""
    scans = db.query(Scan).filter(
        Scan.user_id == user.id,
        Scan.domain  == domain,
        Scan.status  == ScanStatus.complete,
    ).order_by(Scan.started_at).all()

    return [{
        "scan_id":    s.id,
        "date":       s.started_at.isoformat() if s.started_at else None,
        "elapsed":    s.elapsed,
        "summary":    s.summary or {},
    } for s in scans]


# ══════════════════════════════════════════════════════════════
#  REPORTS
# ══════════════════════════════════════════════════════════════

@app.post("/report/on-demand", tags=["Reports"])
async def on_demand_report(
    req:  OnDemandReportRequest,
    bg:   BackgroundTasks,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    scan = db.query(Scan).filter(
        Scan.id == req.scan_id, Scan.user_id == user.id
    ).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status != ScanStatus.complete:
        raise HTTPException(400, f"Scan not complete (status: {scan.status.value})")

    report = Report(
        id=str(uuid.uuid4()), user_id=user.id,
        scan_id=req.scan_id, report_type="on-demand",
        format=req.format, status="generating",
    )
    db.add(report); db.commit()

    # NOTE: do NOT pass the request-scoped `db` here — FastAPI closes it
    # before the background task runs. report_manager opens its own session.
    bg.add_task(generate_on_demand, report.id, req.scan_id, user.id,
                req.format, req.email_to, req.send_email, req.notes)
    return {"report_id": report.id, "status": "generating"}


@app.post("/report/scheduled", tags=["Reports"])
async def schedule_report(
    req:  ScheduledReportRequest,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    job_id = await scheduler.add_scheduled(user.id, req)
    return {"job_id": job_id, "status": "scheduled", "run_at": req.run_at.isoformat()}


@app.post("/report/frequency", tags=["Reports"])
async def frequency_report(
    req:  FrequencyReportRequest,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    job_id = await scheduler.add_frequency(user.id, req)
    return {"job_id": job_id, "status": "active",
            "frequency": f"every {req.interval_value} {req.interval_unit}"}


@app.get("/report/{report_id}/download", tags=["Reports"])
def download_report(
    report_id: str,
    db:        Session = Depends(get_db),
    token:     Optional[str] = Query(None),
):
    """Download a report file. Accepts JWT as ?token= query param for direct browser links."""
    from .auth import decode_token
    if not token:
        raise HTTPException(401, "token query param required for download links")
    payload = decode_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(401, "Invalid token")

    report = db.query(Report).filter(
        Report.id == report_id, Report.user_id == user_id
    ).first()
    if not report:
        raise HTTPException(404, "Report not found")
    if report.status != "ready" or not report.file_path:
        raise HTTPException(400, "Report not ready yet")
    if not os.path.exists(report.file_path):
        raise HTTPException(404, "Report file missing from disk")

    ext_map = {"html": "text/html", "json": "application/json",
               "cbom": "application/json", "pdf": "application/pdf"}
    fmt = report.format.value if report.format else "html"
    return FileResponse(
        report.file_path,
        media_type=ext_map.get(fmt, "application/octet-stream"),
        filename=report.file_name or f"report.{fmt}",
    )


@app.get("/reports", tags=["Reports"])
def get_reports(
    limit: int   = Query(50, le=200),
    db:    Session = Depends(get_db),
    user:  User    = Depends(get_current_user),
):
    return list_reports(db, user.id, limit)


# ══════════════════════════════════════════════════════════════
#  JOBS
# ══════════════════════════════════════════════════════════════

@app.get("/jobs", tags=["Jobs"])
def get_jobs(
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    return scheduler.list_jobs(db, user.id)


@app.delete("/jobs/{job_id}", tags=["Jobs"])
async def cancel_job(
    job_id: str,
    db:     Session = Depends(get_db),
    user:   User    = Depends(get_current_user),
):
    ok = await scheduler.cancel(job_id, user.id)
    if not ok:
        raise HTTPException(404, "Job not found")
    return {"job_id": job_id, "status": "cancelled"}


# ── Health ─────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
def health(db: Session = Depends(get_db)):
    try:
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    return {"status": "ok", "db": "connected" if db_ok else "error",
            "smtp": "configured" if os.getenv("SMTP_USER") else "not configured"}
