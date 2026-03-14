"""
ScanManager — runs scans in thread pool, persists everything to PostgreSQL.
"""

import os
import time
import traceback
import concurrent.futures
from datetime import datetime, timezone
from typing import Optional, List

from sqlalchemy.orm import Session

from .models import Scan, ScanHost, ScanStatus
from .database import SessionLocal
from .discovery import discover_all_subdomains
from .scanner import (
    scan_single_host,
    export_cyclonedx_cbom,
    build_html_report,
    WEB_PORTS,
    TOP_PORTS,
)

REPORTS_DIR = os.getenv("REPORTS_DIR", "/app/reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)


def start_scan_background(scan_id: str, user_id: str, domain: str,
                           ports: str, threads: int, include_subdomains: bool):
    """Submit scan to thread pool. Returns immediately."""
    _executor.submit(
        _run_scan, scan_id, user_id, domain, ports, threads, include_subdomains
    )


def _run_scan(scan_id: str, user_id: str, domain: str,
              ports: str, threads: int, include_subdomains: bool):
    """Blocking scan runner — executes in thread pool."""
    db = SessionLocal()
    timer = time.time()
    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    port_list = WEB_PORTS if ports == "web" else TOP_PORTS
    events: list = []

    def emit(etype, message, **extra):
        ev = {"type": etype, "message": message, **extra,
              "ts": datetime.now(timezone.utc).isoformat()}
        events.append(ev)
        _update_db(db, scan_id, message=message,
                   events=list(events))

    try:
        _update_db(db, scan_id, status=ScanStatus.running, progress=5,
                   message="Starting enhanced subdomain discovery…", events=events)

        # ── Phase 1: Discovery ─────────────────────────────────
        if include_subdomains:
            emit("phase", "Running enhanced subdomain discovery (9 sources)…")
            subs = discover_all_subdomains(domain, threads=threads)
        else:
            subs = []

        all_hosts = [domain] + subs
        emit("subdomains", f"Found {len(subs)} subdomains across all sources",
             subdomains=subs, total_hosts=len(all_hosts))
        _update_db(db, scan_id, progress=20,
                   message=f"Scanning {len(all_hosts)} hosts…", events=list(events))

        # ── Phase 2: Host Scanning ─────────────────────────────
        emit("phase", f"Scanning {len(all_hosts)} hosts for TLS/PQC…")
        scanned: list = []
        done = 0
        total = len(all_hosts)

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(scan_single_host, h, port_list): h for h in all_hosts}
            for f in concurrent.futures.as_completed(futures):
                done += 1
                result = f.result()
                if result:
                    import json
                    safe_result = json.loads(json.dumps(result, default=str))
                    scanned.append(safe_result)

                    # Persist host to DB
                    host_row = ScanHost(
                        scan_id=scan_id,
                        hostname=safe_result["hostname"],
                        ip=safe_result.get("ip"),
                        data=safe_result,
                    )
                    db.add(host_row)
                    db.commit()

                    emit("host_result", f"Scanned {safe_result['hostname']}",
                         host=safe_result)

                progress = 20 + int((done / total) * 70)
                _update_db(db, scan_id, progress=progress,
                           message=f"Scanning hosts… {done}/{total}", events=list(events))

        # ── Phase 3: Finalise ──────────────────────────────────
        elapsed  = round(time.time() - timer, 1)
        summary  = _build_summary(scanned)

        # Build and save HTML + CBOM
        html_content = build_html_report(domain, scanned, elapsed, scan_time)
        html_path    = os.path.join(REPORTS_DIR, f"scan_{scan_id}.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        import json
        cbom_content = export_cyclonedx_cbom(domain, scanned, scan_time, elapsed)
        cbom_path    = os.path.join(REPORTS_DIR, f"scan_{scan_id}.cdx.json")
        with open(cbom_path, "w", encoding="utf-8") as f:
            json.dump(cbom_content, f, indent=2)

        emit("complete", f"Scan complete — {len(scanned)} hosts in {elapsed}s",
             summary=summary, elapsed=elapsed)

        _update_db(db, scan_id,
                   status=ScanStatus.complete,
                   progress=100,
                   message=f"Complete — {len(scanned)} hosts in {elapsed}s",
                   summary=summary,
                   events=list(events),
                   completed_at=datetime.now(timezone.utc),
                   elapsed=elapsed)

    except Exception as e:
        tb = traceback.format_exc()
        emit("error", f"Scan failed: {e}")
        _update_db(db, scan_id,
                   status=ScanStatus.error,
                   message=f"Error: {e}",
                   error_msg=tb,
                   events=list(events),
                   completed_at=datetime.now(timezone.utc))
    finally:
        db.close()


def _update_db(db: Session, scan_id: str, **kwargs):
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            for k, v in kwargs.items():
                setattr(scan, k, v)
            db.commit()
    except Exception:
        db.rollback()


def _build_summary(scanned: list) -> dict:
    tls_ports   = sum(1 for h in scanned for p in h["ports"] if p.get("has_tls"))
    fully_safe  = sum(1 for h in scanned for p in h["ports"] if p.get("pqc") and p["pqc"]["label_class"] == "safe")
    pqc_ready   = sum(1 for h in scanned for p in h["ports"] if p.get("pqc") and p["pqc"]["label_class"] == "pqc-ready")
    pqc_not_rdy = sum(1 for h in scanned for p in h["ports"] if p.get("pqc") and p["pqc"]["label_class"] == "warn")
    not_safe    = sum(1 for h in scanned for p in h["ports"] if p.get("pqc") and p["pqc"]["label_class"] == "danger")
    awarded     = sum(1 for h in scanned for p in h["ports"] if p.get("pqc") and p["pqc"].get("certificate_label"))
    risk_score  = round(((not_safe * 1.0 + pqc_not_rdy * 0.6) / tls_ports) * 100) if tls_ports else 0

    # Cipher breakdown
    all_ciphers: dict = {}
    for h in scanned:
        for p in h["ports"]:
            tls = p.get("tls") or {}
            for c in tls.get("all_ciphers", []):
                all_ciphers[c] = all_ciphers.get(c, 0) + 1

    # TLS version breakdown
    tls_versions: dict = {}
    for h in scanned:
        for p in h["ports"]:
            v = (p.get("tls") or {}).get("version")
            if v:
                tls_versions[v] = tls_versions.get(v, 0) + 1

    # Port frequency
    port_freq: dict = {}
    for h in scanned:
        for p in h["ports"]:
            port_freq[str(p["port"])] = port_freq.get(str(p["port"]), 0) + 1

    return {
        "total_hosts":        len(scanned),
        "tls_endpoints":      tls_ports,
        "fully_quantum_safe": fully_safe,
        "pqc_ready":          pqc_ready,
        "pqc_not_ready":      pqc_not_rdy,
        "not_quantum_safe":   not_safe,
        "labels_awarded":     awarded,
        "quantum_risk_score": min(risk_score, 100),
        "cipher_breakdown":   dict(sorted(all_ciphers.items(), key=lambda x: -x[1])[:15]),
        "tls_version_breakdown": tls_versions,
        "port_frequency":     dict(sorted(port_freq.items(), key=lambda x: -x[1])[:10]),
    }


# ── Read helpers ───────────────────────────────────────────────

def get_scan_with_hosts(db: Session, scan_id: str, user_id: str) -> Optional[dict]:
    scan = db.query(Scan).filter(
        Scan.id == scan_id, Scan.user_id == user_id
    ).first()
    if not scan:
        return None
    hosts = db.query(ScanHost).filter(ScanHost.scan_id == scan_id).all()
    return {
        "id":           scan.id,
        "domain":       scan.domain,
        "status":       scan.status.value,
        "progress":     scan.progress,
        "message":      scan.message,
        "started_at":   scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "elapsed":      scan.elapsed,
        "summary":      scan.summary or {},
        "events":       scan.events or [],
        "results":      [h.data for h in hosts],
    }


def get_scan_events(db: Session, scan_id: str, user_id: str) -> Optional[list]:
    scan = db.query(Scan).filter(
        Scan.id == scan_id, Scan.user_id == user_id
    ).first()
    return scan.events if scan else None


def list_scans(db: Session, user_id: str, limit: int = 50) -> List[dict]:
    scans = db.query(Scan).filter(
        Scan.user_id == user_id
    ).order_by(Scan.started_at.desc()).limit(limit).all()
    return [{
        "id":           s.id,
        "domain":       s.domain,
        "status":       s.status.value,
        "progress":     s.progress,
        "started_at":   s.started_at.isoformat() if s.started_at else None,
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        "elapsed":      s.elapsed,
        "summary":      s.summary or {},
    } for s in scans]
