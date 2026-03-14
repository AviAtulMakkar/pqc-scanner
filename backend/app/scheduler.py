"""
SchedulerService — APScheduler-backed job engine with PostgreSQL persistence.
"""

import uuid
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from .models import ScheduledJob, JobType, JobStatus, ReportFormat, Scan, ScanStatus
from .database import SessionLocal

try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.date      import DateTrigger
    from apscheduler.triggers.interval  import IntervalTrigger
    HAS_APScheduler = True
except ImportError:
    HAS_APScheduler = False


class SchedulerService:
    def __init__(self):
        self._scheduler = AsyncIOScheduler(timezone="UTC") if HAS_APScheduler else None

    async def start(self):
        if self._scheduler:
            self._scheduler.start()
            await self._restore_jobs()

    async def stop(self):
        if self._scheduler and self._scheduler.running:
            self._scheduler.shutdown(wait=False)

    # ── Add jobs ───────────────────────────────────────────────

    async def add_scheduled(self, user_id: str, req) -> str:
        db = SessionLocal()
        try:
            job = ScheduledJob(
                id=str(uuid.uuid4()), user_id=user_id,
                label=req.label or f"Scheduled — {req.domain}",
                job_type=JobType.scheduled, domain=req.domain,
                ports_config=req.ports,
                report_format=ReportFormat(req.format),
                email_to=req.email_to, send_email=req.send_email,
                run_at=req.run_at, next_run_at=req.run_at,
            )
            db.add(job); db.commit()
            self._schedule_job(job.id, "scheduled", run_at=req.run_at)
            return job.id
        finally:
            db.close()

    async def add_frequency(self, user_id: str, req) -> str:
        db = SessionLocal()
        try:
            unit_sec  = {"hours": 3600, "days": 86400, "weeks": 604800}
            next_run  = datetime.now(timezone.utc) + timedelta(
                seconds=req.interval_value * unit_sec[req.interval_unit]
            )
            job = ScheduledJob(
                id=str(uuid.uuid4()), user_id=user_id,
                label=req.label or f"Every {req.interval_value} {req.interval_unit} — {req.domain}",
                job_type=JobType.frequency, domain=req.domain,
                ports_config=req.ports,
                report_format=ReportFormat(req.format),
                email_to=req.email_to, send_email=req.send_email,
                interval_value=req.interval_value,
                interval_unit=req.interval_unit,
                max_runs=req.max_runs,
                next_run_at=next_run,
            )
            db.add(job); db.commit()
            self._schedule_job(job.id, "frequency",
                               interval_value=req.interval_value,
                               interval_unit=req.interval_unit,
                               start_date=next_run)
            return job.id
        finally:
            db.close()

    async def cancel(self, job_id: str, user_id: str) -> bool:
        db = SessionLocal()
        try:
            job = db.query(ScheduledJob).filter(
                ScheduledJob.id == job_id,
                ScheduledJob.user_id == user_id
            ).first()
            if not job:
                return False
            job.status = JobStatus.cancelled
            db.commit()
            if self._scheduler:
                try: self._scheduler.remove_job(job_id)
                except Exception: pass
            return True
        finally:
            db.close()

    def list_jobs(self, db: Session, user_id: str) -> list:
        jobs = db.query(ScheduledJob).filter(
            ScheduledJob.user_id == user_id
        ).order_by(ScheduledJob.created_at.desc()).all()
        return [{
            "id":             j.id,
            "label":          j.label,
            "job_type":       j.job_type.value,
            "status":         j.status.value,
            "domain":         j.domain,
            "run_count":      j.run_count,
            "next_run_at":    j.next_run_at.isoformat() if j.next_run_at else None,
            "last_run_at":    j.last_run_at.isoformat() if j.last_run_at else None,
            "created_at":     j.created_at.isoformat() if j.created_at else None,
            "interval_value": j.interval_value,
            "interval_unit":  j.interval_unit,
        } for j in jobs]

    # ── Internal ───────────────────────────────────────────────

    def _schedule_job(self, job_id, job_type, run_at=None,
                      interval_value=None, interval_unit=None, start_date=None):
        if not self._scheduler:
            return
        if job_type == "scheduled":
            self._scheduler.add_job(self._execute, DateTrigger(run_date=run_at),
                                    args=[job_id], id=job_id,
                                    replace_existing=True, misfire_grace_time=3600)
        else:
            kwargs = {interval_unit: interval_value}
            self._scheduler.add_job(self._execute,
                                    IntervalTrigger(**kwargs, start_date=start_date),
                                    args=[job_id], id=job_id, replace_existing=True)

    async def _execute(self, job_id: str):
        db = SessionLocal()
        try:
            job = db.query(ScheduledJob).filter(ScheduledJob.id == job_id).first()
            if not job or job.status != JobStatus.active:
                return
            if job.max_runs and job.run_count >= job.max_runs:
                job.status = JobStatus.completed; db.commit(); return
        finally:
            db.close()

        # Import here to avoid circular imports
        from .scan_manager import start_scan_background, get_scan_with_hosts
        from .report_manager import generate_for_job

        db2 = SessionLocal()
        try:
            job = db2.query(ScheduledJob).filter(ScheduledJob.id == job_id).first()

            # Create scan record
            scan = Scan(
                id=str(uuid.uuid4()), user_id=job.user_id,
                domain=job.domain, status=ScanStatus.queued,
                ports_config=job.ports_config, threads=100,
            )
            db2.add(scan); db2.commit()
            scan_id = scan.id

            start_scan_background(scan_id, job.user_id, job.domain,
                                  job.ports_config, 100, True)

            # Wait for completion (max 30 min)
            for _ in range(360):
                await asyncio.sleep(5)
                s = db2.query(Scan).filter(Scan.id == scan_id).first()
                if s and s.status in (ScanStatus.complete, ScanStatus.error):
                    break

            scan_data = get_scan_with_hosts(db2, scan_id, job.user_id)
            if scan_data and scan_data["status"] == "complete":
                report_id = str(uuid.uuid4())
                from .models import Report
                rep = Report(id=report_id, user_id=job.user_id, scan_id=scan_id,
                             report_type=job.job_type.value,
                             format=job.report_format)
                db2.add(rep); db2.commit()
                await generate_for_job(db2, report_id, scan_data, job.user_id,
                                       job.report_format.value,
                                       job.email_to or [], job.send_email,
                                       job.job_type.value)

            # Update job record
            job.run_count  += 1
            job.last_run_at = datetime.now(timezone.utc)
            if job.job_type == JobType.scheduled:
                job.status = JobStatus.completed
            elif job.max_runs and job.run_count >= job.max_runs:
                job.status = JobStatus.completed
            else:
                unit_sec = {"hours": 3600, "days": 86400, "weeks": 604800}
                job.next_run_at = datetime.now(timezone.utc) + timedelta(
                    seconds=(job.interval_value or 1) * unit_sec.get(job.interval_unit or "days", 86400)
                )
            db2.commit()
        finally:
            db2.close()

    async def _restore_jobs(self):
        """Re-register active jobs from DB on server restart."""
        db = SessionLocal()
        try:
            jobs = db.query(ScheduledJob).filter(
                ScheduledJob.status == JobStatus.active
            ).all()
            for j in jobs:
                if j.job_type == JobType.scheduled and j.run_at:
                    if j.run_at > datetime.now(timezone.utc):
                        self._schedule_job(j.id, "scheduled", run_at=j.run_at)
                elif j.job_type == JobType.frequency:
                    self._schedule_job(j.id, "frequency",
                                       interval_value=j.interval_value,
                                       interval_unit=j.interval_unit,
                                       start_date=j.next_run_at or datetime.now(timezone.utc))
        finally:
            db.close()


scheduler = SchedulerService()
