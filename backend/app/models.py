"""
SQLAlchemy models — PostgreSQL schema for PQC Scanner platform.
Tables: users, scans, scan_hosts, scan_ports, scheduled_jobs, reports
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime,
    Text, JSON, ForeignKey, Enum as SAEnum, Index
)
from sqlalchemy.orm import relationship, declarative_base
import enum, uuid

Base = declarative_base()

def new_uuid():
    return str(uuid.uuid4())

def now_utc():
    return datetime.now(timezone.utc)


class ScanStatus(str, enum.Enum):
    queued   = "queued"
    running  = "running"
    complete = "complete"
    error    = "error"


class JobType(str, enum.Enum):
    scheduled = "scheduled"
    frequency = "frequency"


class JobStatus(str, enum.Enum):
    active    = "active"
    cancelled = "cancelled"
    completed = "completed"


class ReportFormat(str, enum.Enum):
    html = "html"
    json = "json"
    cbom = "cbom"
    pdf  = "pdf"


# ── Users ──────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id            = Column(String, primary_key=True, default=new_uuid)
    email         = Column(String, unique=True, nullable=False, index=True)
    username      = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    full_name     = Column(String, default="")
    is_active     = Column(Boolean, default=True)
    is_admin      = Column(Boolean, default=False)
    created_at    = Column(DateTime(timezone=True), default=now_utc)
    last_login    = Column(DateTime(timezone=True), nullable=True)

    scans  = relationship("Scan",  back_populates="user", cascade="all, delete-orphan")
    jobs   = relationship("ScheduledJob", back_populates="user", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="user", cascade="all, delete-orphan")


# ── Scans ──────────────────────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_user_domain", "user_id", "domain"),
        Index("ix_scans_started_at",  "started_at"),
    )

    id            = Column(String, primary_key=True, default=new_uuid)
    user_id       = Column(String, ForeignKey("users.id"), nullable=False)
    domain        = Column(String, nullable=False)
    status        = Column(SAEnum(ScanStatus), default=ScanStatus.queued)
    progress      = Column(Integer, default=0)
    message       = Column(Text, default="")
    ports_config  = Column(String, default="top")   # "web" or "top"
    threads       = Column(Integer, default=100)
    started_at    = Column(DateTime(timezone=True), default=now_utc)
    completed_at  = Column(DateTime(timezone=True), nullable=True)
    elapsed       = Column(Float, nullable=True)
    error_msg     = Column(Text, nullable=True)

    # Aggregated summary stored as JSON
    summary       = Column(JSON, default=dict)
    # Full scan events log
    events        = Column(JSON, default=list)

    user    = relationship("User",     back_populates="scans")
    hosts   = relationship("ScanHost", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report",   back_populates="scan")


class ScanHost(Base):
    __tablename__ = "scan_hosts"

    id         = Column(String, primary_key=True, default=new_uuid)
    scan_id    = Column(String, ForeignKey("scans.id"), nullable=False)
    hostname   = Column(String, nullable=False)
    ip         = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)

    # Full host data as JSON (ports, TLS, certs, PQC labels)
    data       = Column(JSON, default=dict)

    scan  = relationship("Scan",     back_populates="hosts")

    __table_args__ = (
        Index("ix_scan_hosts_scan_id", "scan_id"),
    )


# ── Scheduled Jobs ─────────────────────────────────────────────

class ScheduledJob(Base):
    __tablename__ = "scheduled_jobs"

    id             = Column(String, primary_key=True, default=new_uuid)
    user_id        = Column(String, ForeignKey("users.id"), nullable=False)
    label          = Column(String, default="")
    job_type       = Column(SAEnum(JobType), nullable=False)
    status         = Column(SAEnum(JobStatus), default=JobStatus.active)
    domain         = Column(String, nullable=False)
    ports_config   = Column(String, default="top")
    report_format  = Column(SAEnum(ReportFormat), default=ReportFormat.html)
    email_to       = Column(JSON, default=list)    # list of recipient emails
    send_email     = Column(Boolean, default=False)

    # Scheduled: run once at this time
    run_at         = Column(DateTime(timezone=True), nullable=True)
    # Frequency: interval
    interval_value = Column(Integer, nullable=True)
    interval_unit  = Column(String, nullable=True)   # hours/days/weeks
    max_runs       = Column(Integer, nullable=True)

    run_count      = Column(Integer, default=0)
    last_run_at    = Column(DateTime(timezone=True), nullable=True)
    next_run_at    = Column(DateTime(timezone=True), nullable=True)
    created_at     = Column(DateTime(timezone=True), default=now_utc)

    user = relationship("User", back_populates="jobs")


# ── Reports ────────────────────────────────────────────────────

class Report(Base):
    __tablename__ = "reports"

    id          = Column(String, primary_key=True, default=new_uuid)
    user_id     = Column(String, ForeignKey("users.id"), nullable=False)
    scan_id     = Column(String, ForeignKey("scans.id"), nullable=True)
    report_type = Column(String, default="on-demand")   # on-demand | scheduled | frequency
    format      = Column(SAEnum(ReportFormat), default=ReportFormat.html)
    status      = Column(String, default="generating")  # generating | ready | error
    file_path   = Column(String, nullable=True)
    file_name   = Column(String, nullable=True)
    emailed_to  = Column(JSON, default=list)
    email_status = Column(String, nullable=True)
    notes       = Column(Text, nullable=True)
    created_at  = Column(DateTime(timezone=True), default=now_utc)

    user = relationship("User", back_populates="reports")
    scan = relationship("Scan", back_populates="reports")

    __table_args__ = (
        Index("ix_reports_user_id", "user_id"),
    )
