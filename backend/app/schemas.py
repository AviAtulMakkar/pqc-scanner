"""
Pydantic v2 schemas — API request/response models.
Separate from SQLAlchemy models to keep layers clean.
"""

from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional, List, Any, Dict
from datetime import datetime
import re


# ── Auth ───────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username:  str       = Field(..., min_length=3, max_length=32)
    email:     EmailStr
    password:  str       = Field(..., min_length=8)
    full_name: str       = Field("", max_length=64)

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    user_id:      str
    username:     str
    email:        str
    is_admin:     bool

class UserOut(BaseModel):
    id:         str
    username:   str
    email:      str
    full_name:  str
    is_admin:   bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


# ── Scans ──────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    domain:             str   = Field(..., example="pnb.co.in")
    ports:              str   = Field("top", pattern="^(web|top)$")
    threads:            int   = Field(100, ge=10, le=300)
    include_subdomains: bool  = True

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, v):
        return re.sub(r"^https?://", "", v).strip("/").lower()

class ScanSummaryOut(BaseModel):
    id:           str
    domain:       str
    status:       str
    progress:     int
    started_at:   datetime
    completed_at: Optional[datetime]
    elapsed:      Optional[float]
    summary:      Dict[str, Any]

    class Config:
        from_attributes = True

class ScanDetailOut(ScanSummaryOut):
    events: List[Dict]
    hosts:  List[Dict]


# ── Reports ────────────────────────────────────────────────────

class OnDemandReportRequest(BaseModel):
    scan_id:      str
    format:       str        = Field("html", pattern="^(html|json|cbom)$")
    email_to:     List[str]  = []
    send_email:   bool       = False
    notes:        Optional[str] = None

class ScheduledReportRequest(BaseModel):
    domain:       str
    run_at:       datetime
    format:       str        = Field("html", pattern="^(html|json|cbom)$")
    label:        str        = ""
    email_to:     List[str]  = []
    send_email:   bool       = False
    ports:        str        = "top"

    @field_validator("domain")
    @classmethod
    def clean(cls, v):
        return re.sub(r"^https?://", "", v).strip("/").lower()

class FrequencyReportRequest(BaseModel):
    domain:         str
    interval_value: int      = Field(..., ge=1)
    interval_unit:  str      = Field(..., pattern="^(hours|days|weeks)$")
    format:         str      = Field("html", pattern="^(html|json|cbom)$")
    label:          str      = ""
    max_runs:       Optional[int] = None
    email_to:       List[str] = []
    send_email:     bool     = False
    ports:          str      = "top"

    @field_validator("domain")
    @classmethod
    def clean(cls, v):
        return re.sub(r"^https?://", "", v).strip("/").lower()

class ReportOut(BaseModel):
    id:          str
    scan_id:     Optional[str]
    report_type: str
    format:      str
    status:      str
    file_name:   Optional[str]
    email_status: Optional[str]
    emailed_to:  List[str]
    created_at:  datetime

    class Config:
        from_attributes = True


# ── Jobs ───────────────────────────────────────────────────────

class JobOut(BaseModel):
    id:             str
    label:          str
    job_type:       str
    status:         str
    domain:         str
    run_count:      int
    next_run_at:    Optional[datetime]
    last_run_at:    Optional[datetime]
    created_at:     datetime
    interval_value: Optional[int]
    interval_unit:  Optional[str]

    class Config:
        from_attributes = True
