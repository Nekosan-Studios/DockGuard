from datetime import datetime, timezone
from typing import Optional
from sqlmodel import Field, Relationship, SQLModel


class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scanned_at: datetime
    image_name: str          # full image_ref, e.g. "nginx:latest"
    image_repository: str    # name without tag, e.g. "nginx" or "ghcr.io/owner/repo"
    image_digest: str
    grype_version: str
    db_built: Optional[datetime] = None
    distro_name: Optional[str] = None
    distro_version: Optional[str] = None
    is_distro_eol: bool = Field(default=False)
    container_name: Optional[str] = None
    vex_status: Optional[str] = None  # "found", "none", "error", "unchecked"
    vex_source: Optional[str] = None
    vex_checked_at: Optional[datetime] = None

    vulnerabilities: list["Vulnerability"] = Relationship(back_populates="scan")


class Vulnerability(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")

    vuln_id: str
    severity: str
    description: Optional[str] = None
    data_source: Optional[str] = None
    urls: Optional[str] = None  # comma-separated

    cvss_base_score: Optional[float] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    is_kev: bool = False
    risk_score: Optional[float] = None
    cwes: Optional[str] = None  # comma-separated

    package_name: str
    installed_version: str
    fixed_version: Optional[str] = None
    fix_state: Optional[str] = None
    package_type: Optional[str] = None
    package_language: Optional[str] = None
    purl: Optional[str] = None
    locations: Optional[str] = None  # newline-separated file paths
    first_seen_at: Optional[datetime] = None
    vex_status: Optional[str] = None        # "not_affected", "affected", "fixed", "under_investigation"
    vex_justification: Optional[str] = None
    vex_statement: Optional[str] = None

    scan: Optional[Scan] = Relationship(back_populates="vulnerabilities")


class AppState(SQLModel, table=True):
    """Single-row table (id=1) for app-wide persistent state."""
    id: int = Field(default=1, primary_key=True)
    last_db_checked_at: Optional[datetime] = None
    grype_version: Optional[str] = None
    db_schema: Optional[str] = None
    db_built: Optional[datetime] = None

class Setting(SQLModel, table=True):
    key: str = Field(primary_key=True)
    value: str
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SystemTask(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    task_type: str       # e.g., "scan", "scheduled_check_containers", "scheduled_db_update"
    task_name: str       # e.g., "Scan nginx:latest", "Monitor Containers"
    status: str          # "queued", "running", "completed", "failed"
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error_message: Optional[str] = None
    result_details: Optional[str] = None  # Generic info (e.g. "Found 3 new containers")
