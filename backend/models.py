from datetime import UTC, datetime

from sqlmodel import Field, Relationship, SQLModel


class Scan(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    scanned_at: datetime
    image_name: str  # full image_ref, e.g. "nginx:latest"
    image_repository: str  # name without tag, e.g. "nginx" or "ghcr.io/owner/repo"
    image_digest: str
    grype_version: str
    db_built: datetime | None = None
    distro_name: str | None = None
    distro_version: str | None = None
    is_distro_eol: bool = Field(default=False)
    container_name: str | None = None
    vex_status: str | None = None  # "found", "none", "error", "unchecked"
    vex_source: str | None = None
    vex_checked_at: datetime | None = None
    vex_error: str | None = None

    vulnerabilities: list["Vulnerability"] = Relationship(back_populates="scan")


class Vulnerability(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")

    vuln_id: str
    severity: str
    description: str | None = None
    data_source: str | None = None
    urls: str | None = None  # comma-separated
    urls_titles: str | None = None  # JSON object mapping URL -> title

    cvss_base_score: float | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    is_kev: bool = False
    risk_score: float | None = None
    cwes: str | None = None  # comma-separated
    cwe_titles: str | None = None  # JSON object mapping CWE ID -> definition name

    package_name: str
    installed_version: str
    fixed_version: str | None = None
    fix_state: str | None = None
    package_type: str | None = None
    package_language: str | None = None
    purl: str | None = None
    locations: str | None = None  # newline-separated file paths
    first_seen_at: datetime | None = None
    vex_status: str | None = None  # "not_affected", "affected", "fixed", "under_investigation"
    vex_justification: str | None = None
    vex_statement: str | None = None
    match_type: str | None = None  # "exact-direct-match" | "exact-indirect-match"
    upstream_name: str | None = None  # source package name for indirect matches (e.g. "gnutls28")
    cvss_vector: str | None = None  # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"

    scan: Scan | None = Relationship(back_populates="vulnerabilities")


class NotificationChannel(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str
    apprise_url: str
    enabled: bool = True
    notify_urgent: bool = False
    notify_all_new: bool = False
    notify_digest: bool = False
    notify_kev: bool = False
    notify_eol: bool = False
    notify_scan_failure: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class NotificationLog(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    channel_id: int = Field(foreign_key="notificationchannel.id")
    notification_type: str  # "urgent", "new_vulns", "digest", "eol", "scan_failure", "test"
    title: str
    body: str
    status: str  # "sent", "failed"
    error_message: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AppState(SQLModel, table=True):
    """Single-row table (id=1) for app-wide persistent state."""

    id: int = Field(default=1, primary_key=True)
    last_db_checked_at: datetime | None = None
    grype_version: str | None = None
    db_schema: str | None = None
    db_built: datetime | None = None
    last_digest_data: str | None = None


class Setting(SQLModel, table=True):
    key: str = Field(primary_key=True)
    value: str
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SystemTask(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    task_type: str  # e.g., "scan", "scheduled_check_containers", "scheduled_db_update"
    task_name: str  # e.g., "Scan nginx:latest", "Monitor Containers"
    status: str  # "queued", "running", "completed", "failed"
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_message: str | None = None
    result_details: str | None = None  # Generic info (e.g. "Found 3 new containers")
