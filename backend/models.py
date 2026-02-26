from datetime import datetime
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
    container_name: Optional[str] = None

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

    scan: Optional[Scan] = Relationship(back_populates="vulnerabilities")
