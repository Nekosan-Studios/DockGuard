# Plan: Fix Dashboard Performance Issues

## Context

The recent "dashboard love" commit (02daa5d, Mar 3 2026) introduced a new `/dashboard/summary` endpoint and enhanced several others. While it consolidated multiple frontend API calls into one, the backend implementations have severe N+1 query patterns that cause slow page loads. Every dashboard request now triggers dozens of individual database queries that can each be collapsed into one or two efficient queries.

---

## Issues Identified

### 1. N+1 in `/dashboard/summary` — critical/KEV counts (api.py:262–276)
For each running image: 1 scan lookup + 1 critical count + 1 KEV count = **3 queries × N images**.

### 2. N+1 in `/dashboard/summary` — 30-day trend (api.py:289–299)
For each scan in the deduped `day_image_scan` dict: 1 critical count query = up to **30 days × M images queries**.

### 3. Missing `.limit(1)` on latest scan lookup (api.py:302)
`select(Scan).order_by(Scan.scanned_at.desc()).first()` loads all rows ordered before Python takes the first. Should use `.limit(1)`.

### 4. N+1 in `/activity/recent` (api.py:332–348)
For each of the 5 recent scans: 1 severity-breakdown query = **5 extra queries**.

### 5. N+1 in `/containers/running` (api.py:204–239)
For each running container: 1 scan lookup + 1 severity breakdown = **2 queries × N containers**.

### 6. Missing database indexes (models.py / alembic)
No indexes on `scan.image_name`, `scan.scanned_at`, `vulnerability.severity`, or `vulnerability.is_kev`. These columns appear in nearly every WHERE/ORDER BY clause.

---

## Implementation Plan

### File: `backend/api.py`

**Fix 1 — Dashboard critical/KEV counts (replace lines 260–276)**

Use a subquery to find the latest scan ID per running image, then one aggregation query using `CASE`/`SUM` to count both critical and KEV in a single round-trip:

```python
from sqlalchemy import case as sa_case

if running_images:
    latest_scan_id_subq = (
        select(func.max(Scan.id))
        .where(Scan.image_name.in_(running_images))
        .group_by(Scan.image_name)
    )
    row = session.exec(
        select(
            func.coalesce(func.sum(sa_case((Vulnerability.severity == "Critical", 1), else_=0)), 0),
            func.coalesce(func.sum(sa_case((Vulnerability.is_kev == True, 1), else_=0)), 0),
        ).where(Vulnerability.scan_id.in_(latest_scan_id_subq))
    ).one()
    critical_count, kev_count = row[0], row[1]
else:
    critical_count, kev_count = 0, 0
```
Result: **3N queries → 1 query** (for any N).

**Fix 2 — Dashboard 30-day trend (replace lines 289–299)**

After building `day_image_scan`, collect the relevant scan IDs and fetch ALL critical counts in one query, then do the per-day summation in Python:

```python
trend_scan_ids = [s.id for day_scans in day_image_scan.values() for s in day_scans.values()]
if trend_scan_ids:
    crit_rows = session.exec(
        select(Vulnerability.scan_id, func.count(Vulnerability.id))
        .where(Vulnerability.scan_id.in_(trend_scan_ids))
        .where(Vulnerability.severity == "Critical")
        .group_by(Vulnerability.scan_id)
    ).all()
    critical_by_scan = dict(crit_rows)
else:
    critical_by_scan = {}

trend = [
    {"date": day, "critical": sum(critical_by_scan.get(s.id, 0) for s in day_image_scan[day].values())}
    for day in sorted(day_image_scan.keys())
]
```
Result: **D×M queries → 1 query** (for any D days, M images).

**Fix 3 — Latest scan lookup (api.py:302)**

```python
# Before:
latest_scan = session.exec(select(Scan).order_by(Scan.scanned_at.desc())).first()
# After:
latest_scan = session.exec(select(Scan).order_by(Scan.scanned_at.desc()).limit(1)).first()
```

**Fix 4 — Recent activity severity breakdown (replace lines 332–348)**

Batch the severity queries into one after fetching the scans:

```python
scans = session.exec(select(Scan).order_by(Scan.scanned_at.desc()).limit(limit)).all()
scan_ids = [s.id for s in scans]
severity_by_scan: dict[int, dict[str, int]] = defaultdict(dict)
if scan_ids:
    for scan_id, severity, cnt in session.exec(
        select(Vulnerability.scan_id, Vulnerability.severity, func.count(Vulnerability.id))
        .where(Vulnerability.scan_id.in_(scan_ids))
        .group_by(Vulnerability.scan_id, Vulnerability.severity)
    ).all():
        severity_by_scan[scan_id][severity] = cnt

result = []
for scan in scans:
    vulns_by_severity = severity_by_scan.get(scan.id, {})
    result.append({..., "vulns_by_severity": vulns_by_severity, "total": sum(vulns_by_severity.values())})
```
Result: **N+1 queries → 2 queries** (always, regardless of limit).

**Fix 5 — Running containers severity breakdown (replace lines 204–239)**

1. Collect all running image names, get latest scan ID per image in one query.
2. Load those scans in one query.
3. Load severity breakdowns for all scan IDs in one query.

```python
running = watcher.list_running_containers()
if not running:
    return {"containers": []}

image_names = [img["image_name"] for img in running]
latest_scan_id_subq = (
    select(func.max(Scan.id))
    .where(Scan.image_name.in_(image_names))
    .group_by(Scan.image_name)
)
scans_by_image = {
    s.image_name: s
    for s in session.exec(select(Scan).where(Scan.id.in_(latest_scan_id_subq))).all()
}
scan_ids = [s.id for s in scans_by_image.values()]
severity_by_scan: dict[int, dict[str, int]] = defaultdict(dict)
if scan_ids:
    for scan_id, severity, cnt in session.exec(
        select(Vulnerability.scan_id, Vulnerability.severity, func.count(Vulnerability.id))
        .where(Vulnerability.scan_id.in_(scan_ids))
        .group_by(Vulnerability.scan_id, Vulnerability.severity)
    ).all():
        severity_by_scan[scan_id][severity] = cnt

containers = []
for img in running:
    scan = scans_by_image.get(img["image_name"])
    if not scan:
        containers.append({..., "has_scan": False})
        continue
    vulns_by_severity = severity_by_scan.get(scan.id, {})
    containers.append({..., "has_scan": True})
```
Result: **2N queries → 3 queries** (always, regardless of N).

### File: new Alembic migration

Create `backend/alembic/versions/<hash>_add_performance_indexes.py` with the following indexes:

| Index name | Table | Column(s) | Rationale |
|---|---|---|---|
| `ix_scan_image_name` | scan | image_name | `_latest_scan_for_ref`, dashboard loops |
| `ix_scan_scanned_at` | scan | scanned_at | trend query, latest scan lookup, ORDER BY |
| `ix_vulnerability_scan_id_severity` | vulnerability | (scan_id, severity) | every severity count/filter query |
| `ix_vulnerability_scan_id_is_kev` | vulnerability | (scan_id, is_kev) | KEV count query |

Use `op.create_index` / `op.drop_index` for upgrade/downgrade.

---

## Critical Files

- `backend/api.py` — all query changes (lines 204–239, 260–299, 302, 322–350)
- `backend/alembic/versions/` — new migration file to add indexes
- `backend/models.py` — read-only reference; no changes needed

## Verification

1. Start the app and navigate to the dashboard — it should load noticeably faster.
2. Enable SQLite query logging (or add a timer) and confirm the `/dashboard/summary` endpoint makes ~4 total DB queries instead of 30+.
3. Run `curl http://localhost:8000/dashboard/summary` and `curl http://localhost:8000/activity/recent` — confirm correct JSON is returned.
4. Run `curl http://localhost:8000/containers/running` — confirm per-container severity data is correct.
5. Verify the migration applies cleanly: `alembic upgrade head` should create all 4 indexes without error.
