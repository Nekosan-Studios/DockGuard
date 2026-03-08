# VEX Integration for DockGuard

## Context

VEX (Vulnerability Exploitability eXchange) lets software suppliers formally declare whether a vulnerability in their image actually affects users. Most images don't publish VEX today, but adoption is growing. By surfacing VEX data in DockGuard, we:
1. Automatically reduce false-positive noise for images that do publish VEX
2. Raise user awareness of VEX (and its absence), potentially driving adoption
3. Position DockGuard as VEX-aware, which is a differentiator for a home lab tool

This plan implements two features:
- **VEX Discovery**: Check if scanned images have VEX attestations in their OCI registry
- **VEX-Aware UI**: Surface VEX status in vulnerability views with appropriate subtlety

## How VEX Discovery Works (No cosign needed)

OCI registries support a **Referrers API** (`GET /v2/<repo>/referrers/<digest>`) that returns a list of artifacts (attestations, SBOMs, signatures) attached to an image. We query this API directly via HTTP — no cosign binary required.

**Flow:**
1. After a scan completes, we know the `image_name` and `image_digest`
2. Query the registry's referrers endpoint for that digest
3. Filter for artifacts with `artifactType` matching OpenVEX (`application/vex+json` or sigstore attestation predicates)
4. If found, download the VEX document and parse the statements
5. Match VEX statements to vulnerability rows by CVE ID
6. Store VEX metadata on the Scan (has_vex) and apply status to matching Vulnerability rows

**Fallback:** If referrers API returns 404, try the referrers tag scheme (`<repo>:sha256-<digest>`). If neither works, mark the scan as "VEX checked, none found."

**Registry auth:** Use credentials from the Docker daemon config (`~/.docker/config.json`), which is available inside the container via the Docker socket mount. The Docker SDK can provide auth tokens.

## Implementation Plan

### 1. Database Schema Changes

**File:** `backend/models.py`

Add to `Scan`:
```python
vex_status: Optional[str] = None  # "found", "none", "error", "unchecked"
vex_source: Optional[str] = None  # URL or description of where VEX was found
vex_checked_at: Optional[datetime] = None
```

Add to `Vulnerability`:
```python
vex_status: Optional[str] = None        # "not_affected", "affected", "fixed", "under_investigation"
vex_justification: Optional[str] = None  # VEX justification enum value
vex_statement: Optional[str] = None      # Free-text status_notes from VEX doc
```

Generate Alembic migration:
```bash
uv run alembic -c backend/alembic.ini revision --autogenerate -m "add_vex_fields"
```

### 2. VEX Discovery Module

**New file:** `backend/vex_discovery.py`

```python
async def check_vex_for_image(image_name: str, image_digest: str) -> VexResult:
    """Check OCI registry for VEX attestations attached to an image.

    Returns VexResult with:
      - found: bool
      - statements: list of {vuln_id, status, justification, notes}
      - source: str (registry URL)
    """
```

**Implementation details:**
- Parse `image_name` to extract registry host and repository
- Resolve auth token from Docker daemon or registry defaults
- Call `GET /v2/<repo>/referrers/<digest>` with Accept header for OCI image index
- Filter manifests by `artifactType` containing "vex" or "openvex"
- If found, fetch the VEX blob, parse as OpenVEX JSON
- Extract statements with status/justification/notes per vulnerability
- Handle errors gracefully (timeout, auth failure, unsupported registry) — never fail the scan

**Timeout:** 10 second total timeout per image. VEX check is best-effort.

**Caching:** Store `vex_checked_at` on Scan. Don't re-check VEX for the same image digest if checked within the last 24 hours (configurable).

### 3. Scheduler Integration

**File:** `backend/scheduler.py`

In `_scan_image_sync()`, after `grype_scanner.scan_image()` succeeds:
1. Call `check_vex_for_image(image_name, image_digest)`
2. Update the `Scan` row with `vex_status`, `vex_source`, `vex_checked_at`
3. If VEX statements found, match by `vuln_id` and update `Vulnerability` rows with `vex_status`, `vex_justification`, `vex_statement`

This happens synchronously within the existing scan thread pool — adds minimal overhead (one HTTP call, usually a quick 404).

### 4. API Changes

**File:** `backend/api.py`

Modify `_serialise_vuln()` to include VEX fields in response:
```python
"vex_status": v.vex_status,
"vex_justification": v.vex_justification,
"vex_statement": v.vex_statement,
```

Add VEX summary to scan/container metadata responses:
```python
"has_vex": scan.vex_status == "found",
```

No new endpoints needed — VEX data piggybacks on existing vulnerability responses.

### 5. Frontend: VexStatusCell Component

**New file:** `frontend/src/lib/components/vuln/VexStatusCell.svelte`

Follow the `KevCell.svelte` pattern:
- If `vex_status` is null: render nothing (no column noise for images without VEX)
- If `vex_status == "not_affected"`: green shield-check icon with tooltip showing justification
- If `vex_status == "affected"`: red alert icon
- If `vex_status == "under_investigation"`: amber clock icon

Use a Tooltip (not Popover) for the justification — keeps it lightweight.

### 6. Frontend: Vulnerability Table Integration

**Files:**
- `frontend/src/routes/vulnerabilities/+page.svelte`
- `frontend/src/routes/containers/+page.svelte`

**Approach — minimal noise for the common case (no VEX):**

The VEX column only appears when at least one vulnerability in the current view has VEX data. This means:
- For most users today: no VEX column visible, zero noise
- When VEX data exists: column appears, showing status per row

**Implementation:**
- Derive `hasAnyVex` from the loaded rows: `rows.some(v => v.vex_status)`
- Conditionally render the VEX column header and cells only when `hasAnyVex` is true
- Column position: after KEV, before First Seen

### 7. Frontend: VEX Indicator on Container Cards

**File:** `frontend/src/routes/containers/+page.svelte`

When a container's image has VEX data (`has_vex` from API):
- Show a small "VEX" badge next to the image name (similar to the EOL badge)
- Tooltip: "This image includes VEX attestations from the supplier"
- Color: blue/info (not green — VEX existing doesn't mean all vulns are not_affected)

When no VEX: show nothing (not "No VEX" — that would be noise on every container).

### 8. Frontend: Report Filter

Add a new report option to the vulnerabilities page dropdown:
```
{ value: "vex_suppressed", label: "VEX: Not Affected" }
```

Backend filter in `/vulnerabilities`:
```python
elif report == "vex_suppressed":
    q = q.where(Vulnerability.vex_status == "not_affected")
```

This lets users see all vulns that the supplier says don't apply — useful for review and audit.

## Files to Modify

| File | Change |
|------|--------|
| `backend/models.py` | Add VEX fields to Scan and Vulnerability |
| `backend/vex_discovery.py` | **New** — OCI registry VEX lookup |
| `backend/scheduler.py` | Call VEX discovery after scan completes |
| `backend/api.py` | Serialize VEX fields, add vex_suppressed report filter |
| `backend/alembic/versions/` | **New** migration for VEX fields |
| `frontend/src/lib/components/vuln/VexStatusCell.svelte` | **New** component |
| `frontend/src/routes/vulnerabilities/+page.svelte` | Conditional VEX column, new report option |
| `frontend/src/routes/containers/+page.svelte` | VEX badge on container cards |

## Verification

1. **Unit test:** Mock OCI referrers API response with a sample OpenVEX document, verify `check_vex_for_image()` parses correctly
2. **Integration test:** Scan a Chainguard image (they publish VEX) and verify VEX data appears in the API response
3. **UI test:** With VEX data present, verify the VEX column appears in the vulnerability table
4. **UI test:** With no VEX data, verify no VEX column (zero noise)
5. **Error handling:** Test with private registry (auth), registry without referrers API (fallback), and timeout scenarios
6. **Run existing tests:** `uv run pytest -v` to ensure no regressions

## What This Does NOT Include (Future Work)

- User-driven suppress/acknowledge (Phase 1 from earlier brainstorm) — separate feature
- Publishing VEX for our own DockGuard image — separate CI/CD task
- VEX Hub integration — Trivy-specific, not available in Grype
- Passing VEX files to `grype --vex` during scan — unnecessary since we apply VEX post-scan to our own data
