# VEX Integration — Implementation Results

**Date:** 2026-03-07
**Branch:** gen-fixes

## Summary

VEX (Vulnerability Exploitability eXchange) integration has been implemented end-to-end. DockGuard now automatically checks OCI registries for VEX attestations after each scan and surfaces the results in the UI.

## Files Changed

### Backend

| File | Change |
|------|--------|
| `backend/models.py` | Added VEX fields to `Scan` (vex_status, vex_source, vex_checked_at) and `Vulnerability` (vex_status, vex_justification, vex_statement) |
| `backend/vex_discovery.py` | **New** — OCI Referrers API client for VEX discovery. Parses OpenVEX documents, handles auth, fallback tag scheme, and timeouts |
| `backend/scheduler.py` | Added `_check_vex_for_latest_scan()` method, called after each successful scan in `_scan_image_sync()` |
| `backend/api.py` | Added `has_vex` to scan/container responses, `vex_suppressed` report filter, updated report description |
| `backend/alembic/versions/6672a2a27dc7_add_vex_fields.py` | **New** migration — adds 6 VEX columns to scan and vulnerability tables |
| `pyproject.toml` | Added `httpx` to production dependencies |

### Frontend

| File | Change |
|------|--------|
| `frontend/src/lib/components/vuln/VexStatusCell.svelte` | **New** component — renders VEX status with icon + tooltip (green shield-check for not_affected, red alert for affected, amber clock for under_investigation, blue shield for fixed) |
| `frontend/src/routes/vulnerabilities/+page.svelte` | Conditional VEX column (only shown when data exists), VEX: Not Affected report option, VEX fields on Vulnerability interface |
| `frontend/src/routes/containers/+page.svelte` | Blue "VEX" badge on containers with VEX data, conditional VEX column in sub-table |

### Tests

| File | Tests |
|------|-------|
| `backend/tests/test_vex_discovery.py` | **New** — 18 tests covering image ref parsing, artifact type detection, OpenVEX parsing, full discovery flow (mocked HTTP), error handling |

## How It Works

1. **After each Grype scan**, the scheduler calls `check_vex_for_image()` with the image name and digest
2. The module queries the OCI Referrers API (`GET /v2/<repo>/referrers/<digest>`) on the image's registry
3. If the API returns 404, it falls back to the referrers tag scheme
4. Referrer artifacts are filtered for VEX-related media/artifact types
5. VEX documents are fetched, parsed as OpenVEX, and statements matched to vulnerability rows by CVE ID
6. The scan's `vex_status` is set to "found", "none", or "error"
7. Matching vulnerability rows get `vex_status`, `vex_justification`, and `vex_statement` updated

## UI Behavior

- **No VEX data (most images today):** Zero noise — no VEX column visible anywhere
- **VEX data present:** Column appears automatically, showing status per vulnerability
- **Container cards:** Blue "VEX" badge appears next to the image name
- **Report filter:** New "VEX: Not Affected" option shows all supplier-suppressed vulnerabilities

## Test Results

```
87 passed, 1 deselected, 1 warning in 12.42s
```

All existing tests pass. No regressions.

## What's NOT Included (Future Work)

- User-driven suppress/acknowledge — separate feature
- Publishing VEX for our own DockGuard image
- VEX Hub integration (Trivy-specific)
- Passing VEX files to `grype --vex` during scan
