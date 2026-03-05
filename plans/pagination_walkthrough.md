# Large Dataset Pagination — Implementation Walkthrough

## What Was Built

Replaced the previous approach (send all rows, render progressively in the browser) with server-side sorting and bounded pagination across both vulnerability views.

---

## Changes Overview

### Backend

#### New Alembic Migration
[f1a2b3c4d5e6_add_pagination_sort_indexes.py](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/alembic/versions/f1a2b3c4d5e6_add_pagination_sort_indexes.py)

Added three composite indexes on the `vulnerability` table:
- `(scan_id, cvss_base_score, id)` — pagination sort by CVSS
- `(scan_id, epss_score, id)` — pagination sort by EPSS
- `(scan_id, first_seen_at, id)` — pagination sort by first seen date

#### `GET /vulnerabilities` (cross-container "All" report)
[api.py](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/api.py)

New query params: `sort_by`, `sort_dir`, `limit` (default 100), `offset` (default 0).

Response now includes `total_count`, `has_more`, and `count` alongside `vulnerabilities`.

Sorting happens in Python after the cross-container grouping step (required since grouping is inherently Python-side). Pagination is applied as a Python slice on the sorted grouped list.

#### `GET /images/vulnerabilities` (per-image/container sub-view)

New query params: `sort_by`, `sort_dir`, `limit` (default 200), `offset` (default 0).

Response now includes `total_count`, `has_more`, `count`. SQL `ORDER BY` is used for non-severity sorts; severity sort is Python-side (non-lexicographic order).

---

### Frontend

#### Vulnerabilities Page (`/vulnerabilities`)
[+page.server.ts](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/routes/vulnerabilities/+page.server.ts) — passes `sort_by`, `sort_dir`, `limit=100`, `offset=0` to backend; returns `total_count` and `has_more`.

[+page.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/routes/vulnerabilities/+page.svelte) — rewrote from scratch:
- **Removed** all client-side sort state and progressive batch rendering
- **Added** `sort_by`/`sort_dir` as URL search params; column header clicks call `goto()` to navigate, triggering a SvelteKit re-load with the new sort (first page only, server-rendered)
- **Added** `IntersectionObserver` on a sentinel `<div>` at the bottom of the table; triggers `fetch` of the next 100-row page via `/api/vulnerabilities-paged` proxy, appending to a local `rows` array
- **Added** "Showing N of M vulnerabilities" to the card description

#### New API Proxy Route
[/api/vulnerabilities-paged/+server.ts](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/routes/api/vulnerabilities-paged/+server.ts) — forwards all query params to the backend `GET /vulnerabilities` endpoint (used by client-side infinite scroll fetches).

#### Containers Page (`/containers`)
[+page.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/routes/containers/+page.svelte) — major script refactor:
- **Removed**: `scheduleNextBatch`, `cancelPendingBatch`, `pendingVulns`, `pendingCallbacks`, `sortedVulns()`, `VulnSort` interface, `vulnSortStates` map
- **Added**: `containerVulnsMeta` SvelteMap tracking `{ totalCount, offset, hasMore, loadingMore, sortCol, sortDir }` per expanded image
- **Changed**: `fetchVulns()` now accepts `offset`, `sortCol`, `sortDir` params; sends `limit=200&offset=N&sort_by=X&sort_dir=Y` to the API; on `offset=0` replaces rows, on `offset>0` appends
- **Added**: MutationObserver + IntersectionObserver machinery that detects `data-sentinel` divs appearing in the DOM as Svelte renders them, and automatically triggers the next page fetch
- **Soft cap at 600 rows** (`SUBVIEW_MAX_ROWS = 600`): once 600 rows are accumulated, `hasMore` is forced false. A message replaces the loading sentinel: *"Showing 600 of M vulnerabilities — use the severity filters above or sort by CVSS / EPSS to prioritize."*
- **Added**: "Showing N of M" note appears when total > page size but soft cap has not been hit

Column sort header clicks now call `fetchVulns` at `offset=0` with new sort params (replaces JS re-sort), triggering a real re-fetch from the server.

Updated [/api/vulnerabilities/+server.ts](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/routes/api/vulnerabilities/+server.ts) to forward all query params (including new sort/pagination ones) to the backend.

---

## Verification

### Test Suite

```
63 passed, 1 deselected, 0 failed in 13.02s
```

All 63 existing tests pass unchanged — the new pagination fields (`total_count`, `has_more`) are additive and don't break any existing assertions.

### Alembic Migration

```
INFO Running upgrade 85896e7c6488 -> f1a2b3c4d5e6, add pagination sort indexes
```

Migration runs cleanly. Three new composite indexes created.

---

## UX Summary

| Scenario | Before | After |
|---|---|---|
| 3,000-vuln "All Vulnerabilities" | Loads entire 3,000-row JSON, massive render lag | First 100 rows load immediately; scroll loads 100 more at a time |
| Sort by CVSS | Client JS re-sorts existing rows | URL param change → server re-fetches first 100 sorted rows, IntersectionObserver loads more |
| Container with 3,000 Medium vulns | Progressive DOM batching—all 3,000 rows eventually in DOM | 200 rows on expand, scroll adds 200 more up to 600 max; soft-cap message shown |
| Soft cap hit | N/A | "Showing 600 of 3,000 vulnerabilities — use severity filters or sort by CVSS/EPSS to prioritize." |
