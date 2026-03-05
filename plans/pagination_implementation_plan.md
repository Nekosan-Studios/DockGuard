# Large Dataset Pagination

Replace the current approach (send all rows, render progressively) with server-side sorting and — for the "All Vulnerabilities" report specifically — cursor-based infinite scroll pagination. All other reports (Critical, KEV, New) continue to load fully if they return ≤ 1 000 rows; beyond that they also paginate.

---

## Proposed Changes

### Backend

#### [MODIFY] [api.py](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/api.py)

**`GET /vulnerabilities` — cursor-based pagination + server-side sort**

New query params (all optional):
| Param | Default | Notes |
|---|---|---|
| `sort_by` | `severity` | One of: `severity`, `cvss_base_score`, `epss_score`, `is_kev`, `first_seen_at`, `vuln_id`, `package_name` |
| `sort_dir` | `asc` | `asc` or `desc` |
| `limit` | `100` | Max 500 |
| `cursor` | `null` | Opaque base64-encoded string encoding the last row's sort-key + id |

Response shape changes:
```json
{
  "report": "all",
  "total_count": 4321,
  "count": 100,
  "next_cursor": "eyJzZXYiOiJIaWdoIiwiaWQiOjQ1Nn0=",
  "vulnerabilities": [...]
}
```

- `total_count` is the full result set size (one extra `COUNT(*)` query using the same filters, no limit).
- `next_cursor` is `null` when no more pages remain.
- The cursor encodes the last row's sort-column value + `id` so the next query can use `>` / `<` comparisons instead of `OFFSET` (immune to rows shifting between requests).
- Sorting is done entirely in SQL with `ORDER BY` + the cursor inequality predicate.

**`GET /images/vulnerabilities` — server-side sort + offset pagination**

New query params:
| Param | Default | Notes |
|---|---|---|
| `sort_by` | `severity` | Same allowed set as above |
| `sort_dir` | `asc` | `asc` or `desc` |
| `limit` | `200` | Max 500 |
| `offset` | `0` | Simple integer offset (safe: per-scan data is static during browsing) |

Response shape gains `total_count` and `has_more` fields:
```json
{
  "scan_id": 42,
  "scanned_at": "...",
  "total_count": 1850,
  "count": 200,
  "has_more": true,
  "vulnerabilities": [...]
}
```

Offset is used (not cursor) because the per-scan vulnerability set is static during a browsing session — there's no risk of row drift between pages.

**DB index migration**

Add an Alembic migration adding composite indexes on the `vulnerability` table:
- `(scan_id, severity, cvss_base_score, id)` — covers the default sort and cursor range scans
- `(scan_id, is_kev, id)` — covers KEV report
- `(scan_id, first_seen_at, id)` — covers new-24h report

#### [NEW] Alembic migration file (auto-generated name)

One migration adding the three composite indexes above.

---

### Frontend — Vulnerabilities Page

#### [MODIFY] [vulnerabilities/+page.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/routes/vulnerabilities/+page.svelte)

- **Remove** client-side sort state (`sortCol`, `sortDir`, `sortedVulnsList`), progressive-render batch state (`renderedVulns`, `pendingVulns`, `scheduleNextBatch`, `cancelPendingBatch`).
- **Add** `sort_by` / `sort_dir` URL search params. Column header clicks update the URL (via `goto`) and trigger a new fetch — resets to page 1.
- **Add** an `IntersectionObserver` on a sentinel `<div>` at the bottom of the table. When it becomes visible and `next_cursor` is non-null, fetch the next page and append rows.
- **Add** a "Showing N of M" indicator in the card header.
- **Remove** the loading spinner row that showed "Loading N more…" (replaced by a bottom sentinel spinner).
- The `data.vulnerabilities` array from `+page.server.ts` provides the first page. Subsequent pages are fetched client-side and appended to a local `rows` state array.
- When the report or sort changes, `rows` resets and the first page is re-fetched.

#### [MODIFY] [vulnerabilities/+page.server.ts](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/routes/vulnerabilities/+page.server.ts)

Pass `sort_by` and `sort_dir` from the URL to the backend API call. Return `total_count` and `next_cursor` alongside `vulnerabilities` and `count`.

---

### Frontend — Containers Page

#### [MODIFY] [containers/+page.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/routes/containers/+page.svelte)

**Core change: replace progressive batch rendering with offset-based infinite scroll within the expanded row.**

The fundamental issue: progressive rendering only staggers DOM creation — it doesn't limit total DOM nodes. A container with 2 000 Medium vulns still ends up with 2 000 `<tr>` rows in the DOM (each with Tooltip components and event listeners), which overwhelms the browser regardless of how slowly they're added.

Changes:
- **Remove** `scheduleNextBatch`, `cancelPendingBatch`, `pendingVulns`, `pendingCallbacks` — the entire progressive-render machinery.
- **Remove** `sortedVulns()` client-side sort — rows arrive sorted from server.
- **Add** `containerVulnsMeta` state map: `imageName → { totalCount, offset, hasMore, loading }`.
- `fetchVulns(imageName, severity?, offset=0)` always sends `limit=200&offset=N&sort_by=X&sort_dir=Y`. On offset=0 it replaces `containerVulns`; on offset>0 it appends.
- An **`IntersectionObserver`** on a sentinel `<div>` placed at the bottom of the expanded sub-table triggers `fetchVulns(imageName, severity, currentOffset + 200)` when `hasMore` is true.
- Column sort clicks call `fetchVulns` with new sort params, resetting offset to 0 (replacing `toggleVulnSort` → re-render).
- Show a "Showing N of M" note when M > N inside the expanded panel.
- The auto-filter-to-top-severity behavior on first expand is unchanged.
- The severity filter pill behavior (click to narrow/widen) still triggers a fresh `fetchVulns` call at offset=0.
- **Soft cap at 600 rows** (`SUBVIEW_MAX_ROWS = 600` named constant): once the accumulated `containerVulns` for an image reaches 600, the `IntersectionObserver` stops triggering further loads. A message replaces the loading sentinel: *"Showing 600 of M [Severity] vulnerabilities — use the severity filters above or sort by CVSS / EPSS to prioritize."* This refers only to controls already present in the UI.

> [!NOTE]
> Each "page" of 200 rows renders in a single synchronous pass — no batching needed. 200 rows with tooltips is well within browser comfort zone. The soft cap ensures the DOM never exceeds 600 rows per expanded container, regardless of how many the server has.

> [!TIP]
> When text search or CSV export are added in a future iteration, update the soft-cap message to mention them. Adjust `SUBVIEW_MAX_ROWS` as needed.

---

## Verification Plan

### Automated Tests

Run existing suite — all existing tests must still pass:
```bash
cd /Users/mattweinecke/Documents/GitHub/DockGuard
uv run pytest backend/tests/ -v
```

New tests to add in `backend/tests/test_api.py`:

**`GET /vulnerabilities` pagination tests:**
- `test_get_vulnerabilities_across_running_pagination_default` — verify default 100-row limit and presence of `total_count` / `next_cursor` in response.
- `test_get_vulnerabilities_across_running_cursor_paging` — seed 150 rows, fetch page 1 (100 rows), use `next_cursor` to fetch page 2 (50 rows), assert no duplication and total_count=150.
- `test_get_vulnerabilities_across_running_sort_by_cvss` — seed mixed-severity rows, request `sort_by=cvss_base_score&sort_dir=desc`, assert descending CVSS order in response.
- `test_get_vulnerabilities_across_running_invalid_sort_col` — request an unknown `sort_by` value, expect 422.

**`GET /images/vulnerabilities` pagination + sort tests:**
- `test_get_image_vulnerabilities_server_sort_by_severity` — seed 5 mixed vulns, request `sort_by=severity&sort_dir=asc`, assert severity ordering matches `SEVERITY_ORDER`.
- `test_get_image_vulnerabilities_sort_by_cvss_desc` — assert descending CVSS in response.
- `test_get_image_vulnerabilities_pagination_limit_offset` — seed 300 vulns, request `limit=200&offset=0`, assert `count=200`, `has_more=True`, `total_count=300`; then request `limit=200&offset=200`, assert `count=100`, `has_more=False`.
- `test_get_image_vulnerabilities_no_overlap_between_pages` — assert no vuln `id` appears on both page 1 and page 2.

### Manual Browser Verification

1. Run the app: `./dev.sh`
2. Open [http://localhost:5173/vulnerabilities?report=all](http://localhost:5173/vulnerabilities)
3. Verify the table loads with the first 100 rows and shows "Showing 100 of N" in the header
4. Scroll to the bottom — a spinner should appear briefly, then more rows should append
5. Continue scrolling to verify additional pages load until the table is exhausted (no more next_cursor)
6. Click a column sort header (e.g. CVSS) — verify the table resets and rows come back in the correct order
7. Switch report to "Critical Vulnerabilities" — verify rows are not paginated (if count ≤ 1000) and full data loads immediately
8. Open Containers page, expand a high-vuln container, verify the sub-view still loads correctly by severity filter
9. Click a sort header in the sub-view (e.g. Package) — verify rows re-order via a new server fetch (no JS sort)
