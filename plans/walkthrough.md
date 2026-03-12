# Priority Badge Redesign — Walkthrough

Replaced CVSS-based severity pills with risk-score-based **Priority** badges across the entire application.

## Priority Buckets

| Priority | Risk Score | Color |
|----------|-----------|-------|
| Urgent   | ≥ 8       | Red   |
| High     | ≥ 5       | Orange|
| Medium   | ≥ 2       | Amber |
| Low      | < 2       | Blue  |

## Changes by Phase

### Phase 1: Foundation + Row-Level Pills
- Created [PriorityCell.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/lib/components/vuln/PriorityCell.svelte) — replaces [SeverityCell.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/lib/components/vuln/SeverityCell.svelte)
- Added [priorityFromRiskScore()](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/lib/components/vuln/utils.ts#66-73), `PRIORITY_ORDER`, `PRIORITY_CLASSES` to [utils.ts](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/lib/components/vuln/utils.ts)
- Updated [VulnRow.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/lib/components/vuln/VulnRow.svelte) to use `PriorityCell`
- Column headers in [vulnerabilities/+page.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/routes/vulnerabilities/+page.svelte) and [ContainerRow.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/lib/components/vuln/ContainerRow.svelte) → "Priority"

### Phase 2: Container Pills + Backend Priority Filter
- Backend: Added [_priority_bucket()](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/api_helpers.py#33-43) to [api_helpers.py](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/api_helpers.py), `vulns_by_priority` to `/containers/running`, `?priority=` filter to `/images/vulnerabilities`
- Frontend: Container-level pills in [ContainerRow.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/lib/components/vuln/ContainerRow.svelte) switched from severity to priority; parent sort in [containers/+page.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/routes/containers/+page.svelte) updated

### Phase 3: Dashboard
- Backend: `critical_count` → `urgent_count` (risk_score ≥ 8), trend chart key [critical](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/routers/vulnerabilities.py#168-185) → `urgent`, `vulns_by_priority` added to `/activity/recent` in [containers.py](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/routers/containers.py)
- Frontend: Stat card → "Urgent Priority", trend chart → "Urgent Priority — 30-Day Trend", recent activity pills → priority badges in [+page.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/routes/+page.svelte)

### Phase 4: Vulnerability Reports
- Backend: Added `report=urgent` (risk_score ≥ 8) to [vulnerabilities.py](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/routers/vulnerabilities.py)
- Frontend: Report dropdown default changed from "Critical Vulnerabilities" → "Urgent Priority"; dashboard link points to `?report=urgent`

## Verification

| Check | Result |
|-------|--------|
| Frontend unit tests | 10 files, 59 tests ✅ |
| Frontend lint (ESLint) | Clean ✅ |
| Frontend type-check (svelte-check) | 0 errors ✅ |
| Backend unit tests | 162 passed ✅ |

> [!NOTE]
> The `critical_count` field is still returned in the API for backward compatibility but now reflects urgent priority (risk_score ≥ 8) rather than CVSS severity.
