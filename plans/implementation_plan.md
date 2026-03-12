# Priority Badge Redesign — Phased Plan

## Goal

Replace CVSS-based severity labels with risk-score/KEV-based **Priority** across the entire UI. The priority buckets:

| Priority | Condition | Color |
|---|---|---|
| **Urgent** | `is_kev = true` | Red |
| **High** | risk score ≥ 6 | Orange |
| **Medium** | risk score ≥ 2 | Amber |
| **Low** | risk score < 2 | Muted blue |

---

## Full Inventory of Severity Touchpoints

### Backend
1. **[containers.py](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/routers/containers.py)** — `critical_count` stat, [critical](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/routers/vulnerabilities.py#157-174) trend data, `vulns_by_severity` in recent activity + running containers
2. **[vulnerabilities.py](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/routers/vulnerabilities.py)** — `report == "critical"` filter, `?severity=Critical` param, `severity` sort/grouping
3. **`api_helpers.py`** — `_severity_rank()` used for sort ordering

### Frontend
1. **Dashboard** ([+page.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/routes/+page.svelte)) — "Critical Vulnerabilities" stat card, 30-day trend chart, recent activity pills
2. **Vulnerabilities page** — "Critical Vulnerabilities" report type, "Severity" column header + default sort
3. **Containers page** — ContainerRow severity pills (interactive filters), SEVERITY_ORDER, "Severity" subview column header
4. **[SeverityCell.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/lib/components/vuln/SeverityCell.svelte)** — row-level pill
5. **[utils.ts](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/lib/components/vuln/utils.ts)** — `SEVERITY_CLASSES`, [riskScoreTooltip](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/lib/components/vuln/utils.ts#40-43)

---

## Phased Approach

### Phase 1: Foundation + Row-Level Pills
*Frontend only, no backend changes.*

**Files:**
- **[utils.ts](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/lib/components/vuln/utils.ts)** — Add `PRIORITY_CLASSES`, `PRIORITY_ORDER`, `priorityFromVuln(riskScore, isKev)` function
- **[SeverityCell.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/lib/components/vuln/SeverityCell.svelte)** → Rename to **`PriorityCell.svelte`** — pill now shows priority label + color from `priorityFromVuln()`, with risk score sub-label. Tooltip explains the buckets.
- **[VulnRow.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/lib/components/vuln/VulnRow.svelte)** — Pass `isKev` to PriorityCell, update column header "Severity" → "Priority"
- **Vulnerabilities page** ([+page.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/routes/+page.svelte)) — Column header "Severity" → "Priority"
- **ContainerRow.svelte** — Column header "Severity" → "Priority" in the sub-table

---

### Phase 2: Container-Level Pills + Backend Priority Filter
*Container pills switch from severity to priority. Requires backend changes.*

**Backend:**
- **[containers.py](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/routers/containers.py)** — Add `vulns_by_priority` to `/running-containers` response (computed from risk_score + is_kev for each vuln in latest scan). Keep `vulns_by_severity` for backward compat during transition.
- **[vulnerabilities.py](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/routers/vulnerabilities.py)** — Add `?priority=Urgent|High|Medium|Low` param to `/images/vulnerabilities` for the pill-filter interactions

**Frontend:**
- **[ContainerRow.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/lib/components/vuln/ContainerRow.svelte)** — Replace `SEVERITY_ORDER` → `PRIORITY_ORDER`, `SEVERITY_CLASSES` → `PRIORITY_CLASSES`, `vulns_by_severity` → `vulns_by_priority`, filter sends `priority=` instead of `severity=`

---

### Phase 3: Dashboard
*Stat card, trend chart, and recent activity switch to priority.*

**Backend:**
- **[containers.py](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/routers/containers.py)** — Replace `critical_count` with `urgent_count` (KEV-based). Trend data switches from [critical](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/routers/vulnerabilities.py#157-174) to `urgent` (history starts fresh — acceptable).
- **[containers.py](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/routers/containers.py)** — `/activity/recent` response adds `vulns_by_priority` alongside `vulns_by_severity`

**Frontend:**
- **Dashboard [+page.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/routes/+page.svelte)**:
  - Stat card: "Critical Vulnerabilities" → "Urgent Priority" (links to `/vulnerabilities?report=urgent`)
  - Trend chart: "Critical Vulnerabilities — 30-Day Trend" → "Urgent Priority — 30-Day Trend", key changes from [critical](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/routers/vulnerabilities.py#157-174) → `urgent`
  - Recent activity table: pills switch from `SEVERITY_CLASSES` → `PRIORITY_CLASSES`, read `vulns_by_priority`

---

### Phase 4: Vulnerability Reports
*Report types aligned with priority model.*

**Backend:**
- **[vulnerabilities.py](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/routers/vulnerabilities.py)** — Add `report=urgent` type: `WHERE is_kev = True` (same as `kev` report but with the priority label framing — or we merge them). Consider whether [critical](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/routers/vulnerabilities.py#157-174) report stays as a legacy option or gets removed.

**Frontend:**
- **Vulnerabilities [+page.svelte](file:///Users/mattweinecke/Documents/GitHub/DockGuard/frontend/src/routes/+page.svelte)**:
  - Report dropdown: replace "Critical Vulnerabilities" → "Urgent Priority" (value: `urgent`)
  - Default report changes from [critical](file:///Users/mattweinecke/Documents/GitHub/DockGuard/backend/routers/vulnerabilities.py#157-174) → `urgent`
  - Dashboard card link changes from `?report=critical` → `?report=urgent`

> [!IMPORTANT]
> **Question:** The "Urgent" report and the existing "Actively Exploited (KEV)" report would now be identical (both = KEV). Should we:
> - **(A)** Merge them into one "Urgent Priority" report (removes KEV as a separate entry)
> - **(B)** Keep "Urgent Priority" as the default and keep "KEV" as a separate explicit report
> - **(C)** Make "Urgent Priority" include both KEV *and* risk score ≥ 6 (so it's Urgent + High)?
> 
> My lean: **(A)** — merge them. The KEV card on the dashboard already gives the "actively exploited" framing, and having two identical reports is confusing. The report dropdown becomes: `All | Urgent Priority | Newly Found | VEX Annotated`.

---

## Verification Plan

Per-phase:
```bash
uv run pytest -v
cd frontend && npm run lint && npm run check && npm run test:unit -- run
```

Plus visual verification in the running app after each phase.
