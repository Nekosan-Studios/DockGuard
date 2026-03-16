# Scan Identity + New Semantics Rewrite — Implementation Blueprint

## Goal

Implement a clean, image-centric scan model while preserving a container-centric UX.

This rewrite unifies the meaning of **New** across the product:

- **New** = last-scan delta for the same `image_name` lineage.
- **First scan for a lineage** = all findings are New.
- No time-window semantics for New (remove 24h-based behavior).

Also split historical and current container scope consistently:

- **Scan-triggered history/alerts** use scan-time container membership.
- **Current dashboard/current-state views** use current running containers.

## Locked Product Decisions

1. Keep container-focused UX (show impact by containers).
2. Use image lineage identity (`image_name`) for comparison/history logic.
3. No migration cutoff logic; treat old scan ordering uniformly.
4. No DB wipe requirement for users.
5. Time-based “new in last N hours” view is out of scope for now.

## Data Model Contract

### Current issues

- `Scan.container_name` can only store one container even when many containers share an image.
- Historical queries and notifications currently mix image and container semantics.

### Target schema

- `Scan` remains the image-scan record.
- Add `ScanContainer` as scan-to-container membership:
  - `id` (pk)
  - `scan_id` (fk -> `scan.id`, indexed)
  - `container_name` (text, indexed)
  - unique constraint on (`scan_id`, `container_name`)

### Clean-break policy

- Remove use of `Scan.container_name` in all application logic.
- Keep `Scan.container_name` only temporarily if needed for migration safety, then remove in a follow-up migration once all code paths are switched.

## Migration Contract (No DB Reset)

### Migration steps

1. Create `scancontainer` table.
2. Backfill from legacy `scan.container_name`:
   - for each scan with non-null `container_name`, insert one `ScanContainer` row.
3. Recompute `Vulnerability.first_seen_at` using lineage key:
   - key = (`scan.image_name`, `vuln_id`, `package_name`, `installed_version`)
   - set to earliest `scan.scanned_at` where the key appears.

### Expected historical limitations

- Historical multi-container blast radius cannot be fully recovered before migration (legacy model stored at most one container per scan).
- Old notification logs remain as historical records and may reflect old semantics.

### User-facing migration message

- Existing database is preserved.
- “New” logic and first-seen lineage are corrected.
- Some old historical container impact counts may be incomplete.
- No action required by user; no data directory reset required.

## Scan Pipeline Contract

### Scheduler and polling

- Keep digest-based scan dedup behavior for scan triggering.
- Each poll cycle does two distinct operations:
  1. Queue scan tasks for newly seen/changed digests.
  2. Refresh container associations for all currently running containers against latest scan for each image lineage.

### Scan execution

- A scan task scans one image lineage/version (not one container instance).
- On scan completion:
  - persist `Scan` + vulnerabilities,
  - persist scan-time `ScanContainer` rows for all currently running containers using that image.

### Task wording changes

- Task names and result details should describe image scans and affected container counts.
- Avoid per-container scan task framing when multiple containers share one image.

## Canonical New Semantics Contract

### Definition

For scan `S_n` in lineage `L = image_name`:

- if `S_n` has no predecessor in `L`: all findings in `S_n` are New.
- else New = findings in `S_n` not present in `S_(n-1)` by key:
  - (`vuln_id`, `package_name`, `installed_version`)

### Required consistency

Apply this exact definition to all of:

- `report=new` API response,
- New pill/badge labeling in vulnerability rows,
- Dashboard New count,
- scan-triggered notifications (`notify_all_new`, urgent/kev subsets).

## API Contract Changes

### Endpoint-by-endpoint diff

#### 1) `GET /vulnerabilities`

**Request changes**

- `report=new` remains valid, but meaning changes to last-scan delta.
- `new_hours` is removed from backend behavior and from frontend query construction.

**Response changes**

- Add `is_new` boolean per grouped vulnerability row.
- Keep `containers` as current-running scope for this endpoint.
- Keep existing shape for `vulnerabilities`, `total_count`, `total_instances`, `has_more`.

**Compatibility**

- Ignore unknown `new_hours` if still sent by old clients (do not fail requests).

**Frontend consumers**

- `frontend/src/routes/vulnerabilities/+page.server.ts`
- `frontend/src/routes/vulnerabilities/+page.svelte`
- `frontend/src/routes/api/vulnerabilities-paged/+server.ts`

#### 2) `GET /dashboard/summary`

**Request changes**

- None.

**Response changes**

- Add `new_findings` (latest-scan delta aggregate across latest scans of running image lineages).
- Keep `new_vulns_24h` as a temporary alias for one compatibility window, but set it equal to `new_findings`.
- After frontend rollout, remove `new_vulns_24h` in cleanup phase.

**Frontend consumers**

- `frontend/src/routes/+page.server.ts`
- `frontend/src/routes/+page.svelte`

#### 3) `GET /activity/recent`

**Request changes**

- None (`limit` stays).

**Response changes**

- Replace `container_name` with scan-time membership fields:
  - `affected_containers_at_scan: string[]`
  - `affected_container_count_at_scan: number`
- Keep image and vulnerability summary fields (`image_name`, `scan_id`, `scanned_at`, `vulns_by_*`, `total`).

**Frontend consumers**

- `frontend/src/routes/+page.server.ts`
- `frontend/src/routes/+page.svelte` (recent activity table)

#### 4) `GET /containers/running`

**Request changes**

- None.

**Response changes**

- Keep one row per currently running container.
- No semantic change to current-time scope.
- Ensure rows can reference same latest scan for shared images.
- Keep priority/severity fields stable to avoid unrelated UI churn in this rewrite.

**Frontend consumers**

- `frontend/src/routes/containers/+page.server.ts`
- `frontend/src/lib/components/vuln/ContainerRow.svelte`

#### 5) `GET /tasks` and `GET /tasks/scheduled`

**Request changes**

- None.

**Response changes**

- No schema change required.
- `task_name` and `result_details` text should shift to image-scan language (not per-container scan framing).

**Frontend consumers**

- `frontend/src/routes/tasks/+page.server.ts`
- `frontend/src/routes/tasks/+page.svelte`

#### 6) Notification channel APIs (`/notifications/channels`, `/notifications/log`)

**Request/response changes**

- No schema change required.
- Semantics of `notify_all_new` become explicitly “new since previous scan”.

**Frontend consumers**

- `frontend/src/routes/notifications/+page.svelte`

### Notification processing contract (backend jobs)

#### Scan-triggered alerts

- Compare previous scan by `image_name` lineage.
- First scan in lineage => all findings are New.
- Include scan-time blast radius from `ScanContainer`.

#### Daily digest

- Remains current-state scope (running containers/images at digest runtime).
- Can include New counts, but using the same last-scan delta definition.

## UI/Copy Contract

### New wording

- “New” always means **since previous scan**.
- Remove “New (Last 24h)” wording.
- Vulnerabilities report label for `report=new` should explicitly indicate previous-scan delta.

### Surfaces to align

- Dashboard summary card and description.
- Vulnerabilities report dropdown labels and descriptions.
- Row-level new pill/tooltip text.
- Notification settings copy for “All New”.
- Tasks page text to reflect image-level scan jobs and container blast-radius reporting.

## Phased Execution Plan

### Phase 1 — Schema + Migration Foundations

1. Add `ScanContainer` model + migration.
2. Backfill scan-container links from legacy field.
3. Recompute `first_seen_at` by `image_name` lineage.
4. Add migration tests for backfill/recompute behavior.

### Phase 2 — Backend Scan/Query Semantics

1. Refactor scan pipeline to persist scan-time container memberships.
2. Convert new-finding comparison logic to `image_name` lineage everywhere.
3. Update `/vulnerabilities?report=new`, `/dashboard/summary`, `/activity/recent`, scan-triggered notifications.
4. Keep temporary compatibility fields only where unavoidable.

### Phase 3 — Frontend Contract Alignment

1. Remove time-based New controls (`new_hours`) from vulnerabilities route and UI.
2. Update all New labels/tooltips/copy to “since previous scan”.
3. Update dashboard/activity/tasks rendering for scan-time vs current-time scope.
4. Update notification settings copy.

### Phase 4 — Cleanup

1. Remove deprecated backend compatibility fields/paths.
2. Remove remaining uses of legacy `Scan.container_name`.
3. Final pass on docs and release note text.

## Regression Test Plan

### Core semantic tests

1. **Same image, multiple containers**: one scan lineage, multiple affected containers.
2. **Same repository, different tags**: histories remain separate by `image_name`.
3. **First scan behavior**: all findings are New.
4. **Subsequent scan behavior**: only true delta findings are New.
5. **Reintroduced finding**: reappearing finding after absence is New again.

### Migration tests

1. Backfill creates one `ScanContainer` row for legacy scans with `container_name`.
2. Recomputed `first_seen_at` follows `image_name` lineage rules.
3. No DB reset required; existing scans/vulns retained.

### Notification tests

1. Scan-triggered alerts use scan-time container scope.
2. Daily digest uses current-running scope.
3. `notify_all_new` payload and counts reflect last-scan delta semantics.

## Validation Plan (Required for completion)

Backend:

1. `uv run ruff format`
2. `uv run ruff check --fix`
3. `uv run ruff check`
4. `uv run pytest -v`

Frontend (in `frontend/`):

1. `npm run format`
2. `npm run lint:fix`
3. `npm run check`
4. `npm run lint`
5. `npm run format:check`
6. `npm run test:unit:run`

## Exit Criteria

Rewrite is done when all are true:

1. “New” has one meaning (last-scan delta) across API/UI/notifications.
2. Scan-time and current-time container scopes are explicit and consistently applied.
3. Multi-container single-image blast radius is represented correctly.
4. Migration completes without requiring DB deletion.
5. Full backend/frontend validation passes.
