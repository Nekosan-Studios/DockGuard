# Rename Walkthrough: DockerSecurityWatch → DockGuard

## Changes Made

Renamed every user-visible and developer-facing reference from `DockerSecurityWatch` to **DockGuard** across all naming variants.

### Files Modified

| File | Change |
|---|---|
| `backend/database.py` | Default DB path → `data/dockguard.db` |
| `pyproject.toml` | Package name → `dockguard` |
| `uv.lock` | Regenerated (via `uv lock`) |
| `backend/tests/conftest.py` | Test container → `dg-test` |
| `docker/docker-compose.yml` | Service name → `dockguard` |
| `.github/workflows/ci.yml` | Image name → `dockguard` |
| `frontend/src/lib/components/app-sidebar.svelte` | Sidebar brand → `DockGuard` |
| `frontend/src/routes/settings/+page.svelte` | Prose → `DockGuard` |
| `frontend/src/routes/containers/+page.svelte` | Log prefix `[DSW]` → `[DG]` |
| `dev.sh` | Banner → `DockGuard — dev` |
| `README.md` | Title, service name, volume (`dg-data`), DB filename, environment var defaults |
| `VULNERABILITY_REPORT.md` | Image name → `dockguard` |
| `plans/settings_implementation_walkthrough.md` | Project name in prose |

### Intentionally Unchanged

- **`DockerWatcher` class** (`backend/docker_watcher.py`) — describes what the component does (watches Docker), not the project name.
- **`file:///` paths in historical plan docs** — these reference the repo directory path, which is not being renamed.
- **GitHub repo / folder name** — out of scope.

## Verification Results

| Check | Result |
|---|---|
| `uv run pytest -v` | ✅ 63 passed, 1 deselected |
| `npm run check` (svelte-check) | ✅ 0 errors, 8 warnings (all pre-existing in UI components) |
| `uv lock` | ✅ Regenerated: `docker-security-watch` → `dockguard` |
| Grep audit for stale references | ✅ No stale project-name references found |
