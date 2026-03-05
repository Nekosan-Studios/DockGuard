# Rename Project: DockerSecurityWatch → DockGuard

Rename every user-visible and developer-facing reference from the old name to **DockGuard**, including code, config, Docker, CI, and documentation.

## User Review Required

> [!IMPORTANT]
> **Naming convention mapping** — please confirm the variants below match your intent:
>
> | Old variant | New variant | Where used |
> |---|---|---|
> | `DockerSecurityWatch` | `DockGuard` | README title, dev.sh banner, settings page prose |
> | `docker-security-watch` | `dockguard` | pyproject.toml `name`, docker-compose service name, VULNERABILITY_REPORT |
> | `docker_security_watch` | `dockguard` | Default database filename (`data/dockguard.db`) |
> | `dockersecuritywatch` | `dockguard` | CI image name (`ghcr.io/.../dockguard`) |
> | `DockerWatch` | `DockGuard` | Sidebar brand text |
> | `DSW` / `dsw-test` / `dsw-data` | `DG` / `dg-test` / `dg-data` | Console log prefix, test container name, compose volume |

> [!WARNING]
> **Database filename change**: The default `DATABASE_PATH` will change from `data/docker_security_watch.db` to `data/dockguard.db`. Existing deployments that rely on the old default will need to either:
> - Rename/copy the file, **or**
> - Set `DATABASE_PATH` explicitly to the old name.
>
> I'll add a note in the README about this.

> [!IMPORTANT]
> **GitHub repo name**: The top-level folder is `DockerSecurityWatch` (your GitHub repo name). Renaming the folder on disk or the GitHub repository itself is **out of scope** for this change — I'll only update content inside the repo. Let me know if you'd also like me to rename the containing folder.

---

## Proposed Changes

### Backend

#### [MODIFY] [database.py](file:///Users/mattweinecke/Documents/GitHub/DockerSecurityWatch/backend/database.py)
- Default `DATABASE_PATH` → `data/dockguard.db`

#### [MODIFY] [conftest.py](file:///Users/mattweinecke/Documents/GitHub/DockerSecurityWatch/backend/tests/conftest.py)
- Test container name `dsw-test` → `dg-test`

---

### Python Project Config

#### [MODIFY] [pyproject.toml](file:///Users/mattweinecke/Documents/GitHub/DockerSecurityWatch/pyproject.toml)
- `name = "docker-security-watch"` → `name = "dockguard"`
- After editing, regenerate `uv.lock` via `uv lock`

---

### Docker

#### [MODIFY] [docker-compose.yml](file:///Users/mattweinecke/Documents/GitHub/DockerSecurityWatch/docker/docker-compose.yml)
- Service name `docker-security-watch` → `dockguard`

---

### CI/CD

#### [MODIFY] [ci.yml](file:///Users/mattweinecke/Documents/GitHub/DockerSecurityWatch/.github/workflows/ci.yml)
- Image name `dockersecuritywatch` → `dockguard`

---

### Frontend

#### [MODIFY] [app-sidebar.svelte](file:///Users/mattweinecke/Documents/GitHub/DockerSecurityWatch/frontend/src/lib/components/app-sidebar.svelte)
- Sidebar brand `DockerWatch` → `DockGuard`

#### [MODIFY] [settings/+page.svelte](file:///Users/mattweinecke/Documents/GitHub/DockerSecurityWatch/frontend/src/routes/settings/+page.svelte)
- Prose text `DockerSecurityWatch` → `DockGuard`

#### [MODIFY] [containers/+page.svelte](file:///Users/mattweinecke/Documents/GitHub/DockerSecurityWatch/frontend/src/routes/containers/+page.svelte)
- Console log prefix `[DSW]` → `[DG]`

---

### Dev Script

#### [MODIFY] [dev.sh](file:///Users/mattweinecke/Documents/GitHub/DockerSecurityWatch/dev.sh)
- Banner `DockerSecurityWatch — dev` → `DockGuard — dev`

---

### Documentation

#### [MODIFY] [README.md](file:///Users/mattweinecke/Documents/GitHub/DockerSecurityWatch/README.md)
- All references: title, service name table, `dsw-data` volume, `docker_security_watch.db`, and prose

#### [MODIFY] [VULNERABILITY_REPORT.md](file:///Users/mattweinecke/Documents/GitHub/DockerSecurityWatch/VULNERABILITY_REPORT.md)
- Image name `docker-security-watch` → `dockguard`

#### [MODIFY] Plans & docs (8 files in `plans/` and `docs/plans/`)
- Update file paths and project name references where they appear
- These are historical plan/walkthrough docs — I'll update the human-readable project name references but leave git-history paths as-is since they're historical records

---

## Verification Plan

### Automated Tests

1. **Python tests** — confirm nothing broke:
   ```bash
   cd /Users/mattweinecke/Documents/GitHub/DockerSecurityWatch
   uv run pytest -v
   ```

2. **Frontend type-check** — confirm the Svelte changes compile:
   ```bash
   cd /Users/mattweinecke/Documents/GitHub/DockerSecurityWatch/frontend
   npm run check
   ```

3. **uv lock regeneration** — confirm the lock file is consistent:
   ```bash
   cd /Users/mattweinecke/Documents/GitHub/DockerSecurityWatch
   uv lock
   ```

### Manual Verification

4. **Grep audit** — confirm no stale references remain:
   ```bash
   cd /Users/mattweinecke/Documents/GitHub/DockerSecurityWatch
   grep -ri "DockerSecurityWatch\|docker-security-watch\|docker_security_watch\|dockersecuritywatch\|DockerWatch\|\[DSW\]\|dsw-test\|dsw-data" --include="*.py" --include="*.ts" --include="*.svelte" --include="*.md" --include="*.yml" --include="*.toml" --include="*.sh" .
   ```
   Expected: **no matches** (except possibly in `.git/` or `node_modules/`, which are excluded by default).
