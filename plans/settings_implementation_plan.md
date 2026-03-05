# Database-Backed Settings with Override Plan

We want to allow users to configure the application behavior from the UI, while still letting `docker-compose.yml` (environment variables) have the final say if they are set.

## Proposed Changes

We will expose the following three settings in the UI:
1. `SCAN_INTERVAL_SECONDS` (default: 60)
2. `MAX_CONCURRENT_SCANS` (default: 1)
3. `DB_CHECK_INTERVAL_SECONDS` (default: 3600)

Infrastructure config like `DATABASE_PATH` and `API_URL` will remain strictly as environment variables.

---

### Backend Components

#### [MODIFY] `backend/models.py`
Add a new SQLModel class:
```python
class Setting(SQLModel, table=True):
    key: str = Field(primary_key=True)
    value: str
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
```
*(We'll use strings for values to keep it simple, parsing them when needed).*

#### [MODIFY] `backend/alembic/versions/`
Run `alembic revision --autogenerate` to create the migration for the new `Setting` table.

#### [NEW] `backend/config.py`
Create a `ConfigManager` to handle reading the configurations.
It will provide a method `get_setting(key: str, default: Any, db_session: Session) -> dict`.
This method will:
1. Check `os.environ.get(key)`. If it exists, return `{'value': val, 'source': 'env', 'editable': False}`.
2. If not, query the DB for `Setting` where `key == key`. If it exists, return `{'value': val, 'source': 'db', 'editable': True}`.
3. If not, return `{'value': default, 'source': 'default', 'editable': True}`.

#### [MODIFY] `backend/scheduler.py`
Change how it loads the intervals. Instead of reading `os.environ.get()` directly at module level, the scheduler will query the `ConfigManager` using a database session.
*Challenge:* The scheduler jobs are set up at startup. We will need to either:
a) Read the DB once on startup to schedule the jobs.
b) Re-schedule or dynamically read the DB inside the jobs.
*Approach:* We will read the config on startup to set the interval triggers. If the user changes settings in the UI, we should probably update the APScheduler jobs dynamically.

#### [MODIFY] `backend/api.py`
Add two new endpoints:
- `GET /settings`: Returns all settings (their value, source, and if they are editable).
- `PATCH /settings`: Updates the `Setting` table in the database for the provided keys. Returns `400` if the user tries to update a key that has `editable: False` (driven by Env Var). And it will notify the scheduler to update its job triggers if intervals are modified.

---

### Frontend Components

#### [NEW] `frontend/src/lib/stores/settings.ts`
A Svelte store to fetch from `GET /api/settings` and hold the current configuration state.

#### [NEW] `frontend/src/routes/settings/+page.svelte`
A new page using shadcn-svelte components.
- Iterate over the settings.
- If `editable` is true, show a number input.
- If `editable` is false, show a disabled number input with a small lock icon or badge explaining "Configured via Docker / Environment Variable".
- A "Save Settings" button that sends the `PATCH` request.

## Verification Plan

### Automated Tests
1. Add `test_settings_api` in `backend/tests/test_api.py` to ensure GET/PATCH work and that environment variables correctly override the database config.
2. Run unit tests using `uv run pytest -v`.

### Manual Verification
1. Open the UI Settings page and verify the layout.
2. Verify saving a setting updates the database.
3. Verify setting an environment variable in `dev.sh` or `docker-compose.yml` accurately locks the field in the UI.
