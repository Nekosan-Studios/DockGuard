# Settings Management Implementation

I have successfully implemented the new Settings management flow, bringing UI-controlled configuration to DockGuard while retaining strict environment variable precedence for container environments.

## Features Added

*   **Database Settings Manager:** Added a `Setting` database table and a `ConfigManager` utility in the backend to systematically handle setting resolution (Env > DB > Default).
*   **Dynamic Scheduler Updates:** Refactored the `APScheduler` in `backend/scheduler.py` to dynamically update its container polling and DB check intervals based on new setting profiles saved in the database.
*   **Settings API:** Added `GET` and `PATCH /settings` endpoints in FastAPI and hooked them up natively via SvelteKit’s proxy routing (`+server.ts`).
*   **Settings UI:** Built a dedicated Svelte page grouping configurations (Scanning and Updates) and highlighting fields bound by an Environment Variable constraint vs default application state. Added saving operations and success/error feedbacks.
*   **Navigation:** Added the "Settings" item dynamically to the `app-sidebar.svelte` drawer to easily reach the interface. 

## Testing and Verification 

1.  **Backend Pytests:** Added `test_settings_bug.py` to correctly test API endpoint response bodies, payload typing, and backend validation against incorrect payloads (such as strings masquerading as numbers). These tests pass successfully. 
2.  **Browser Verification:** Verified the complete stack via Chromium tests. The browser bot navigated the UI tree, observed the Svelte components render smoothly with the correct badge UI states ("Default"), changed arbitrary integers across input values, and submitted configuration forms with persisting database status on window reloads.

![Settings UI](/Users/mattweinecke/.gemini/antigravity/brain/a6868c55-96cd-4622-8c06-8e6e4e918413/.system_generated/click_feedback/click_feedback_1772676845371.png)

## Considerations

*   As initially discussed via `Approach A`, modifying the properties `SCAN_INTERVAL_SECONDS`, `MAX_CONCURRENT_SCANS`, or `DB_CHECK_INTERVAL_SECONDS` using the `docker-compose.yml` file defaults the source to `env`, rendering those UI pieces fully locked from the Svelte dashboard. 
*   Because the frontend component automatically coerces values to strings due to JSON mapping, any future components mapping API properties using integers natively should convert them explicitly downstream in `api.py`.
