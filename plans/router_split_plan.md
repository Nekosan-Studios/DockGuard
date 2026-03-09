# DockGuard Refactoring Strategy

Based on a comprehensive review of the DockGuard codebase, several key areas have been identified for refactoring. The goal is to improve maintainability, separation of concerns, and testability without disrupting existing features.

## 🔴 Major Overhauls (High Priority / High Impact)

### 1. Deconstruct Frontend "God Components"
The Svelte frontend relies on massive, monolithic page components that mix state management, API data fetching, complex sorting/filtering logic, and UI rendering.
*   **Target:** `frontend/src/routes/containers/+page.svelte` (1400+ lines)
*   **Target:** `frontend/src/routes/vulnerabilities/+page.svelte` (800+ lines)
*   **Strategy:**
    *   **Extract UI Components:** Move the complex table rendering (rows, headers, pagination controls) into dedicated components in `src/lib/components/vuln/`.
    *   **Extract Logic:** Move the complex state blocks (`activeFilters`, `sortCol`, `intersectionObserver` pagination logic) into Svelte stores or custom `$state` functional hooks in `src/lib/stores/` or `src/lib/utils/`.
    *   **Simplify Pages:** Keep `+page.svelte` strictly focused on page layout and high-level data orchestration.

### 2. Deconstruct Backend API Router
The backend `api.py` is a monolithic file (~900 lines) containing all routes, business logic, sorting helpers, and default API data limits.
*   **Target:** `backend/api.py`
*   **Strategy:**
    *   Create a `backend/routers/` directory to split endpoints by domain:
        *   `backend/routers/vulnerabilities.py`
        *   `backend/routers/containers.py`
        *   `backend/routers/tasks.py`
        *   `backend/routers/settings.py`
    *   Keep `api.py` (or rename to `main.py`) strictly for FastAPI app initialization, middleware, and including the routers.

## 🟡 Medium Effort (Structural Improvements)

### 3. Modularize `scheduler.py`
Currently, `scheduler.py` (500+ lines) manages APScheduler configuration, direct Docker interactions, database purges, and parsing Grype outputs.
*   **Target:** `backend/scheduler.py`
*   **Strategy:**
    *   Extract Docker interaction logic to a dedicated `docker_service.py` (augmenting `docker_watcher.py`).
    *   Extract Grype execution logic to a `grype_service.py` (augmenting `grype_scanner.py`).
    *   Keep `scheduler.py` explicitly for defining scheduled jobs and interval tracking.

### 4. Improve Frontend State Management
Both major frontend pages use heavy local `$state` for pagination, active filters, and loading statuses, often leading to prop drilling or massive component files.
*   **Strategy:** Implement `$state` classes/functions in `.ts` files to encapsulate the logic for "Paginated Resource" or "Vulnerability Table State", ensuring reusability across containers and vulnerabilities views.

## 🟢 Quick Wins (Low-Hanging Fruit)

### 5. Consolidate Backend Models and Helpers
*   **Target:** Review and extract inline helper functions inside `api.py` (e.g., `_as_utc`, `_latest_scan_for_ref`, `_parse_image_query`) into a dedicated `backend/utils.py` or within their respective feature modules (like `images.py`).

---

### Recommended Next Steps
We can tackle these incrementally to ensure nothing breaks. I recommend starting with:
1.  **Backend Router Split (Priority 2):** It's low risk, highly mechanical, and immediately improves backend readability.
2.  **Frontend Component Extraction (Priority 1):** Breaking down `containers/+page.svelte` piece by piece.
