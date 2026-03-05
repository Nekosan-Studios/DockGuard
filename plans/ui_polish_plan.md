# Implement Dedicated Vulnerabilities Page

This plan outlines the creation of a new dedicated `/vulnerabilities` page that allows users to drill down into specific vulnerability reports (Critical, Actively Exploited, Newly Found) across all running containers.

## Proposed Changes

### Backend API (`backend/api.py`)
Add a new generic endpoint `GET /vulnerabilities` that fetches vulnerabilities across all running containers and groups them by vulnerability.

#### [MODIFY] [api.py](file:///Users/mattweinecke/Documents/GitHub/DockerSecurityWatch/backend/api.py)
*   **Add Endpoint**: Create a new route `GET /vulnerabilities` that accepts an optional `report` query parameter (`critical`, `kev`, `new`).
*   **Logic**:
    *   Fetch all currently running containers and determine their latest `scan_id`.
    *   Query the `Vulnerability` table for those `scan_id`s, applying filters based on the `report` param (e.g., `severity == 'Critical'`, `is_kev == True`, or `first_seen_at >= 24_hours_ago`).
    *   Group identical vulnerabilities (by `vuln_id`, `package_name`, `installed_version`) across different containers.
    *   For each grouped vulnerability, attach a list of the containers (name and image) it was found in.
    *   Return the grouped list.

---

### Frontend Components & Routes
Create the new page and link the dashboard stat cards to it.

#### [NEW] [vulnerabilities/+page.svelte](file:///Users/mattweinecke/Documents/GitHub/DockerSecurityWatch/frontend/src/routes/vulnerabilities/+page.svelte)
*   **UI Structure**: Build a full-page data table similar to the sub-table found in the Containers view.
*   **Performance / Rendering**: Implement progressive rendering using Svelte reactivity and `requestIdleCallback` (or `setTimeout` fallback). Load data in chunks (e.g., 50 rows at a time) to prevent the browser UI from locking up when hundreds of vulnerabilities are returned. Add a "Loading X more vulnerabilities..." indicator at the bottom of the table until the idle callbacks finish rendering all items.
*   **Columns**: ID, Severity, Package, Version, Fixed In, CVSS, EPSS, KEV, First Seen, **Containers** (new column showing badges/tags of affected containers), and Description.
*   **Interactivity**: Allow sorting and filtering. Include a selector at the top to switch between the three predefined reports: "Critical Vulnerabilities", "Actively Exploited", and "Newly Found (Last 24h)".

#### [NEW] [vulnerabilities/+page.server.ts](file:///Users/mattweinecke/Documents/GitHub/DockerSecurityWatch/frontend/src/routes/vulnerabilities/+page.server.ts)
*   **Loader**: Parse the `?report=` URL query parameter (defaulting to `critical` or `all`).
*   **Data Fetching**: Call the new backend `/vulnerabilities?report=...` endpoint and return the data to the Svelte page.

#### [MODIFY] [+page.svelte (Dashboard)](file:///Users/mattweinecke/Documents/GitHub/DockerSecurityWatch/frontend/src/routes/+page.svelte)
*   **Hyperlinks**: Wrap the stat cards (Critical, Actively Exploited, New) in SvelteKit links `<a>` that point to `/vulnerabilities?report=critical`, `/vulnerabilities?report=kev`, and `/vulnerabilities?report=new`.
*   **Hover Styles**: Add hover/cursor-pointer styles to the stat cards to indicate they are clickable.

#### [MODIFY] [app-sidebar.svelte](file:///Users/mattweinecke/Documents/GitHub/DockerSecurityWatch/frontend/src/lib/components/app-sidebar.svelte)
*   **Navigation**: Add "Vulnerabilities" back to the sidebar navigation menu, linking to `/vulnerabilities`. We can use the ShieldAlert or TriangleAlert icon.

## Verification Plan

### Automated Tests
*   Run the Svelte check and build tools (`npm run check`, `npm run build`) in the `frontend` directory to ensure type safety and build success.
*   Run the Python formatting and linting tools if they exist, or just ensure the FastAPI app starts correctly without syntax errors.

### Manual Verification
1.  Navigate to the Dashboard.
2.  Click on the "Critical Vulnerabilities" stat card.
3.  Verify it navigates to `/vulnerabilities?report=critical` and displays a table of top-level vulnerabilities.
4.  Check that the new "Containers" column correctly lists the containers affected by each specific CVE/package combination.
5.  Switch between the reports (Critical, KEV, New) using the dropdown/tabs on the Vulnerabilities page and verify the data reloads properly.
6.  Ensure sorting and formatting match the existing application style.
