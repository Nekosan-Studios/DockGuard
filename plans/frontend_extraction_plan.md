# Frontend Component Extraction Plan

## Goal Description
The purpose of this refactor is to break down the monolithic Svelte components `containers/+page.svelte` (~1400 lines) and `vulnerabilities/+page.svelte` (~860 lines). Currently, these files mix data fetching, API pagination, complex sorting/filtering state (often tracked in cumbersome `Map<string, State>` formats), and heavy UI table rendering. 

By extracting these responsibilities into dedicated reusable UI components and Svelte 5 state modules, we will improve readability, simplify state management, and make the application easier to test and maintain.

## User Review Required
> [!NOTE]
> The most significant architectural change here is abandoning the global `Map<string, T>` state trackers in `containers/+page.svelte` governing expanded states. By extracting a `<ContainerRow>` component, all those `Map`s collapse into simple local `$state()` variables encapsulated within each individual row! This will delete hundreds of lines of boilerplate.

### Addressing Vulnerability Row Commonality
You are completely right. Both views actually group by CVE. 
- **Containers View:** A vulnerability row represents a CVE grouped by the Packages affected *within that specific container*.
- **Vulnerabilities View:** A vulnerability row represents a CVE grouped by Packages affected *across all containers*.

Because both views use the exact same complex logic for rendering the primary package alongside a "+N more packages" expandable popover, they are structurally 95% identical. The **only** difference is that the global view renders a "Containers" column.

**Our Updated Strategy:** Because the divergence is so small (literally just a single `Table.Cell` for containers), creating two separate row components would lead to massive duplication of the complex package grouping UI. 

Instead, we will create a single, unified `<VulnRow>` component. It will take an optional `showContainers: boolean = false` prop. This is clean parametrization, completely avoiding the tangled "God Component" anti-pattern because the branching logic is isolated to a single, simple column check. This ensures both tables stay perfectly identical in behavior and styling.

## Proposed Changes

### 1. `containers/+page.svelte`
We will extract the table row and its expanded vulnerability details into a self-contained component.
#### [MODIFY] `frontend/src/routes/containers/+page.svelte`
- Delete all `Map<string, ...>` state trackers (`containerVulns`, `containerVulnsMeta`, `activeFilters`, `expandedContainers`, etc).
- Simplify the template to render the main `Table` and loop over `data.containers` returning a `<ContainerRow>` component.
- Retain only the state for sorting the *parent* container list.

#### [NEW] `frontend/src/lib/components/vuln/ContainerRow.svelte`
- Encapsulate the `Table.Row` for a single container.
- Manage local `$state()` for `expanded`, `vulns`, `offset`, `hasMore`, `activeFilters`, and `sortCol`.
- Contain the `fetchVulns()` API logic localized to this specific container's image reference.
- Contain the Intersection Observer logic for infinite scrolling this specific container's vulnerabilities.
- Render the nested `<Table.Root>` containing the vulnerability list when expanded.

### 2. `vulnerabilities/+page.svelte`
We will extract the complex, infinite-scrolling vulnerability table rows into a reusable component, and isolate the header controls.

#### [MODIFY] `frontend/src/routes/vulnerabilities/+page.svelte`
- Retain the top-level page layout, URL parameter derivations, and total counts.
- Extract the vulnerability `Table.Row` rendering to a dedicated `<VulnTableRow>` component to reduce template bloat.
- Extract the filter controls into a separate `<VulnFilters>` (optional, if time permits).

#### [NEW] `frontend/src/lib/components/vuln/VulnRow.svelte`
- Encapsulates the `Table.Row` rendering for a CVE across both pages.
- Maintains the complex `packages` sub-list popover and data parsing.
- Accepts a `showContainers={true|false}` prop to toggle the container list cell for the global view.
- Maximizes reuse of the existing atomic cells (`SeverityCell`, `CvssCell`, etc.).

## Verification Plan

### Automated Tests
```bash
# Ensure standard UI logic tests continue to pass
cd frontend && npm run test:unit
```

### Manual Verification
1. Run `./dev.sh`.
2. Navigate to `http://localhost:5173/containers`.
3. Expand a container row. Verify that vulnerabilities load dynamically via the API.
4. Scroll down within the expanded view to trigger the Intersection Observer and ensure infinite scrolling paginates correctly.
5. Apply a severity filter within the expanded row and verify filtering works.
6. Navigate to `http://localhost:5173/vulnerabilities`.
7. Scroll down to trigger pagination and verify rows continue appending smoothly.
