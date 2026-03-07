# Vulnerability Grouping by CVE ID — Implementation Walkthrough

## Problem

Vulnerability reports inconsistently displayed CVEs: sometimes a CVE appeared on one row with multiple containers combined, other times the same CVE was repeated across multiple rows. The root cause was the grouping key `vuln_id|package_name|installed_version` — when different containers had different package versions for the same CVE, separate rows were created.

## Changes Made

### Backend: `backend/api.py`

**Grouping key changed** from `vuln_id|package_name|installed_version` to just `vuln_id`.

**New data structure**: Each grouped vulnerability now includes a `packages` list containing all affected packages:
```python
{
    "package_name": str,
    "installed_version": str,
    "fixed_version": str | None,
    "package_type": str | None,
    "locations": str | None,
    "severity": str,
    "cvss_base_score": float | None,
}
```

**Severity/CVSS promotion**: When merging, the row-level severity is promoted to the worst across all packages (using `_severity_rank`), and CVSS is promoted to the highest score.

**Package ordering**: Packages within each group are sorted by:
1. Worst severity (lowest `_severity_rank` index first)
2. Highest CVSS score
3. Alphabetical package name

**Representative package**: The first package in the sorted list becomes the representative, populating the top-level `package_name`, `installed_version`, `fixed_version`, `package_type`, and `locations` fields for backward compatibility and sorting.

### Frontend: `frontend/src/routes/vulnerabilities/+page.svelte`

**New interface**: Added `PackageInfo` interface and `packages: PackageInfo[]` to `Vulnerability`.

**`{#each}` key**: Changed from `vuln.vuln_id + vuln.package_name + vuln.installed_version` to just `vuln.vuln_id`.

**Package/Version/Fixed In columns**: Now display the representative package (`vuln.packages[0]`). When additional packages exist, a `+N more` badge appears in the Package column.

**"+N more" badge**:
- Styled as an indigo pill (distinct from container badges which are slate)
- Clickable — opens a Popover (not tooltip) so users can interact with the content
- Popover lists all affected packages with name, type badge, installed version, and fixed version
- Scrollable (max-height 48/12rem) for CVEs affecting many packages

**Containers column header**: Replaced `SortButton` with plain text label since the column was never sortable (the sort handler already returned early for "containers").

## Files Modified

| File | Change |
|------|--------|
| `backend/api.py` | Grouping logic in `/vulnerabilities` endpoint (lines ~398-445) |
| `frontend/src/routes/vulnerabilities/+page.svelte` | Interface, imports, each-key, package display, containers header |

## Design Decisions

- **Popover over Tooltip**: Users may want to copy package names or read version strings without content vanishing on mouse movement.
- **Badge style**: Indigo color differentiates from slate container badges while maintaining visual consistency.
- **Representative selection**: Worst severity first ensures the most urgent package is always visible without clicking.
- **Sorting by package_name**: Uses representative package name, consistent with how the containers column (also multi-valued) is handled.
