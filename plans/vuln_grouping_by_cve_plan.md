# Vulnerability Grouping by CVE ID — Implementation Plan

## Problem

Vulnerability reports inconsistently display CVEs across containers. Sometimes a CVE appears on one line with multiple containers combined in the container column; other times the same CVE is repeated across multiple lines (one per container). This happens because the grouping key includes `package_name` and `installed_version` — when different containers have different versions of the same package, separate rows are created.

## Investigation

### Current grouping key (backend/api.py:406)

```python
key = f"{v.vuln_id}|{v.package_name}|{v.installed_version}"
```

This means the same CVE creates separate rows when:
- Different containers have different versions of the same package
- The same CVE affects different packages across containers

### Endpoints

- `/vulnerabilities` (api.py:341-484) — cross-container view with grouping logic. Used by the main vulnerabilities page.
- `/images/vulnerabilities` (api.py:218-287) — per-image view, no grouping. Used by the containers sub-view.

### Severity ranking (api.py:33-40)

Internal sort order: Critical > High > Medium > Low > Negligible > Unknown. This is our own mapping for sorting, not a Grype-provided field. Grype only provides the text label.

## Decision: Group by `vuln_id` Only (Option A)

Each unique CVE ID appears exactly once in the table, regardless of how many packages or containers are affected.

## Display Strategy: Primary + Overflow (Option 3)

- Package/Version/Fixed In columns show the **representative package** (most severe)
- When additional packages exist, a `+N more` **clickable badge** opens a **popover** listing all packages with details
- Badge styled similarly to container badges (consistent pattern), with `cursor-pointer`
- Popover (not tooltip) chosen because users may want to select text or read longer version strings

## Implementation Details

### Backend (api.py)

1. **Change grouping key** from `vuln_id|package_name|installed_version` to just `vuln_id`
2. **Collect packages** into a list on each grouped vuln:
   - Each entry: `{ package_name, installed_version, fixed_version, package_type, locations }`
3. **Pick representative package**: worst severity > highest CVSS > alphabetical name
4. **Row-level fields**: severity and CVSS = worst across all merged packages
5. **Sorting by `package_name`**: uses the representative package's name

### Frontend (+page.svelte)

1. **Update `Vulnerability` interface** to include a `packages` array
2. **Package/Version/Fixed In columns** show representative (first) package from the array
3. **"+N more" badge** when `packages.length > 1`:
   - Styled like container badges (pill, border, small text) but slightly different color (muted blue/indigo)
   - Clickable — opens a popover
4. **Popover content**: lists all packages with name, version, fixed version, package type
5. **Containers column header**: remove `SortButton`, replace with plain text label (column is not sortable)
6. **Update `{#each}` key** from `vuln.vuln_id + vuln.package_name + vuln.installed_version` to just `vuln.vuln_id`

### Sorting Ramifications

- **Severity sort**: uses worst severity across merged packages (no change needed if row-level severity is set correctly)
- **CVSS sort**: uses highest CVSS across merged packages
- **Package name sort**: uses representative package name
- **Containers column**: explicitly not sortable (already was, but now we remove the misleading arrow)
- **EPSS / KEV / First Seen**: per-CVE fields, unaffected by grouping
