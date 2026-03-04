# Dashboard Performance Fix — Results Summary

## Changes Made

### `backend/api.py`

| # | Function | Issue | Fix | Before | After |
|---|---|---|---|---|---|
| 1 | `get_dashboard_summary` | 3 queries per running image for critical+KEV counts | Single subquery + conditional aggregation | 3N queries | 1 query |
| 2 | `get_dashboard_summary` | 1 query per scan per day in 30-day trend | Batch all scan IDs, one `GROUP BY scan_id` query | D×M queries | 1 query |
| 3 | `get_dashboard_summary` | Latest scan lookup missing `.limit(1)` | Added `.limit(1)` to the `ORDER BY scanned_at DESC` select | full table ordered | 1 row |
| 4 | `get_recent_activity` | 1 severity-breakdown query per scan | Batch all scan IDs, one `GROUP BY scan_id, severity` query | N+1 queries | 2 queries |
| 5 | `get_running_containers` | 2 queries per running container | Subquery for latest scan IDs + batched severity query | 2N queries | 3 queries |

**Total dashboard page load: ~30–180+ queries → ~6 queries (fixed, regardless of scale)**

### `backend/alembic/versions/a1b2c3d4e5f6_add_performance_indexes.py`

New migration adding 4 indexes on the most-queried columns:

| Index | Table | Column(s) |
|---|---|---|
| `ix_scan_image_name` | scan | image_name |
| `ix_scan_scanned_at` | scan | scanned_at |
| `ix_vulnerability_scan_id_severity` | vulnerability | (scan_id, severity) |
| `ix_vulnerability_scan_id_is_kev` | vulnerability | (scan_id, is_kev) |

## How to Apply

Run `alembic upgrade head` from the `backend/` directory after pulling the branch.
No data changes — indexes only.
