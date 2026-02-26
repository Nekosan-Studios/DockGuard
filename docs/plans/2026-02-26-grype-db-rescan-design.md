# Design: Grype DB Update Detection and Rescan

**Date:** 2026-02-26

## Problem

The grype vulnerability database updates approximately once per day. Currently, scans are only triggered when a running container's image digest changes. If the grype DB updates while containers are running (or stopped), those containers are not rescanned with the new data until their image digest changes — which may never happen for stable images like `nginx:latest`.

## Goal

Automatically rescan all containers whenever a new grype vulnerability database is detected, ensuring vulnerability data stays current even when images themselves have not changed.

## Approach

Add a second scheduled job to `ContainerScheduler` that periodically runs `grype db check`. If a new DB is available, clear `_seen_digests` entirely so the existing `_check_running_containers` job rescans all currently-running containers on its next poll, and any stopped containers are rescanned when they come back up.

`grype db check` exit codes (stable public CLI interface):
- `0` — DB is current, no action needed
- `1` — update available, trigger rescan
- other — unexpected error, log and take no action

## Changes

**`backend/scheduler.py` only.** No other files need to change.

1. New env var: `DB_CHECK_INTERVAL_SECONDS` (default: `3600`, i.e. hourly)
2. New async method `_check_db_update()`:
   - Runs `grype db check` via subprocess
   - `returncode == 0`: log "DB current", do nothing
   - `returncode == 1`: log "DB update available", call `_seen_digests.clear()`
   - Any other returncode: log error with actual code, do nothing
3. Register `_check_db_update` as a second `IntervalTrigger` APScheduler job in `__init__`

**No changes to:** `grype_scanner.py`, `api.py`, `models.py`, database schema, or the existing `_check_running_containers` job.

## Why clear all of `_seen_digests` (not just running containers)

Clearing only running container digests would leave stopped containers in `_seen_digests`. When a stopped container restarts after a DB update, it would be skipped by `_check_running_containers` because its digest is still known. Clearing the full set ensures every container — running or previously stopped — gets rescanned with the new DB when it is next observed.

## Error Handling

- Subprocess exception (e.g. grype not on PATH): caught, logged, no rescan triggered
- Unexpected exit code: logged with actual value, no rescan triggered
- Errors never cause a spurious `_seen_digests.clear()`

## Testing

Three new unit tests in `tests/test_scheduler.py`, following the existing mock pattern:

- `returncode == 1` → `_seen_digests` is cleared
- `returncode == 0` → `_seen_digests` unchanged
- `returncode == 2` (unexpected) → `_seen_digests` unchanged, error logged
