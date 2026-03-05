# Handling Grype EOL Warnings

I have investigated how Grype reports End-Of-Life (EOL) usage within its JSON output. 

Rather than having a top-level `is_eol` flag, Grype attaches alerts to the individual packages it scanned. In the resulting JSON, there is an `alertsByPackage` array. When a container is using an EOL distro (like `ubuntu:14.04`), Grype attaches a `"type": "distro-eol"` alert to **every single package** from that distro.

```json
"alerts": [
  {
    "type": "distro-eol",
    "message": "Package is from end-of-life distro: ubuntu 14.04",
    "metadata": {
      "name": "ubuntu",
      "version": "14.04"
    }
  }
]
```

Because we can reliably parse this, we can easily extract this state during a scan and surface it in our UI. Here is a proposed plan for implementation.

## Proposed Changes

### Database & Backend
*   **`backend/models.py`**: Add `is_distro_eol: bool = Field(default=False)` to the `Scan` model.
*   **Alembic**: Generate and apply a database migration for the new column.
*   **`backend/grype_scanner.py`**: Iterate through `grype_json.get("alertsByPackage", [])` during a scan. If any package has an alert of type `"distro-eol"`, flag the `Scan` as EOL.
*   **`backend/api.py`**: Update the `/containers/running` and `/dashboard/summary` APIs to return the `is_distro_eol` flag so the frontend knows which containers/images are EOL.

---

### UI Brainstorming & Options

Since you want to draw attention to this, here are the places we can surface the EOL status in the frontend:

1.  **Dashboard Environment Card**: Add a small indicator (e.g., `2 EOL Systems`) in the Environment card if any of the *currently running* containers are strictly EOL.
2.  **Containers Sub-View**: 
    *   Add a prominent red or amber "EOL" badge next to the container name/image name in the table row.
    *   When the row is expanded, we can show a full Shadcn Alert banner warning the user: *"This image uses an end-of-life OS (Ubuntu 14.04). Vulnerability data may be incomplete or outdated."*
3.  **Vulnerabilities Sub-View**: When viewing the vulnerabilities for a specific image, if that image's latest scan is marked `is_distro_eol`, place a prominent Alert banner at the very top of the vulnerability table.

## User Review Required

Does this database strategy and UI plan sound good to you? Which of the UI options would you like to proceed with, or would you like to do a combination of all three?
