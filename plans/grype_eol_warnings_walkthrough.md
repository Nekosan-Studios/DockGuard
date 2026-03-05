# Grype EOL Warnings Implementation

We've successfully surfaced Grype's End-of-Life (EOL) distro warnings throughout the DockGuard application according to your exact specifications!

## What Changed

1. **Database Backend (`backend/models.py`)**
   - We added an `is_distro_eol` boolean flag directly to the `Scan` table, allowing us to permanently store the EOL status for a scan.
   - We generated and successfully applied an Alembic migration to update the SQLite database schema without losing data.

2. **Scanner Parser (`backend/grype_scanner.py`)**
   - We updated the scanner script so that when Grype returns a report in JSON format, we comb through the `alertsByPackage` array in the JSON to locate any alert with `"type": "distro-eol"`.
   - If an alert is found, the script automatically tags the associated `Scan` record with `is_distro_eol=True`.

3. **API Endpoints (`backend/api.py`)**
   - **Dashboard**: The `/dashboard/summary` endpoint now aggregates the count of actively running EOL containers and returns `eol_count`.
   - **Containers**: In `/containers/running`, we added the `is_distro_eol` flag for every container, carrying it straight to the UI.
   - **Vulnerabilities**: The main `/vulnerabilities` and `/images/vulnerabilities` endpoints have been modified to aggregate and pass down the `eol_images` list so the frontend can check if the current report covers any expired operating systems.

4. **Frontend UI Enhancements**
   - **Dashboard**: Added a new badge (styled in orange indicating a warning) inside the *Environment* card that tracks the number of EOL systems currently running.
   - **Containers View**: Included an inline "EOL OS" warning badge next to the container names. We also added a custom banner to the row expansion subview that explains *why* the EOL banner is showing: "This image uses an end-of-life operating system. Vulnerability data may be incomplete or outdated."
   - **Vulnerabilities View**: Integrated a prominent alert banner at the top of the reports view (styled with `ShieldAlert`) whenever the underlying vulnerabilities belong to an EOL container. It dynamically lists the affected images.

## How to Test

Whenever a container running an EOL base OS (e.g. `alpine:3.10` or a very old `ubuntu` tag) is scanned by Grype, you will now see these bright orange warning indicators populate automatically across all three core views!
