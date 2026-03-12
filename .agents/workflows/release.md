---
description: how to release a new versioned build of DockGuard

---

# DockGuard Release Workflow

Releasing a new version is a single action in the GitHub web UI.
No local scripts are needed.

## Steps

1. Go to **GitHub → Releases → Draft a new release**
2. Under **"Choose a tag"**, type the new version tag (e.g. `v1.3.0`) and select **"Create new tag on publish"** targeting `master`
3. Add an optional release title and description
4. Click **"Publish release"**

CI will automatically:
- Detect the new `v*` tag
- Build the Docker image with `APP_VERSION` baked in
- Push to GHCR with both the semver tag (`1.3.0`) and `latest`

The Settings page in the published container will show **DockGuard v1.3.0**.

## Notes

- **No version bump commits needed.** `pyproject.toml`, `package.json`, and lockfiles are permanently set to `0.0.0` — the git tag is the authoritative version.
- **Local dev builds** show `DockGuard vDevelopment build` in Settings (no `APP_VERSION` env var set).
- **Manual CI builds** (via `workflow_dispatch`) will also use `Development build` since no tag is present; this is expected for dev/test builds.
- **Semver tagging**: use `vMAJOR.MINOR.PATCH` format (e.g. `v1.3.0`). The `v` prefix is stripped when baking into the image (`APP_VERSION=1.3.0`).
