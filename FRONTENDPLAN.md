# Plan: SvelteKit Frontend Scaffold — Step 1

## Context
DockerSecurityWatch has a FastAPI backend (port 8000) with 5 endpoints. This plan scaffolds
a SvelteKit + Tailwind CSS + shadcn-svelte frontend in a new `frontend/` directory at the
project root, matching the Dockhand dark-dashboard aesthetic. Step 1 builds the layout
shell and two functional pages using the existing APIs.

---

## What Gets Built

### Directory Structure
```
frontend/
├── package.json             ← dependencies (SvelteKit, Tailwind, shadcn-svelte, bits-ui)
├── svelte.config.js         ← SvelteKit config
├── vite.config.js           ← Vite config + API proxy (localhost:8000 → /api)
├── components.json          ← shadcn-svelte config
├── src/
│   ├── app.html             ← HTML shell
│   ├── app.css              ← global styles + Tailwind + shadcn CSS variables (dark theme)
│   ├── lib/
│   │   ├── api.js           ← typed fetch helpers for all 5 endpoints
│   │   └── components/
│   │       ├── Sidebar.svelte       ← dark left-nav with icon + label items
│   │       ├── SeverityBadge.svelte ← colored badge: Critical/High/Medium/Low/Negligible
│   │       └── StatCard.svelte      ← metric card (label + big number + optional subtitle)
│   └── routes/
│       ├── +layout.svelte   ← root layout: sidebar + main content area
│       ├── +page.svelte     ← Dashboard page (/)
│       └── running/
│           └── +page.svelte ← Running Containers page (/running)
└── static/
    └── favicon.png
```

---

## Pages

### 1. Dashboard (`/`)
Uses: `GET /vulnerabilities/count`, `GET /vulnerabilities/critical/running`

```
┌─────────────────────────────────────────────────────────────────┐
│  ◈  DockerSecurityWatch                                         │
├──────────┬──────────────────────────────────────────────────────┤
│          │  Dashboard                                           │
│ Dashboard│                                                      │
│          │  ┌─────────────────┐  ┌─────────────────┐           │
│ Running  │  │ Total Vulns     │  │ Critical Running │           │
│          │  │      247        │  │       15         │           │
│ Images   │  │ across all imgs │  │ in live contners │           │
│ (future) │  └─────────────────┘  └─────────────────┘           │
│          │                                                      │
│          │  Critical Vulnerabilities in Running Containers      │
│          │  ┌──────────────────────────────────────────────┐    │
│          │  │ CVE ID      │ Severity │ Package │ Image     │    │
│          │  │ CVE-2024-.. │ CRITICAL │ openssl │ nginx:... │    │
│          │  │ CVE-2023-.. │ CRITICAL │ zlib    │ redis:7   │    │
│          │  └──────────────────────────────────────────────┘    │
└──────────┴──────────────────────────────────────────────────────┘
```

### 2. Running Containers (`/running`)
Uses: `GET /vulnerabilities/critical/running`

Full-page table of all critical vulnerabilities across running containers.
Columns: CVE ID | Severity | CVSS | EPSS | KEV | Package | Version | Fixed

```
┌─────────────────────────────────────────────────────────────────┐
│  ◈  DockerSecurityWatch                                         │
├──────────┬──────────────────────────────────────────────────────┤
│          │  Critical Vulnerabilities — Running Containers  [15] │
│ Dashboard│                                                      │
│          │  ┌──────┬──────────┬──────┬──────┬─────┬─────────┐  │
│ Running  │  │CVE ID│ Severity │ CVSS │ EPSS │ KEV │ Package │  │
│ ←active  │  ├──────┼──────────┼──────┼──────┼─────┼─────────┤  │
│          │  │CVE-..│ CRITICAL │ 9.8  │ 0.97 │  ✓  │ openssl │  │
│ Images   │  │CVE-..│ CRITICAL │ 8.1  │ 0.44 │     │ zlib    │  │
│ (future) │  └──────┴──────────┴──────┴──────┴─────┴─────────┘  │
└──────────┴──────────────────────────────────────────────────────┘
```

---

## Design Language (matching Dockhand)

### Dark mode (default)
- Background: `#0d1117` (near-black)
- Sidebar: `#161b22` (dark gray)
- Cards/panels: `#1c2128`
- Borders: `#30363d`
- Text primary: `#e6edf3`
- Text muted: `#8b949e`

### Light mode
- Background: `#ffffff`
- Sidebar: `#f6f8fa`
- Cards/panels: `#ffffff`
- Borders: `#d0d7de`
- Text primary: `#24292f`
- Text muted: `#57606a`

### Shared (both modes)
- Critical badge: red pill
- High badge: orange pill
- Medium badge: yellow pill
- Low badge: blue pill
- Active nav item: left accent bar + slightly lighter bg

### Theme switching
- Toggle button in the top-right of the sidebar (sun/moon icon)
- Preference stored in `localStorage` and applied on load (no flash)
- CSS variables on `.dark` class on `<html>` handle the color swap

---

## API Proxy Setup
During development, Vite proxies `/api/*` → `http://localhost:8000/*` so the frontend
never has CORS issues. In production (Docker), FastAPI serves the built static files
via `StaticFiles`. No changes to the backend are needed for Step 1.

---

## Technology Versions
- SvelteKit (latest, ~2.x) with Svelte 5 runes
- Tailwind CSS v4 (`@tailwindcss/vite` plugin, `@import "tailwindcss"` in CSS)
- Custom components (no shadcn CLI — written manually to match shadcn aesthetic)
- Node 20+

---

## Implementation Notes (post-build)
- `"type": "module"` required in `package.json` — SvelteKit/Vite are ESM-only
- Tailwind v4 dark mode: `@custom-variant dark (&:where(.dark, .dark *))` in `app.css`
- API response for `/vulnerabilities/critical/running` returns `running_images[]` at
  the top level; individual vulnerability objects don't carry image_name directly
  (image attribution is a Step 2 enhancement requiring backend changes)
- `$derived(() => ...)` pattern used in SeverityBadge for class computation

---

## Not In Scope for Step 1
- Images list page (requires a new `GET /images` endpoint not yet built)
- Per-image vulnerability detail page (needs image navigation)
- History charts (needs charting library, e.g. LayerChart)
- Search / filtering
- Docker Compose integration of the frontend container
