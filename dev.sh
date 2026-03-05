#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIDS=()

# Colors
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
GREEN=$'\033[0;32m'
BOLD=$'\033[1m'
NC=$'\033[0m'

info() { printf "${GREEN}✓${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}⚠${NC}  %s\n" "$*"; }
err()  { printf "${RED}✗${NC} %s\n" "$*"; }

# ─── cleanup on Ctrl+C / exit ───────────────────────────────────────────────────
cleanup() {
    echo
    echo "Shutting down..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    echo "Done."
}
trap cleanup EXIT INT TERM

# ─── dependency checks ──────────────────────────────────────────────────────────
echo "${BOLD}DockGuard — dev${NC}"
echo

MISSING=0

if command -v uv &>/dev/null; then
    info "uv $(uv --version)"
else
    err "uv not found — https://docs.astral.sh/uv/"
    MISSING=1
fi

if command -v npm &>/dev/null; then
    info "node $(node --version)  npm $(npm --version)"
else
    err "npm not found"
    MISSING=1
fi

if [[ ! -d "$SCRIPT_DIR/frontend/node_modules" ]]; then
    err "frontend/node_modules missing — run: cd frontend && npm install"
    MISSING=1
fi

if command -v grype &>/dev/null; then
    info "grype found"
else
    warn "grype not found — vulnerability scans will fail  (brew install grype)"
fi

if docker info &>/dev/null 2>&1; then
    info "Docker daemon running"
else
    warn "Docker daemon not running — container detection will be unavailable"
fi

echo
[[ "$MISSING" -ne 0 ]] && { err "Fix the above and re-run."; exit 1; }

# ─── start backend ──────────────────────────────────────────────────────────────
echo "Starting backend  :8765 ..."
(cd "$SCRIPT_DIR" && uv run uvicorn backend.api:app --reload --port 8765) &
PIDS+=($!)

# ─── start frontend ─────────────────────────────────────────────────────────────
echo "Starting frontend :5173 ..."
(cd "$SCRIPT_DIR/frontend" && npm run dev) &
PIDS+=($!)

# ─── wait for Vite, then open browser ───────────────────────────────────────────
printf "\nWaiting for Vite dev server"
for i in {1..30}; do
    if curl -s -o /dev/null http://localhost:5173; then
        echo
        info "Dev server ready — opening http://localhost:5173"
        if command -v open &>/dev/null; then
            open "http://localhost:5173"       # macOS
        elif command -v xdg-open &>/dev/null; then
            xdg-open "http://localhost:5173"   # Linux
        fi
        break
    fi
    printf "."
    sleep 1
done

# ─── status and hand off ────────────────────────────────────────────────────────
echo
echo "${BOLD}Services running${NC}"
echo "  Backend  → http://localhost:8765"
echo "  Frontend → http://localhost:5173"
echo
echo "Press Ctrl+C to stop all."
echo

wait
