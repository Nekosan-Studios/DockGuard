#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIDS=()

# Clear any stale VIRTUAL_ENV from a previous or renamed project — uv manages its own venv.
unset VIRTUAL_ENV

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

# ─── kill previous instances ─────────────────────────────────────────────────
kill_port() {
    local port=$1
    local pids
    pids=$(lsof -ti :"$port" 2>/dev/null) || true
    if [[ -n "$pids" ]]; then
        warn "Killing existing process(es) on port $port (PIDs: $(echo $pids | tr '\n' ' '))"
        echo "$pids" | xargs kill 2>/dev/null || true
        sleep 1
    fi
}

kill_port 8765
kill_port 5173

# ─── start backend ──────────────────────────────────────────────────────────────
echo "Starting backend  :8765 ..."
(cd "$SCRIPT_DIR" && uv run python -m uvicorn backend.api:app --reload --port 8765) &
BACKEND_PID=$!
PIDS+=("$BACKEND_PID")

# Give it a moment to fail fast (import errors, missing deps, port conflict, etc.)
sleep 2
if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    err "Backend failed to start — check output above."
    exit 1
fi
info "Backend process alive (PID $BACKEND_PID)"

# ─── start frontend ─────────────────────────────────────────────────────────────
echo "Starting frontend :5173 ..."
(cd "$SCRIPT_DIR/frontend" && npm run dev) &
FRONTEND_PID=$!
PIDS+=("$FRONTEND_PID")

# Give Vite a moment to fail fast (missing node_modules, config error, etc.)
sleep 2
if ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
    err "Frontend failed to start — check output above."
    exit 1
fi
info "Frontend process alive (PID $FRONTEND_PID)"

# ─── wait for Vite, then open browser ───────────────────────────────────────────
printf "\nWaiting for Vite dev server"
for i in {1..30}; do
    # Check both processes are still alive on every iteration.
    if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
        echo
        err "Backend process died unexpectedly — aborting."
        exit 1
    fi
    if ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
        echo
        err "Frontend process died unexpectedly — aborting."
        exit 1
    fi
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
