# ── Stage 1: Frontend Builder ──────────────────────────────────────────
FROM node:25-alpine AS frontend-builder

WORKDIR /app/frontend

# Install deps first for caching
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

# Copy source and build
COPY frontend/ .
RUN npm run check
RUN npm run build

# Prune devDependencies
RUN npm prune --omit=dev

# ── Stage 2: Backend & Base Image ──────────────────────────────────────
FROM python:3.14.3-alpine

# Install system dependencies
RUN apk add --no-cache \
    curl \
    ca-certificates \
    tzdata \
    supervisor \
    nodejs \
    npm

# Install grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin v0.109.0

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install Python dependencies
RUN uv sync --no-dev --frozen

# Copy application source
COPY backend/ ./backend/
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Copy frontend build from Stage 1
COPY --from=frontend-builder /app/frontend/build ./frontend/build
COPY --from=frontend-builder /app/frontend/node_modules ./frontend/node_modules
COPY --from=frontend-builder /app/frontend/package.json ./frontend/

# Create data directory
RUN mkdir -p /app/data

EXPOSE 8765 3000

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
