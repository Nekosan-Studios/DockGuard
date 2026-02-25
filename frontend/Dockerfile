# ── Build stage ──────────────────────────────────────────────────────────────
FROM node:25-trixie-slim AS builder

WORKDIR /app

# Install deps first so this layer is cached until package files change
COPY package.json package-lock.json ./
RUN npm ci

# Copy source and build
COPY . .
RUN npm run build

# Prune devDependencies so we only carry prod deps into the final image
RUN npm prune --omit=dev

# ── Production stage ──────────────────────────────────────────────────────────
FROM node:22-slim

WORKDIR /app

COPY --from=builder /app/build ./build
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

EXPOSE 3000

ENV NODE_ENV=production

CMD ["node", "build/index.js"]
