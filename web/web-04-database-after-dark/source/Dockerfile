FROM node:22-alpine AS deps

WORKDIR /app

RUN apk add --no-cache --virtual .build-deps \
    python3 \
    make \
    g++

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:22-alpine

ENV NODE_ENV=production \
    PORT=3000 \
    DB_PATH=/app/data/inventory.db

WORKDIR /app

# Create writable data directory for SQLite database with node ownership
RUN mkdir -p /app/data && chown -R node:node /app/data

COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json entrypoint.sh ./
COPY --chown=node:node src ./src
COPY --chown=node:node public ./public

RUN chmod 0755 /app/entrypoint.sh

USER node

# GZ::CTF maps the configured challenge port; declaring EXPOSE would reserve
# extra ports for every dynamic instance (see upstream challenge templates).
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- "http://127.0.0.1:${PORT}/healthz" >/dev/null || exit 1

CMD ["/app/entrypoint.sh"]
