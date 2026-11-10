FROM node:22-alpine AS deps

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:22-alpine

ENV NODE_ENV=production \
    PORT=3000 \
    BACKUP_DIR=/app/runtime/backups

WORKDIR /app

COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json entrypoint.sh ./
COPY --chown=node:node src ./src
COPY --chown=node:node public ./public

RUN chmod 0755 /app/entrypoint.sh \
    && mkdir -p /app/runtime/backups \
    && chown -R node:node /app/runtime

USER node

# GZ::CTF maps the container port configured on the challenge; the image must
# not declare EXPOSE, otherwise every dynamic instance reserves extra ports.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- "http://127.0.0.1:${PORT}/healthz" >/dev/null || exit 1

CMD ["/app/entrypoint.sh"]
