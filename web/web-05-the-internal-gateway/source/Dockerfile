FROM node:22-alpine AS deps

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:22-alpine

ENV NODE_ENV=production \
    PORT=3000 \
    INTERNAL_PORT=9000

WORKDIR /app

COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json entrypoint.sh ./
COPY --chown=node:node gateway ./gateway
COPY --chown=node:node internal ./internal
COPY --chown=node:node public ./public

RUN chmod 0755 /app/entrypoint.sh

USER node

# Only the gateway port is reachable from outside the container. The internal
# diagnostics service binds 127.0.0.1 and is never published. As with the other
# AxumSec web challenges the image declares no EXPOSE, because GZ::CTF maps the
# configured service port and extra declarations would reserve ports per
# dynamic instance.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${PORT}/health" || exit 1

CMD ["/app/entrypoint.sh"]
