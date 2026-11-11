FROM node:22-alpine AS deps

WORKDIR /app/server

COPY server/package.json server/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:22-alpine

# Python + Scapy build the capture in memory; no raw sockets or extra
# capabilities are required, and none are granted at runtime.
RUN apk add --no-cache python3 py3-pip

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --break-system-packages -r /tmp/requirements.txt \
    && rm -f /tmp/requirements.txt

ENV NODE_ENV=production \
    PORT=3000 \
    RUNTIME_DIR=/app/runtime \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

RUN mkdir -p /app/runtime && chown node:node /app/runtime

COPY --from=deps --chown=node:node /app/server/node_modules ./server/node_modules
COPY --chown=node:node server/package.json server/server.js ./server/
COPY --chown=node:node scripts ./scripts
COPY --chown=node:node public ./public
COPY --chown=node:node entrypoint.sh ./

RUN chmod 0755 /app/entrypoint.sh

USER node

# No EXPOSE: GZ::CTF maps the configured service port, and extra declarations
# would reserve ports for every dynamic instance.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${PORT}/health" || exit 1

CMD ["/app/entrypoint.sh"]
