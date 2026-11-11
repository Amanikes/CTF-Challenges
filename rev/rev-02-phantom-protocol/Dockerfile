FROM alpine:3.20 AS build

WORKDIR /build

RUN apk add --no-cache build-base

COPY src ./src

# -O1 keeps the three transformation stages as a readable loop; -fno-inline
# keeps them in their own functions. -s strips all symbols for the release
# binary, and the static link lets participants run it on any Linux x86_64 host.
RUN gcc -std=c11 -O1 -fno-inline -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
        -Wall -Wextra -static -s \
        -o /build/phantom-client src/phantom_client.c \
    && chmod 0755 /build/phantom-client

FROM node:22-alpine AS deps

WORKDIR /app/server

COPY server/package.json server/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:22-alpine

RUN apk add --no-cache python3

ENV NODE_ENV=production \
    PORT=3000 \
    RUNTIME_DIR=/app/runtime

WORKDIR /app

RUN mkdir -p /app/bin /app/runtime && chown node:node /app/bin /app/runtime

COPY --from=deps --chown=node:node /app/server/node_modules ./server/node_modules
COPY --chown=node:node server/package.json server/server.js ./server/
COPY --chown=node:node generator ./generator
COPY --chown=node:node public ./public
COPY --chown=node:node package ./package
COPY --chown=node:node entrypoint.sh ./
COPY --from=build --chown=node:node /build/phantom-client ./bin/phantom-client

RUN chmod 0755 /app/entrypoint.sh /app/bin/phantom-client

USER node

# No EXPOSE: GZ::CTF maps the configured service port, and extra declarations
# would reserve ports for every dynamic instance.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${PORT}/health" || exit 1

CMD ["/app/entrypoint.sh"]
