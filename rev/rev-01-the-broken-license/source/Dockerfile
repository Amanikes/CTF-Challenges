FROM alpine:3.20 AS build

WORKDIR /build

RUN apk add --no-cache build-base

COPY src ./src

# Straightforward disassembly is intentional: -O1 with no inlining keeps
# validate_license as a real symbol, symbols are not stripped, and the static
# link makes the downloadable binary run on any Linux x86_64 host. Ordinary
# hardening flags stay on. objcopy only drops DWARF sections that the static
# musl libc objects carry in; .symtab is kept so the binary stays analysable.
RUN gcc -std=c11 -O1 -g0 -fno-inline -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
        -Wall -Wextra -static \
        -o /build/northstar-license src/northstar-license.c \
    && objcopy --strip-debug /build/northstar-license \
    && chmod 0755 /build/northstar-license

FROM node:22-alpine AS deps

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:22-alpine

ENV NODE_ENV=production \
    PORT=3000 \
    ARTIFACT_DIR=/app/runtime

WORKDIR /app

RUN mkdir -p /app/bin /app/runtime && chown node:node /app/bin /app/runtime

COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json entrypoint.sh server.js ./
COPY --chown=node:node scripts ./scripts
COPY --chown=node:node shared ./shared
COPY --chown=node:node public ./public
COPY --chown=node:node package ./package
COPY --from=build --chown=node:node /build/northstar-license ./bin/northstar-license

RUN chmod 0755 /app/entrypoint.sh /app/bin/northstar-license

USER node

# As with the AxumSec web challenges the image declares no EXPOSE: GZ::CTF maps
# the configured service port and extra declarations would reserve ports for
# every dynamic instance.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${PORT}/health" || exit 1

CMD ["/app/entrypoint.sh"]
