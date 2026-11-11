FROM python:3.12-alpine3.21

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    PCAP_PATH=/app/runtime/capture.pcap \
    LOG_LEVEL=INFO

WORKDIR /app

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm -f /tmp/requirements.txt

# Dedicated unprivileged account; the artifact directory is the only writable
# path the container needs.
RUN addgroup -g 10001 -S net02 \
    && adduser -u 10001 -S -G net02 -h /app net02 \
    && mkdir -p /app/runtime \
    && chown -R net02:net02 /app/runtime

COPY --chown=net02:net02 src ./src
COPY --chown=net02:net02 templates ./templates
COPY --chown=net02:net02 static ./static
COPY --chown=net02:net02 entrypoint.sh ./

RUN chmod 0755 /app/entrypoint.sh

USER net02

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status == 200 else 1)"

CMD ["/app/entrypoint.sh"]
