FROM python:3.12-alpine3.21

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    PCAP_PATH=/app/artifacts/capture.pcap \
    LOG_LEVEL=INFO

WORKDIR /app

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm -f /tmp/requirements.txt

# Dedicated unprivileged account; the artifact directory is the only writable
# location the container requires.
RUN addgroup -g 10001 -S net03 \
    && adduser -u 10001 -S -G net03 -h /app net03 \
    && mkdir -p /app/artifacts \
    && chown -R net03:net03 /app/artifacts

COPY --chown=net03:net03 src ./src
COPY --chown=net03:net03 templates ./templates
COPY --chown=net03:net03 static ./static
COPY --chown=net03:net03 entrypoint.sh ./

RUN chmod 0755 /app/entrypoint.sh

USER net03

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=25s --retries=3 \
    CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status == 200 else 1)"

CMD ["/app/entrypoint.sh"]
