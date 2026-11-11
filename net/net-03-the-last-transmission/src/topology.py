"""Synthetic network topology for NET-03 — The Last Transmission.

Every address is from a documentation-only range (RFC 5737 / RFC 1918). No
packet is ever transmitted: these values only label layers that Scapy
serialises to a file.
"""

# Internal workstation under investigation
CLIENT_IP = "10.10.20.15"
CLIENT_MAC = "02:00:5e:0a:14:0f"

# Internal recursive resolver
DNS_IP = "10.10.20.1"
DNS_MAC = "02:00:5e:0a:14:01"

# Default gateway: frames leaving the segment are addressed to it, which is
# what a capture taken on the segment actually shows.
GATEWAY_MAC = "02:00:5e:0a:14:fe"

# Suspicious external server
SERVER_IP = "192.0.2.80"
SERVER_HOSTNAME = "files-update.example.test"

# Additional documentation-range peers used for background noise
BACKUP_IP = "192.0.2.140"
BACKUP_HOSTNAME = "backup.asterion.internal"

FTP_CONTROL_PORT = 21
FTP_DATA_PORT = 50000

HTTP_PORT = 80
HTTPS_PORT = 443

DNS_PORT = 53

# Passive-mode port encoding: 50000 = 195 * 256 + 80
PASV_HIGH = FTP_DATA_PORT // 256
PASV_LOW = FTP_DATA_PORT % 256

INCIDENT_REFERENCE = "AX-7842"
ARCHIVE_NAME = "confidential_bundle.zip"
FTP_USER = "evidence"
FTP_PASSWORD = "archive-access"

# 2026-07-02T09:20:00Z — fixed so captures are reproducible.
BASE_TIME = 1_782_648_000.0
