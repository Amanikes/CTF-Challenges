"""Incident bundle generation for NET-03 — The Last Transmission.

The ZIP is built in memory and is the exact binary payload that the synthetic
FTP data connection carries. It is stored uncompressed so the transferred
payload spans several TCP segments and stays byte-for-byte inspectable.
"""

import io
import zipfile

ARCHIVE_NAME = "confidential_bundle.zip"
EVIDENCE_PATH = "evidence/incident_summary.txt"
EVIDENCE_IDENTIFIER = "AXUM-INCIDENT-03"
INCIDENT_REFERENCE = "AX-7842"

# Fixed metadata keeps the archive byte-identical for the same flag.
FIXED_DATE = (2026, 7, 2, 9, 20, 0)

REPORT_TEMPLATE = """\
ASTERION TECHNOLOGIES
CONFIDENTIAL INCIDENT REPORT

Incident Reference: AX-7842
Classification: INTERNAL

The following transmission was recovered from the affected workstation.

Recovered evidence identifier:
AXUM-INCIDENT-03

Verification token:
{flag}

--------------------------------------------------------------------------
HANDLING NOTICE
--------------------------------------------------------------------------

This bundle was recovered by the incident response team during the
investigation of the suspected data breach affecting the Asterion
Technologies engineering segment. It must not be copied, forwarded or
retained outside the incident workspace.

The archive was reconstructed from a packet capture taken on the affected
network segment on 2 July 2026. The capture covers the period immediately
preceding the disappearance of the confidential material.

--------------------------------------------------------------------------
OBSERVATIONS
--------------------------------------------------------------------------

1. Workstation 10.10.20.15 resolved an unfamiliar host shortly before the
   transfer began. The name had not been seen on this segment before.

2. The workstation then opened a short series of ordinary looking web
   requests against the resolved address. Individual requests carried no
   sensitive content; the response bodies identify the transfer session.

3. A file transfer session followed. The transfer used the standard file
   transfer protocol over the control port, negotiated a passive data port,
   and retrieved a single archive.

4. The archive was removed from the workstation filesystem before the
   response team was able to image the disk.

--------------------------------------------------------------------------
EVIDENCE
--------------------------------------------------------------------------

The recovered archive is the object referenced by the transfer session. Its
verification token is reproduced above and is unique to this case. Tokens
from other workspaces are not valid for this investigation.

--------------------------------------------------------------------------
CONTAINMENT
--------------------------------------------------------------------------

The affected workstation was isolated from the segment, the destination
address was blocked at the perimeter, and the credentials used for the
transfer were revoked. No further sessions to the destination address were
observed after containment.

Analysts are reminded that the destination address is documentation-only and
does not resolve on production networks; this bundle is training material.

--------------------------------------------------------------------------
END OF REPORT
--------------------------------------------------------------------------
"""


class ArtifactError(ValueError):
    """Raised when the incident bundle cannot be built or validated."""


# The flag placeholder is substituted with the runtime value; the archive
# itself is built deterministically from that value.
def build_report(flag):
    """Render the evidence file for the given runtime flag."""
    if not isinstance(flag, str) or flag == "":
        raise ArtifactError("flag must be a non-empty string")
    return REPORT_TEMPLATE.format(flag=flag)


def build_bundle(flag):
    """Return the ZIP bytes for the given runtime flag."""
    report = build_report(flag).encode("utf-8")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo(EVIDENCE_PATH, date_time=FIXED_DATE)
        info.compress_type = zipfile.ZIP_STORED
        info.external_attr = (0o644 & 0xFFFF) << 16
        archive.writestr(info, report)

    return buffer.getvalue()


def validate_bundle(data, flag):
    """Re-open the archive and confirm structure, content and flag."""
    if not data:
        raise ArtifactError("archive is empty")

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        broken = archive.testzip()
        if broken is not None:
            raise ArtifactError(f"archive member failed its CRC check: {broken}")

        names = sorted(archive.namelist())
        if names != [EVIDENCE_PATH]:
            raise ArtifactError(f"unexpected archive contents: {names}")

        report = archive.read(EVIDENCE_PATH).decode("utf-8")

    if "ASTERION TECHNOLOGIES" not in report:
        raise ArtifactError("evidence file is missing the organisation header")
    if INCIDENT_REFERENCE not in report:
        raise ArtifactError("evidence file is missing the incident reference")
    if EVIDENCE_IDENTIFIER not in report:
        raise ArtifactError("evidence file is missing the evidence identifier")
    if flag not in report:
        raise ArtifactError("evidence file does not contain the runtime flag")

    return {
        "bytes": len(data),
        "members": names,
        "report_bytes": len(report.encode("utf-8")),
    }
