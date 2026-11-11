#!/usr/bin/env python3
"""End-to-end validation of NET-03 on a GZ::CTF instance.

Drives the platform like a participant with a packet analyser:

1. creates a game and a DynamicContainer challenge through the admin API;
2. registers two players, one team each, and starts one container per team;
3. downloads each team's PCAP from the platform entry URL;
4. reconstructs the FTP passive data connection and extracts the archive;
5. reads the evidence file and recovers the flag;
6. asserts the two flags differ and match the configured template;
7. submits each flag through the native validation endpoint and checks the
   platform accepts the team's own flag and rejects the other team's.

Example:
  python3 tests/gzctf_e2e.py --base-url http://127.0.0.1:3000 \
      --admin-user Admin --admin-pass '***' \
      --image net-03-the-last-transmission:dev
"""

import argparse
import io
import json
import random
import string
import sys
import time
import zipfile

import requests
from scapy.all import TCP, rdpcap

FLAG_TEMPLATE = "AXUM{last_transmission_[TEAM_HASH]}"
FTP_DATA_PORT = 50000
EVIDENCE_PATH = "evidence/incident_summary.txt"
INCIDENT_REFERENCE = "AX-7842"
ARCHIVE_NAME = "confidential_bundle.zip"


class Failure(Exception):
    pass


def say(message):
    print(f"[gzctf-e2e] {message}", flush=True)


def api(session, method, url, expected=200, **kwargs):
    response = session.request(method, url, timeout=30, **kwargs)
    if response.status_code != expected:
        raise Failure(
            f"{method} {url} -> HTTP {response.status_code} (expected {expected}): {response.text[:600]}"
        )
    return response


def register(base, username, password):
    session = requests.Session()
    payload = {"userName": username, "email": f"{username}@example.com", "password": password}
    body = api(session, "POST", f"{base}/api/Account/Register", json=payload).json()
    if body.get("data") != "LoggedIn":
        raise Failure(f"registration for {username} did not log in: {body}")
    return session


def login(base, username, password):
    session = requests.Session()
    api(session, "POST", f"{base}/api/Account/LogIn", json={"userName": username, "password": password})
    return session


def create_team(session, base, name):
    return api(session, "POST", f"{base}/api/Team", json={"name": name, "bio": ""}).json()["id"]


def create_game(session, base, title):
    now = int(time.time())
    payload = {
        "title": title,
        "hidden": True,
        "summary": "Automated NET-03 validation game.",
        "content": "Created by tests/gzctf_e2e.py.",
        "acceptWithoutReview": True,
        "practiceMode": True,
        "start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 3600)),
        "end": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 7 * 24 * 3600)),
        "teamMemberCountLimit": 0,
        "containerCountLimit": 2,
        "bloodBonus": 0,
    }
    return api(session, "POST", f"{base}/api/Edit/Games", json=payload).json()["id"]


def create_challenge(session, base, game_id):
    payload = {"title": "The Last Transmission", "category": "Forensics", "type": "DynamicContainer"}
    return api(session, "POST", f"{base}/api/Edit/Games/{game_id}/Challenges", json=payload).json()["id"]


def configure_challenge(session, base, game_id, challenge_id, args):
    payload = {
        "title": "The Last Transmission",
        "content": "Asterion Technologies incident capture.",
        "category": "Forensics",
        "flagTemplate": FLAG_TEMPLATE,
        "hints": [],
        "isEnabled": True,
        "containerImage": args.image,
        "exposePort": args.expose_port,
        "memoryLimit": 192,
        "cpuCount": 1,
        "storageLimit": 64,
        "networkMode": "Open",
        "enableTrafficCapture": False,
        "originalScore": 150,
        "minScoreRate": 1.0,
        "difficulty": 1.0,
        "submissionLimit": 0,
    }
    api(session, "PUT", f"{base}/api/Edit/Games/{game_id}/Challenges/{challenge_id}", json=payload)


def join_game(session, base, game_id, team_id):
    api(session, "POST", f"{base}/api/Game/{game_id}", json={"teamId": team_id})


def start_container(session, base, game_id, challenge_id):
    return api(session, "POST", f"{base}/api/Game/{game_id}/Container/{challenge_id}").json()


def candidate_bases(entry):
    host, port = entry.rsplit(":", 1)
    bases = [f"http://{host}:{port}"]
    if host not in ("127.0.0.1", "localhost"):
        bases.append(f"http://127.0.0.1:{port}")
    return bases


def download_capture(entry, timeout=60):
    deadline = time.time() + timeout
    last_error = None

    while time.time() < deadline:
        for base in candidate_bases(entry):
            try:
                health = requests.get(f"{base}/health", timeout=5)
                if health.status_code != 200:
                    last_error = f"health at {base} returned {health.status_code}"
                    continue

                landing = requests.get(f"{base}/", timeout=10)
                if landing.status_code != 200 or "The Last Transmission" not in landing.text:
                    raise Failure(f"landing page at {base} did not render")

                capture = requests.get(f"{base}/download", timeout=60)
                if capture.status_code != 200 or not capture.content.startswith(b"\xd4\xc3\xb2\xa1"):
                    raise Failure(f"download at {base} did not return a PCAP")

                return base, capture.content
            except requests.RequestException as error:
                last_error = error
            except Failure as error:
                last_error = error

        time.sleep(2)

    raise Failure(f"could not download the capture from {entry}: {last_error}")


def recover_flag(capture_bytes):
    """Rebuild the archive from the FTP data connection and read the token."""
    packets = rdpcap(io.BytesIO(capture_bytes))

    segments = sorted(
        (
            packet
            for packet in packets
            if packet.haslayer(TCP) and packet.haslayer("Raw") and packet[TCP].sport == FTP_DATA_PORT
        ),
        key=lambda packet: packet[TCP].seq,
    )

    if not segments:
        raise Failure("FTP data connection is not present in the capture")

    payload = b"".join(bytes(packet[TCP].payload) for packet in segments)

    if not payload.startswith(b"PK\x03\x04"):
        raise Failure("recovered data connection payload is not a ZIP archive")

    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        if archive.namelist() != [EVIDENCE_PATH]:
            raise Failure(f"unexpected archive members: {archive.namelist()}")
        report = archive.read(EVIDENCE_PATH).decode("utf-8")

    if INCIDENT_REFERENCE not in report:
        raise Failure("evidence file is missing the incident reference")
    if ARCHIVE_NAME not in "confidential_bundle.zip":
        raise Failure("archive name mismatch")

    for line in report.splitlines():
        line = line.strip()
        if line.startswith("AXUM{") and line.endswith("}"):
            return line

    raise Failure("evidence file does not contain a flag")


def submit_and_wait(session, base, game_id, challenge_id, flag):
    response = api(
        session, "POST", f"{base}/api/Game/{game_id}/Challenges/{challenge_id}", json={"flag": flag}
    )
    submission_id = response.json()

    for _ in range(30):
        status = api(
            session,
            "GET",
            f"{base}/api/Game/{game_id}/Challenges/{challenge_id}/Status/{submission_id}",
        ).json()
        if status != "FlagSubmitted":
            return status
        time.sleep(0.5)

    raise Failure("submission status never settled")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default="http://127.0.0.1:3000")
    parser.add_argument("--admin-user", required=True)
    parser.add_argument("--admin-pass", required=True)
    parser.add_argument("--image", default="net-03-the-last-transmission:dev")
    parser.add_argument("--expose-port", type=int, default=8080)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=4))
    report = {"suffix": suffix}

    admin = login(base, args.admin_user, args.admin_pass)
    say("admin session established")

    game_id = create_game(admin, base, f"NET-03 validation {suffix}")
    challenge_id = create_challenge(admin, base, game_id)
    configure_challenge(admin, base, game_id, challenge_id, args)
    say(f"game {game_id} / challenge {challenge_id} configured as DynamicContainer")

    teams = {}
    for label in ("team-a", "team-b"):
        username = f"n3{suffix}{label[-1]}"
        password = f"N3t03-{suffix}-{label}!"
        player = register(base, username, password)
        team_id = create_team(player, base, f"NET03 {suffix} {label}")
        join_game(player, base, game_id, team_id)
        teams[label] = {"session": player, "team_id": team_id, "username": username}
        say(f"{label}: user {username}, team {team_id}, joined game")

    flags = {}
    for label, team in teams.items():
        info = start_container(team["session"], base, game_id, challenge_id)
        if info.get("status") != "Running":
            raise Failure(f"{label}: container status is {info.get('status')}, expected Running")
        say(f"{label}: container running at {info['entry']}")

        portal, capture = download_capture(info["entry"])
        say(f"{label}: downloaded {len(capture)} byte capture from {portal}")

        flag = recover_flag(capture)
        flags[label] = flag
        team.update({"entry": info["entry"], "flag": flag})
        say(f"{label}: recovered {flag}")

    if flags["team-a"] == flags["team-b"]:
        raise Failure("both teams received the same dynamic flag")

    for label, flag in flags.items():
        if not flag.startswith("AXUM{last_transmission_") or not flag.endswith("}"):
            raise Failure(f"{label}: recovered '{flag}' does not match the configured template")

    for label, team in teams.items():
        own = submit_and_wait(team["session"], base, game_id, challenge_id, team["flag"])
        if own != "Accepted":
            raise Failure(f"{label}: own flag was not accepted (status {own})")
        say(f"{label}: own flag accepted by GZ::CTF")

    a, b = teams["team-a"], teams["team-b"]
    cross = submit_and_wait(a["session"], base, game_id, challenge_id, b["flag"])
    if cross == "Accepted":
        raise Failure("team A was able to submit team B's flag")
    say(f"team-a: team B's flag rejected (status {cross})")

    cross = submit_and_wait(b["session"], base, game_id, challenge_id, a["flag"])
    if cross == "Accepted":
        raise Failure("team B was able to submit team A's flag")
    say(f"team-b: team A's flag rejected (status {cross})")

    report.update(
        {
            "game_id": game_id,
            "challenge_id": challenge_id,
            "teams": {
                label: {
                    "username": team["username"],
                    "team_id": team["team_id"],
                    "entry": team["entry"],
                    "flag": team["flag"],
                }
                for label, team in teams.items()
            },
            "result": "passed",
        }
    )

    if not args.keep:
        api(admin, "DELETE", f"{base}/api/Edit/Games/{game_id}")
        say("validation game deleted")

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Failure as error:
        say(f"FAILED: {error}")
        sys.exit(1)
