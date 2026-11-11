#!/usr/bin/env python3
"""End-to-end validation of REV-02 on a GZ::CTF instance.

Drives the platform like a participant:

1. creates a game and a DynamicContainer challenge through the admin API;
2. registers two players, one team each, and starts one container per team;
3. downloads each team's ZIP from the platform entry URL;
4. recovers the token with scripts/verify_solution.py (organizer logic, no
   generator involvement);
5. asserts the two tokens differ and match the configured template;
6. submits each token through the native validation endpoint and checks the
   platform accepts the team's own token and rejects the other team's.

Example:
  python3 tests/gzctf_e2e.py --base-url http://127.0.0.1:3000 \
      --admin-user Admin --admin-pass '***' --image rev-02-phantom-protocol:dev
"""

import argparse
import io
import json
import random
import string
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

import requests

FLAG_TEMPLATE = "AXUM{phantom_protocol_[TEAM_HASH]}"
ROOT = Path(__file__).resolve().parent.parent
RECOVERY = ROOT / "scripts" / "verify_solution.py"


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
        "summary": "Automated REV-02 validation game.",
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
    payload = {"title": "Phantom Protocol", "category": "Reverse", "type": "DynamicContainer"}
    return api(session, "POST", f"{base}/api/Edit/Games/{game_id}/Challenges", json=payload).json()["id"]


def configure_challenge(session, base, game_id, challenge_id, args):
    payload = {
        "title": "Phantom Protocol",
        "content": "Aegis Communications intercept analysis.",
        "category": "Reverse",
        "flagTemplate": FLAG_TEMPLATE,
        "hints": [],
        "isEnabled": True,
        "containerImage": args.image,
        "exposePort": args.expose_port,
        "memoryLimit": 128,
        "cpuCount": 1,
        "storageLimit": 64,
        "networkMode": "Open",
        "enableTrafficCapture": False,
        "originalScore": 300,
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


def download_package(entry, timeout=60):
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
                if landing.status_code != 200 or "Phantom Protocol" not in landing.text:
                    raise Failure(f"landing page at {base} did not render")

                archive = requests.get(f"{base}/download", timeout=30)
                if archive.status_code != 200 or not archive.content.startswith(b"PK"):
                    raise Failure(f"download at {base} did not return a ZIP archive")

                return base, archive.content
            except requests.RequestException as error:
                last_error = error
            except Failure as error:
                last_error = error

        time.sleep(2)

    raise Failure(f"could not download the package from {entry}: {last_error}")


def recover_token(archive_bytes):
    with tempfile.TemporaryDirectory() as workdir:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            names = sorted(archive.namelist())
            expected = sorted(
                [
                    "phantom-protocol/README.txt",
                    "phantom-protocol/phantom-client",
                    "phantom-protocol/protocol.dat",
                ]
            )
            if names != expected:
                raise Failure(f"unexpected archive contents: {names}")

        path = Path(workdir) / "package.zip"
        path.write_bytes(archive_bytes)

        result = subprocess.run(
            [sys.executable, str(RECOVERY), "--archive", str(path), "--quiet"],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            raise Failure(f"recovery failed: {result.stderr.strip()[:400]}")

        return result.stdout.strip()


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
    parser.add_argument("--image", default="rev-02-phantom-protocol:dev")
    parser.add_argument("--expose-port", type=int, default=3000)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=4))
    report = {"suffix": suffix}

    admin = login(base, args.admin_user, args.admin_pass)
    say("admin session established")

    game_id = create_game(admin, base, f"REV-02 validation {suffix}")
    challenge_id = create_challenge(admin, base, game_id)
    configure_challenge(admin, base, game_id, challenge_id, args)
    say(f"game {game_id} / challenge {challenge_id} configured as DynamicContainer")

    teams = {}
    for label in ("team-a", "team-b"):
        username = f"r2{suffix}{label[-1]}"
        password = f"R3v02-{suffix}-{label}!"
        player = register(base, username, password)
        team_id = create_team(player, base, f"REV02 {suffix} {label}")
        join_game(player, base, game_id, team_id)
        teams[label] = {"session": player, "team_id": team_id, "username": username}
        say(f"{label}: user {username}, team {team_id}, joined game")

    flags = {}
    for label, team in teams.items():
        info = start_container(team["session"], base, game_id, challenge_id)
        if info.get("status") != "Running":
            raise Failure(f"{label}: container status is {info.get('status')}, expected Running")
        say(f"{label}: container running at {info['entry']}")

        portal, archive = download_package(info["entry"])
        say(f"{label}: downloaded {len(archive)} byte package from {portal}")

        flag = recover_token(archive)
        flags[label] = flag
        team.update({"entry": info["entry"], "flag": flag})
        say(f"{label}: recovered {flag}")

    if flags["team-a"] == flags["team-b"]:
        raise Failure("both teams received the same dynamic flag")

    for label, flag in flags.items():
        if not flag.startswith("AXUM{phantom_protocol_") or not flag.endswith("}"):
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
