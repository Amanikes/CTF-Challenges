#!/usr/bin/env python3
"""End-to-end validation of WEB-01 on a GZ::CTF instance.

The script drives the platform exactly like a player would:

1. creates a game and a DynamicContainer challenge through the admin API;
2. registers two independent players, one team each;
3. joins both teams to the game;
4. starts one container per team;
5. downloads the exposed backup archive from each instance;
6. checks that the archive contains that team's own flag and not the other
   team's flag;
7. submits each flag through the native GZ::CTF validation endpoint and checks
   that the platform accepts it, while cross-team submissions are rejected.

Requirements:
  * an existing GZ::CTF administrator account;
  * open registration on the target instance (or pre-created players);
  * the challenge image already available to the platform (built locally, or
    pushed to a registry and pass --image).

Example:
  python3 tests/gzctf_e2e.py \
      --base-url http://127.0.0.1:8080 \
      --admin-user Admin --admin-pass '***' \
      --image web-01-forgotten-backup:dev
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

FLAG_TEMPLATE = "AXUM{forgotten_backup_[TEAM_HASH]}"
ARCHIVE_PATH = "/backups/"


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
    payload = {
        "userName": username,
        "email": f"{username}@example.com",
        "password": password,
    }
    response = api(session, "POST", f"{base}/api/Account/Register", json=payload)
    body = response.json()
    if body.get("data") != "LoggedIn":
        raise Failure(f"registration for {username} did not log in: {body}")
    return session


def login(base, username, password):
    session = requests.Session()
    api(session, "POST", f"{base}/api/Account/LogIn", json={"userName": username, "password": password})
    return session


def create_team(session, base, name):
    response = api(session, "POST", f"{base}/api/Team", json={"name": name, "bio": ""})
    return response.json()["id"]


def create_game(session, base, title):
    now = int(time.time())
    payload = {
        "title": title,
        "hidden": True,
        "summary": "Automated WEB-01 validation game.",
        "content": "Created by tests/gzctf_e2e.py.",
        "acceptWithoutReview": True,
        "practiceMode": True,
        "start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 3600)),
        "end": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 7 * 24 * 3600)),
        "teamMemberCountLimit": 0,
        "containerCountLimit": 2,
        "bloodBonus": 0,
    }
    response = api(session, "POST", f"{base}/api/Edit/Games", json=payload)
    return response.json()["id"]


def create_challenge(session, base, game_id, title):
    payload = {"title": title, "category": "Web", "type": "DynamicContainer"}
    response = api(session, "POST", f"{base}/api/Edit/Games/{game_id}/Challenges", json=payload)
    return response.json()["id"]


def configure_challenge(session, base, game_id, challenge_id, args):
    payload = {
        "title": "The Forgotten Backup",
        "content": "Northstar Systems migration leftovers.",
        "category": "Web",
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
        "originalScore": 50,
        "minScoreRate": 1.0,
        "difficulty": 1.0,
        "submissionLimit": 0,
    }
    api(session, "PUT", f"{base}/api/Edit/Games/{game_id}/Challenges/{challenge_id}", json=payload)


def join_game(session, base, game_id, team_id):
    api(session, "POST", f"{base}/api/Game/{game_id}", json={"teamId": team_id})


def start_container(session, base, game_id, challenge_id):
    response = api(session, "POST", f"{base}/api/Game/{game_id}/Container/{challenge_id}")
    return response.json()


def fetch_archive(entry, timeout=45):
    host, port = entry.rsplit(":", 1)

    # When ContainerProvider.PublicEntry is not configured the platform reports the
    # container network address together with the published port; the published port
    # is still reachable through the loopback interface on the platform host.
    candidates = [f"http://{host}:{port}"]
    if host not in ("127.0.0.1", "localhost"):
        candidates.append(f"http://127.0.0.1:{port}")

    deadline = time.time() + timeout
    last_error = None

    while time.time() < deadline:
        for base in candidates:
            try:
                health = requests.get(f"{base}/healthz", timeout=5)
                if health.status_code != 200:
                    raise Failure(f"health endpoint at {base} returned {health.status_code}")

                listing = requests.get(f"{base}{ARCHIVE_PATH}", timeout=10)
                if listing.status_code != 200 or "northstar-site-backup.zip" not in listing.text:
                    raise Failure(f"listing at {base} returned {listing.status_code}")

                archive = requests.get(f"{base}{ARCHIVE_PATH}northstar-site-backup.zip", timeout=10)
                if archive.status_code != 200:
                    raise Failure(f"archive at {base} returned {archive.status_code}")
                return archive.content
            except Exception as error:  # noqa: BLE001 - container may still be booting
                last_error = error

        time.sleep(2)

    raise Failure(f"could not download the archive from {entry}: {last_error}")


def extract_flag(archive_bytes):
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        env = archive.read("config/production.env").decode()

    for line in env.splitlines():
        if line.startswith("CTF_FLAG="):
            return line.split("=", 1)[1].strip()

    raise Failure("CTF_FLAG not found in config/production.env")


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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--admin-user", required=True)
    parser.add_argument("--admin-pass", required=True)
    parser.add_argument("--image", default="web-01-forgotten-backup:dev")
    parser.add_argument("--expose-port", type=int, default=3000)
    parser.add_argument("--keep", action="store_true", help="do not delete the generated game")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=4))
    report = {"suffix": suffix}

    admin = login(base, args.admin_user, args.admin_pass)
    say("admin session established")

    game_id = create_game(admin, base, f"WEB-01 validation {suffix}")
    challenge_id = create_challenge(admin, base, game_id, "The Forgotten Backup")
    configure_challenge(admin, base, game_id, challenge_id, args)
    say(f"game {game_id} / challenge {challenge_id} configured as DynamicContainer")

    teams = {}
    for label in ("team-a", "team-b"):
        username = f"w1{suffix}{label[-1]}"
        password = f"W3b01-{suffix}-{label}!"
        player = register(base, username, password)
        team_id = create_team(player, base, f"WEB01 {suffix} {label}")
        join_game(player, base, game_id, team_id)
        teams[label] = {"session": player, "team_id": team_id, "username": username}
        say(f"{label}: user {username}, team {team_id}, joined game")

    flags = {}
    for label, team in teams.items():
        info = start_container(team["session"], base, game_id, challenge_id)
        if info.get("status") != "Running":
            raise Failure(f"{label}: container status is {info.get('status')}, expected Running")
        say(f"{label}: container running at {info['entry']}")

        archive = fetch_archive(info["entry"])
        flag = extract_flag(archive)
        flags[label] = flag
        team["entry"] = info["entry"]
        team["flag"] = flag
        say(f"{label}: recovered {flag}")

    if flags["team-a"] == flags["team-b"]:
        raise Failure("both teams received the same dynamic flag")
    for label, flag in flags.items():
        if not flag.startswith("AXUM{forgotten_backup_") or not flag.endswith("}"):
            raise Failure(f"{label}: flag {flag} does not match the configured template")

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
