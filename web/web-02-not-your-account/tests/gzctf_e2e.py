#!/usr/bin/env python3
"""End-to-end validation of WEB-02 on a GZ::CTF instance.

Drives the platform like real teams:

1. creates a game and a DynamicContainer challenge through the admin API;
2. registers two independent players, one team each, and joins both to the game;
3. starts one container per team;
4. logs into each bank instance with the published participant credentials;
5. follows the intended IDOR path (`/api/accounts/1002`) and recovers each
   team's flag;
6. checks that the two flags differ, that each instance only serves its own
   flag, and that GZ::CTF accepts each team's own flag but rejects the other
   team's flag;
7. deletes the throw-away game.

Requirements:
  * an existing GZ::CTF administrator account;
  * open registration on the target instance (or pre-created players);
  * the challenge image available to the platform (built locally or pushed to
    a registry and passed with --image).

Example:
  python3 tests/gzctf_e2e.py \
      --base-url http://127.0.0.1:8080 \
      --admin-user Admin --admin-pass '***' \
      --image web-02-not-your-account:dev
"""

import argparse
import json
import random
import re
import string
import sys
import time

import requests

FLAG_PATTERN = re.compile(r"^AXUM\{not_your_account_[0-9a-f]{12}\}$")
BANK_USER = "alex"
BANK_PASSWORD = "Northstar@2026"


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
    response = api(
        session,
        "POST",
        f"{base}/api/Account/Register",
        json={"userName": username, "email": f"{username}@example.com", "password": password},
    )
    if response.json().get("data") != "LoggedIn":
        raise Failure(f"registration for {username} did not log in: {response.json()}")
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
        "summary": "Automated WEB-02 validation game.",
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
    payload = {"title": "Not Your Account", "category": "Web", "type": "DynamicContainer"}
    return api(session, "POST", f"{base}/api/Edit/Games/{game_id}/Challenges", json=payload).json()["id"]


def configure_challenge(session, base, game_id, challenge_id, args):
    payload = {
        "title": "Not Your Account",
        "content": "Northstar Bank portal with an access-control flaw.",
        "category": "Web",
        "flagTemplate": "AXUM{not_your_account_[TEAM_HASH]}",
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
    return api(session, "POST", f"{base}/api/Game/{game_id}/Container/{challenge_id}").json()


def bank_base_urls(entry):
    host, port = entry.rsplit(":", 1)

    # Without ContainerProvider.PublicEntry the platform reports the container
    # network address together with the published host port; that port is still
    # reachable through the loopback interface on the platform host.
    candidates = [f"http://{host}:{port}"]
    if host not in ("127.0.0.1", "localhost"):
        candidates.append(f"http://127.0.0.1:{port}")
    return candidates


def wait_for_bank(candidates, timeout=45):
    deadline = time.time() + timeout
    last_error = None

    while time.time() < deadline:
        for base in candidates:
            try:
                if requests.get(f"{base}/healthz", timeout=5).status_code == 200:
                    return base
            except Exception as error:  # noqa: BLE001 - container may still be booting
                last_error = error
        time.sleep(2)

    raise Failure(f"bank instance never became reachable: {last_error}")


def bank_login(base):
    session = requests.Session()
    response = session.post(
        f"{base}/login",
        data={"username": BANK_USER, "password": BANK_PASSWORD},
        allow_redirects=False,
        timeout=10,
    )
    if response.status_code != 303 or "/dashboard" not in response.headers.get("Location", ""):
        raise Failure(f"bank login failed: HTTP {response.status_code}")
    return session


def read_idor_flag(base):
    session = bank_login(base)
    unauth = requests.get(f"{base}/api/accounts/1002", timeout=10)
    if unauth.status_code != 401:
        raise Failure(f"account API is readable without a session (HTTP {unauth.status_code})")

    own = session.get(f"{base}/api/accounts/1001", timeout=10)
    if own.status_code != 200 or own.json().get("customer", {}).get("name") != "Alex Morgan":
        raise Failure(f"could not read own account: HTTP {own.status_code}")

    target = session.get(f"{base}/api/accounts/1002", timeout=10)
    if target.status_code != 200:
        raise Failure(f"IDOR request failed: HTTP {target.status_code}")

    body = target.json()
    if body.get("customer", {}).get("name") != "Jordan Lee":
        raise Failure("IDOR response does not belong to Jordan Lee")

    flag = body.get("flag")
    if not flag:
        raise Failure("IDOR response contains no flag")

    return flag


def submit_and_wait(session, base, game_id, challenge_id, flag):
    submission_id = api(
        session, "POST", f"{base}/api/Game/{game_id}/Challenges/{challenge_id}", json={"flag": flag}
    ).json()

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
    parser.add_argument("--image", default="web-02-not-your-account:dev")
    parser.add_argument("--expose-port", type=int, default=3000)
    parser.add_argument("--keep", action="store_true", help="do not delete the generated game")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=4))
    report = {"suffix": suffix}

    admin = login(base, args.admin_user, args.admin_pass)
    say("admin session established")

    game_id = create_game(admin, base, f"WEB-02 validation {suffix}")
    challenge_id = create_challenge(admin, base, game_id)
    configure_challenge(admin, base, game_id, challenge_id, args)
    say(f"game {game_id} / challenge {challenge_id} configured as DynamicContainer")

    teams = {}
    for label in ("team-a", "team-b"):
        username = f"w2{suffix}{label[-1]}"
        password = f"W3b02-{suffix}-{label}!"
        player = register(base, username, password)
        team_id = create_team(player, base, f"WEB02 {suffix} {label}")
        join_game(player, base, game_id, team_id)
        teams[label] = {"session": player, "team_id": team_id, "username": username}
        say(f"{label}: user {username}, team {team_id}, joined game")

    for label, team in teams.items():
        info = start_container(team["session"], base, game_id, challenge_id)
        if info.get("status") != "Running":
            raise Failure(f"{label}: container status is {info.get('status')}, expected Running")

        bank_base = wait_for_bank(bank_base_urls(info["entry"]))
        flag = read_idor_flag(bank_base)
        team["bank"] = bank_base
        team["flag"] = flag
        say(f"{label}: container at {info['entry']} returned {flag}")

    if teams["team-a"]["flag"] == teams["team-b"]["flag"]:
        raise Failure("both teams received the same dynamic flag")

    for label, team in teams.items():
        if not FLAG_PATTERN.match(team["flag"]):
            raise Failure(f"{label}: flag {team['flag']} does not match the template")

    other_flag = {
        "team-a": teams["team-b"]["flag"],
        "team-b": teams["team-a"]["flag"],
    }

    for label, team in teams.items():
        session = bank_login(team["bank"])
        response = session.get(f"{team['bank']}/api/accounts/1002", timeout=10)
        if other_flag[label] in response.text:
            raise Failure(f"{label}: instance leaks the other team's flag")

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
                    "bank": team["bank"],
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
