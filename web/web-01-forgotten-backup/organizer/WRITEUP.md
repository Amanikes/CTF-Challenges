# WEB-01 — Organizer Writeup (spoilers)

> **Do not distribute.** This file explains the vulnerability and the solution.
> The player-facing text lives in `challenge.yml` → `public.description` and in
> the top of `README.md`.

## Vulnerability

Information disclosure through an accidentally exposed operations backup
directory. The corporate site itself is not vulnerable; the deployment left a
rotated-out backup archive reachable without authentication:

* `robots.txt` advertises `Disallow: /backups/`, a classic leftover from the
  migration;
* `GET /backups/` returns a directory listing (the "misconfigured default
  server index" pattern);
* `GET /backups/northstar-site-backup.zip` downloads the archive;
* the archive contains `config/production.env`, which contains
  `CTF_FLAG=AXUM{forgotten_backup_<team hash>}`.

No SQL injection, authentication bypass, brute force or tooling beyond
`curl`/`unzip` is required.

## Intended discovery path

1. Open the site and look around — nothing points at the vulnerability.
2. Enumerate public resources; `robots.txt` is the intended clue.
3. Follow `Disallow: /backups/` to the directory listing.
4. Download `northstar-site-backup.zip`.
5. Extract it (or read it in memory) and open `config/production.env`.
6. Submit the flag.

Players who skip `robots.txt` usually find the directory with a wordlist
(`feroxbuster`, `gobuster dir -w ... -x zip`); that is acceptable for an easy
challenge.

## Expected commands

```bash
TARGET=http://ctf.axumsec.example
curl -s "$TARGET/robots.txt"
curl -s "$TARGET/backups/"
curl -s -o backup.zip "$TARGET/backups/northstar-site-backup.zip"
unzip -o backup.zip
grep CTF_FLAG config/production.env
```

Expected solve time: 5–15 minutes for a team that checks `robots.txt`.

## How the backup is generated

`source/entrypoint.sh` runs at container start:

1. exits with status 1 if `GZCTF_FLAG` is unset or empty;
2. runs `source/src/generate-backup.js`, which validates the flag, writes
   `config/production.env` plus a handful of site files into
   `northstar-site-backup.zip` under `/app/runtime/backups/` via `yazl`, using a
   staging file and an atomic rename;
3. unsets `GZCTF_FLAG`;
4. `exec`s the Express server.

The archive is rebuilt on every start, so it always matches the flag the
platform injected for that instance. Nothing is baked into the image, and the
`/app/runtime/backups` directory is empty in the published image.

## How the dynamic flag reaches the application

GZ::CTF generates a per-team flag from the template
`AXUM{forgotten_backup_[TEAM_HASH]}`, where `[TEAM_HASH]` is 12 hex characters
derived from the team token. It passes the value as the `GZCTF_FLAG`
environment variable when creating the container. Only the generator reads it;
the web process runs without it. The platform keeps its own copy and validates
submissions natively — the container has no validation logic.

## How GZ::CTF validates submissions

`POST /api/Game/{gameId}/Challenges/{challengeId}` accepts
`{"flag": "..."}` and returns a submission id; the result is polled with
`GET /api/Game/{gameId}/Challenges/{challengeId}/Status/{submissionId}`.
`Accepted` means the flag matches the team's generated flag. A flag from
another team resolves to `WrongAnswer` because the team hash differs.

## Failure scenarios

| Scenario | Effect | Action |
|---|---|---|
| `GZCTF_FLAG` missing | Container exits 1; log line `GZCTF_FLAG is not set; refusing to start` | Check the challenge is `DynamicContainer` and the platform passes the env var. |
| Challenge created as `StaticContainer` | No flag injected | Recreate the challenge as `DynamicContainer` (type is immutable after creation). |
| Archive not generated | `/backups/` empty; container logs show `[backup]` error | Check volume/permissions on `/app/runtime/backups`. |
| Player cached an old archive | Flag rejected after a container recreate | Relaunch and download again; the flag rotates with the container. |
| Platform shows `172.x.x.x:port` | `PublicEntry` unset | Configure `ContainerProvider.PublicEntry`; see `docs/DEPLOYMENT.md`. |
| Robots.txt ignored | Players use directory brute force | Still solvable; intended difficulty tolerates it. |

## Reset and redeploy

* Restart a team's instance: destroy and relaunch it from the UI (or
  `DELETE` then `POST /api/Game/{id}/Container/{challengeId}`). The entrypoint
  regenerates the archive with the newly injected flag.
* Destroy all instances: disable then re-enable the challenge.
* Update the image: push a new tag, change *Container Image*, relaunch
  instances. The challenge is stateless and can be recreated at any time.
* Deleting the game in 1.9.1 removes the database records but running
  containers can survive until the manager reaps them (default 120 min).
  Remove them explicitly if needed.

## Evidence

The full executed test record, including the two platform-generated flags used
during validation, is in `organizer/QA-CHECKLIST.md`.
