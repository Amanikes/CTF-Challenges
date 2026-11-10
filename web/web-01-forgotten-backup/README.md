# WEB-01 — The Forgotten Backup

| | |
|---|---|
| Category | Web Exploitation |
| Difficulty | Easy |
| Points | 50 |
| Flag format | `AXUM{...}` |
| Platform | GZ::CTF 1.9.x, `DynamicContainer` |
| Per-team flag | Yes (`GZCTF_FLAG`) |
| Expected solve time | 5–15 minutes |

## Player-facing description

> ### Story
>
> Northstar Systems recently launched its new corporate website.
>
> Everything appears to be working perfectly, but something from the previous
> deployment may have been left behind.
>
> The development team claims the migration was completed successfully.
>
> Are you sure?
>
> ### Objective
>
> Investigate the website and recover the hidden flag.

The website is a believable, static-feeling corporate site for the fictional
Northstar Systems. There is no CTF branding and nothing on the page points at
the vulnerability.

## Repository layout

```
web-01-forgotten-backup/
├── challenge.yml              # deployment values, mapped to GZ::CTF fields
├── README.md                  # this file
├── source/
│   ├── Dockerfile             # node:22-alpine, non-root, no EXPOSE
│   ├── package.json           # express 5 + yazl
│   ├── package-lock.json
│   ├── entrypoint.sh          # validates GZCTF_FLAG, builds archive, starts app
│   ├── src/
│   │   ├── server.js          # Express app, /backups/ listing and download
│   │   └── generate-backup.js # runtime archive generation
│   └── public/                # homepage, CSS, robots.txt, favicon
├── organizer/                 # ⚠ spoilers — never ship to players
│   ├── WRITEUP.md
│   ├── SOLUTION.md
│   └── QA-CHECKLIST.md
├── docs/
│   ├── ARCHITECTURE.md
│   └── DEPLOYMENT.md
└── tests/
    ├── run-local-docker-tests.sh  # full local test plan
    └── gzctf_e2e.py               # two-team platform validation
```

## Quick start (local Docker)

```bash
cd source
docker build -t web-01-forgotten-backup:dev .

docker run --rm -d --name web01 \
  -e 'GZCTF_FLAG=AXUM{local_test_flag}' \
  -p 127.0.0.1:3000:3000 \
  web-01-forgotten-backup:dev
```

Then open <http://127.0.0.1:3000/>.

`GZCTF_FLAG` is mandatory: without it the entrypoint exits with status 1 and the
container never serves traffic.

## Running the test plan

```bash
./tests/run-local-docker-tests.sh          # local Docker behaviour
python3 tests/gzctf_e2e.py --help          # two-team platform validation
```

Results of the executed test plan are recorded in
[organizer/QA-CHECKLIST.md](organizer/QA-CHECKLIST.md).

## Documentation

* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — components and flag lifecycle
* [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — build, registry, GZ::CTF setup, reset
* [organizer/WRITEUP.md](organizer/WRITEUP.md) — vulnerability and solution
* [organizer/SOLUTION.md](organizer/SOLUTION.md) — copy-paste solve commands
* [organizer/QA-CHECKLIST.md](organizer/QA-CHECKLIST.md) — verification evidence

## License / usage

Internal AxumSec competition material. Do not publish `organizer/` or the
challenge image before the event ends.
