# WEB-03 — Organizer Writeup (spoilers)

> **Do not distribute.** This file contains the solution. Participant-facing
> material lives in `challenge.yml` → `public.description` and
> `release/README.txt`.

## Challenge summary

Meridian Technologies' project portal ships a JavaScript bundle that still
contains a disabled internal-preview client and the route it calls. The route is
never rendered in the dashboard and is never requested during normal use, but it
is readable in the bundle. Requesting it returns an internal, pre-release project
record together with the per-team flag.

| | |
|---|---|
| Category | Web |
| Difficulty | Easy |
| Points | 50 |
| Vulnerability | Client-side information disclosure (CWE-200 / exposure of internal endpoint) |
| Exposed endpoint | `GET /api/internal/project-preview` |
| Authentication | none |
| Flag location | `flag` property of the internal preview JSON |

## Intended vulnerability

`source/public/assets/app.js` contains:

```js
const applicationConfig = {
  apiBase: '/api',
  build: '3.1.0',
  features: {
    projectOverview: true,
    taskBoard: true,
    activityFeed: true,
    internalPreview: false
  },
  internalPreview: '/api/internal/project-preview'
};
```

and a client function for that route:

```js
async function loadInternalProjectPreview() { … }
```

Nothing in the rendered dashboard mentions the route, the bundle never calls the
function on load (`internalPreview` is `false`), and no source map exists. The
information leaks purely because the bundle is delivered to the browser.

On the server, `source/src/server.js` registers the route without any
authorization and returns the internal record plus the flag:

```js
app.get('/api/internal/project-preview', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json(internalProject);   // { project: {...}, flag: FLAG }
});
```

The handler is marked `INTENTIONAL CTF VULNERABILITY` in the source.

## How the flag is injected

1. GZ::CTF derives a per-team value from
   `AXUM{hidden_in_plain_sight_[TEAM_HASH]}` (12 hex characters).
2. When a team starts its container, the platform sets `GZCTF_FLAG` in the
   container environment.
3. `server.js` reads it at startup, exits with status 1 when missing, and keeps
   it in the `internalProject` object in memory.

## Step-by-step solution

1. Open the portal. A dashboard with project metrics, a portfolio table, tasks
   and activity loads. Nothing unusual is visible.
2. Open DevTools → **Network** (or **Sources**) and reload. The page requests
   `/`, `/assets/style.css`, `/assets/app.js` and `/api/projects`.
3. Open or search `/assets/app.js`. Searching for `api`, `internal` or `preview`
   leads to the configuration entry and the unused preview function.
4. Request the route:

   ```bash
   curl -s "$TARGET/api/internal/project-preview"
   ```

5. The JSON contains `project.name = "Orion Internal Platform"` and the `flag`.
6. Submit the `AXUM{...}` value.

### Example request and response

```http
GET /api/internal/project-preview HTTP/1.1
Host: <instance>
Accept: application/json
```

```json
{
  "project": {
    "name": "Orion Internal Platform",
    "code": "ORION",
    "classification": "Internal Development",
    "status": "Pre-release",
    "owner": "Platform Engineering",
    "sponsor": "Office of the CTO",
    "environment": "staging-eu-west",
    "milestone": "2027-Q1 general availability",
    "steeringGroup": ["Priya Raman", "Tomas Berg", "Marta Kowalski"],
    "notes": "Internal preview data exposed during deployment."
  },
  "flag": "AXUM{hidden_in_plain_sight_<team-hash>}"
}
```

## Root cause

The internal endpoint was treated as secret because it is undocumented, and the
client code that references it was left in the production bundle. Neither is an
access control:

* everything served to a browser is readable by the user;
* an unlisted URL is still reachable by anyone who learns it;
* the server performs no authorization on the route and returns more data than
  any public consumer needs.

## Real-world remediation

1. **Do not rely on obscurity.** Endpoint names, feature flags and client
   bundles are public. Removing the reference from `app.js` reduces noise but is
   not a fix.
2. **Authorize on the server for every request.** The internal route must
   authenticate the caller and check an explicit permission (for example an
   `internal:publish:preview` scope) before returning anything:

   ```js
   app.get('/api/internal/project-preview',
     requireAuth,
     requireScope('internal:publish:preview'),
     (req, res) => res.json(internalProject));
   ```

   Unauthorized callers should receive a 401/403 — never the record.
3. **Minimize data.** Preview responses should use a dedicated DTO with only the
   fields the client needs; internal notes, sponsors and environment names
   should never be serialized for a browser.
4. **Keep secrets out of the frontend contract.** Flags, tokens and internal
   identifiers belong on the server. Anything reachable from the browser must be
   assumed to be public.
5. **Build hygiene.** Strip development-only modules from production bundles
   (dead-code elimination, separate internal builds) and review the published
   asset list in CI.
6. **Regression tests.** Add a test asserting that internal routes return 401/403
   for anonymous callers and that no internal route string appears in the
   production bundle.

## Notes for organizers

* The three checks a beginner needs are all local to DevTools: the bundle is
  loaded via a normal script tag, the route is a plain string, and the response
  is readable JSON.
* No authentication, IDOR, injection or traversal is involved — this is purely
  client-side disclosure.
* The dashboard never calls the endpoint on load (`internalPreview: false`), so
  a solver must actually inspect the bundle or make the request manually.
