# The watch record

One file per day, `out/YYYY-MM-DD.json`:

```json
{"schema": "watch.day/1", "date": "2026-11-21", "checked": ["ransomlook (100)", "sick-call log"],
 "errors": [], "clients": 3, "hits": [ ... ]}
```

Each hit:

| Field | Meaning |
|---|---|
| `schema` | `watch.hit/1` |
| `kind` | `leak_claim`, `vendor_leak_claim`, or `vendor_vuln` |
| `client` | client id from the watchlist (not the display name) |
| `subject` | the client, or the vendor that matched |
| `confidence` | `domain` (high), `name` (needs review), or `vendor` (sick-call match) |
| `matched_on` | the domain, alias, or vendor name that matched |
| `source`, `victim`, `group`, `date`, `url` | from the feed, or the sick-call advisory title |
| `sick_call` | for `vendor_vuln`: `advisory`, `rung`, `window`, `cves` |
| `key` | stable dedupe key |
| `new`, `first_seen` | whether this run is the first time watch saw it |

Joins with sick-call on `sick_call.advisory`, and with Winnow on `client`. The schema changes only with a version bump.
