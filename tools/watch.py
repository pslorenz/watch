#!/usr/bin/env python3
"""watch: is a client, or one of a client's vendors, on fire?

Daily run:
  1. Pull recent leak-site claims (whole feeds; client names never leave this machine).
  2. Match them against each client's names and domains, and against the vendors each client depends on.
  3. Read sick-call's daily log and flag clients whose vendors have an advisory confined to quarters
     or on light duty.
  4. Write out/YYYY-MM-DD.json, DIGEST.md, and alerts.json. Only new items alert; everything is in the record.

  python3 tools/watch.py --watchlist watchlist.json --sick-call-log ../sick-call/log
  python3 tools/watch.py --demo            # example clients, fixture feeds, nothing fetched

Files out, no server. Viewing is the MSP's choice, behind its own authentication (see README).
"""
import argparse, datetime as dt, glob, gzip, hashlib, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import feeds as fd          # noqa: E402
import match as mt          # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = "watch.hit/1"
SHORT_WINDOW_DAYS = 7
KIND_LABEL = {"leak_claim": "Client named on a leak site",
              "vendor_leak_claim": "Client's vendor named on a leak site",
              "vendor_vuln": "Client's vendor at sick call"}


def utc_today():
    return dt.datetime.now(dt.timezone.utc).date()


def _read_json(path, default=None):
    if not path or not os.path.exists(path):
        return default
    with open(path) as fh:
        return json.load(fh)


def _write_json(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=1)


def vendor_entities(client):
    out = []
    for v in client.get("vendors", []):
        out.append({"name": v} if isinstance(v, str) else v)
    return out


def hit_key(*parts):
    return hashlib.sha1("|".join(p or "" for p in parts).lower().encode()).hexdigest()[:16]


# ---- 1-2. leak-site claims -------------------------------------------------------------------------
def leak_hits(clients, records):
    hits = []
    for rec in records:
        for c in clients:
            m = mt.match_entity(c, rec["victim"], rec["website"], rec["text"])
            if m:
                hits.append(dict(kind="leak_claim", client=c["id"], subject=c.get("name", c["id"]),
                                 confidence=m[0], matched_on=m[1], **_rec(rec)))
            for v in vendor_entities(c):
                vm = mt.match_entity(v, rec["victim"], rec["website"], rec["text"])
                if vm:
                    hits.append(dict(kind="vendor_leak_claim", client=c["id"], subject=v["name"],
                                     confidence=vm[0], matched_on=vm[1], **_rec(rec)))
    return hits


def _rec(rec):
    # Deliberately NOT copying rec["text"]: leak-post descriptions list third parties' names and the
    # documents stolen from them. It's read for matching and never written to the record.
    return {"source": rec["source"], "victim": rec["victim"], "group": rec["group"],
            "date": rec["discovered"], "url": rec["url"]}


# ---- 3. sick-call vendor advisories ----------------------------------------------------------------
def read_sick_call(log_dir, since):
    """Latest record per advisory from sick-call's daily log (log/YYYY-MM-DD.jsonl.gz)."""
    latest = {}
    for path in sorted(glob.glob(os.path.join(log_dir or "", "*.jsonl.gz"))):
        with gzip.open(path, "rt") as fh:
            for line in fh:
                r = json.loads(line)
                latest[r["advisory"]] = r
    out = []
    for r in latest.values():
        day0 = r.get("day0") or r.get("scored_on")
        if day0 and day0 >= since.isoformat():
            out.append(r)
    return out


def vendor_vuln_hits(clients, sc_records):
    hits = []
    for r in sc_records:
        short = r.get("rung", 0) >= 3 or r.get("window_days", 99) <= SHORT_WINDOW_DAYS
        if not short:
            continue
        rv = [mt.canonical(x) for x in r.get("vendors", [])]
        for c in clients:
            for v in vendor_entities(c):
                cv = mt.canonical(v["name"])
                if cv and any(mt.whole_words(cv, x) or mt.whole_words(x, cv) for x in rv if x):
                    hits.append(dict(kind="vendor_vuln", client=c["id"], subject=v["name"], confidence="vendor",
                                     matched_on=cv, source="sick-call", victim=r.get("title", r["advisory"]),
                                     group="", date=r.get("day0", ""), url="",
                                     sick_call={"advisory": r["advisory"], "rung": r.get("rung"),
                                                "window": r.get("window"), "cves": r.get("cve_count")}))
    return hits


# ---- 4. record, digest, alerts ---------------------------------------------------------------------
def run(a):
    today = dt.date.fromisoformat(a.today) if a.today else utc_today()
    now = a.now or dt.datetime.now(dt.timezone.utc).strftime("%H%M")
    stamp = now.replace(":", "")[:4] + "Z"
    wl = _read_json(a.watchlist)
    if wl is None:
        raise SystemExit(f"{a.watchlist}: not found. Copy watchlist.example.json to watchlist.json "
                         "in your PRIVATE copy, or run --demo.")
    clients = wl.get("clients", [])
    cfg = _read_json(a.config, {}) or {}
    if a.feed_file:
        records, errors, checked, credits = [], [], [], []
        for f in a.feed_file:
            r, e, c, cr = fd.fetch({os.path.basename(f): {"enabled": True, "url": f},
                                    **{k: {"enabled": False} for k in fd.DEFAULT_FEEDS}})
            records += r; errors += e; checked += c; credits += cr
    else:
        records, errors, checked, credits = fd.fetch(cfg.get("feeds"))
    since = today - dt.timedelta(days=a.lookback)
    records = [r for r in records if not r["discovered"] or r["discovered"] >= since.isoformat()]

    hits = leak_hits(clients, records)
    day_path = os.path.join(a.root, "out", f"{today.isoformat()}.json")
    prev = _read_json(day_path, {}) or {}
    if a.auto:
        # Scheduled runs can start late, so don't key on the exact hour: the first watch at or after
        # 10:00 UTC that finds no full watch logged today does the full one; the rest are leak-only.
        done = any(e.get("full") for e in prev.get("entries", []))
        a.leak_only = done or int(stamp[:2]) < 10
    if a.sick_call_log and not a.leak_only:
        sc_since = today - dt.timedelta(days=a.sick_call_days)
        hits += vendor_vuln_hits(clients, read_sick_call(a.sick_call_log, sc_since))
        checked.append("sick-call")

    state_path = os.path.join(a.root, "state", "seen.json")
    seen = _read_json(state_path, {}) or {}
    unique = {}
    for h in hits:
        # Same claim from two feeds is one hit: the key leaves out the source, and the others are listed.
        h["key"] = hit_key(h["kind"], h["client"], mt.normalize(h["victim"]), h["group"],
                           (h.get("sick_call") or {}).get("advisory", ""))
        if h["key"] in unique:
            first = unique[h["key"]]
            if h["source"] != first["source"] and h["source"] not in first.setdefault("also_seen_in", []):
                first["also_seen_in"].append(h["source"])
        else:
            unique[h["key"]] = h
    hits = sorted(unique.values(), key=lambda h: (h["kind"], h["client"], h["victim"]))
    for h in hits:
        h["schema"] = SCHEMA
        h["new"] = h["key"] not in seen
        h["first_seen"] = seen.get(h["key"], today.isoformat())
        seen.setdefault(h["key"], today.isoformat())

    # One log per day, one entry per watch. A leak-only watch (the 4-hourly runs) keeps the day's
    # vendor-at-sick-call items from the full watch instead of dropping them.
    if a.leak_only:
        keys = {h["key"] for h in hits}
        hits += [dict(h, new=False) for h in prev.get("hits", []) if h["kind"] == "vendor_vuln" and h["key"] not in keys]
    new = [h for h in hits if h["new"]]
    entries = prev.get("entries", []) + [dict(entry(stamp, checked, errors, new), full=not a.leak_only)]
    record = {"schema": "watch.day/1", "date": today.isoformat(), "checked": checked, "errors": errors,
              "credits": sorted(set(credits) | set(prev.get("credits", []))),
              "clients": len(clients), "entries": entries, "hits": hits}
    _write_json(day_path, record)
    _write_json(state_path, seen)
    with open(os.path.join(a.root, "DIGEST.md"), "w") as fh:
        fh.write(digest(record, {c["id"]: c.get("name", c["id"]) for c in clients}))
    _write_json(os.path.join(a.root, "out", "alerts.json"), alerts(new, cfg.get("alert_detail", "generic")))
    print(f"{today} {stamp}: {entries[-1]['text']} clients {len(clients)}, records {len(records)}, hits {len(hits)}, new {len(new)}, "
          f"feed errors {len(errors)}")
    return record


def entry(stamp, checked, errors, new):
    """One line in the day's watch log, deck-log style."""
    if errors and not checked:
        text = f"Feed down: {'; '.join(errors)}. Nothing checked this watch."
    else:
        if new:
            kinds = sorted({KIND_LABEL[h["kind"]].lower() for h in new})
            text = f"{len(new)} new to report: {', '.join(kinds)}."
        else:
            text = "All quiet."
        text += f" Feeds checked: {', '.join(checked)}."
        if errors:
            text += f" Feed down: {'; '.join(errors)}."
    return {"time": stamp, "new": len(new), "text": text}


SECTION_TITLE = {"leak_claim": "Clients named on a leak site",
                 "vendor_leak_claim": "Vendors named on a leak site",
                 "vendor_vuln": "Vendors at sick call"}


def digest(record, names):
    """The watch log. Written every day, quiet or not: 'nothing to report' is still an entry."""
    hits = record["hits"]
    new = [h for h in hits if h["new"]]
    d = mt.defang
    out = [f"# Watch log, {record['date']}", ""]
    out += [f"    {e['time']}  {e['text']}" for e in record.get("entries", [])] + [""]
    if not hits:
        out.append("**All quiet.** Nothing to report.")
    else:
        out.append(f"**Turnover:** {len(new)} new this watch, {len(hits) - len(new)} carried over "
                   f"from earlier watches, {record['clients']} clients on the watchlist.")
    if record["errors"]:
        out += ["", "**Feeds down this watch.** No news from a dead feed is not good news:"] + \
               [f"- {e}" for e in record["errors"]]
    out += ["", "Leak-site posts are **claims by criminals**, not confirmed breaches. Verify with the client "
            "before anyone says the word breach. Feed-sourced names and domains are defanged."]
    for kind in ("leak_claim", "vendor_leak_claim", "vendor_vuln"):
        rows = [h for h in hits if h["kind"] == kind]
        out += ["", f"## {SECTION_TITLE[kind]} ({len(rows)})", ""]
        if not rows:
            out.append("All quiet.")
            continue
        for h in sorted(rows, key=lambda x: (not x["new"], x["client"])):
            flag = "**NEW** " if h["new"] else f"Since {h['first_seen']}: "
            who = names.get(h["client"], h["client"])
            if kind == "vendor_vuln":
                sc = h["sick_call"]
                status = "confined to quarters" if (sc["rung"] or 0) >= 3 else "light duty"
                out.append(f"- {flag}{who}: {h['subject']}, {h['victim']}. {status.capitalize()}, "
                           f"rung {sc['rung']}, {sc['window']} window.")
            else:
                conf = (f"domain match on {d(h['matched_on'])}" if h["confidence"] == "domain"
                        else "name match, needs review")
                about = "" if kind == "leak_claim" else f"vendor {h['subject']}: "
                seen = f"{h['source']}" + (f", also {', '.join(h['also_seen_in'])}" if h.get("also_seen_in") else "")
                out.append(f"- {flag}{who}: {about}\"{d(h['victim'])}\" claimed by {h['group'] or 'unknown group'} "
                           f"on {h['date'] or '?'} ({conf}; {seen}).")
    if record.get("credits"):
        out += ["", "Leak-site data: " + "; ".join(record["credits"]) + "."]
    out += ["", f"Full record: `out/{record['date']}.json`. Open it in `viewer.html` for a table view.",
            "", "End of watch.", ""]
    return "\n".join(out)


def alerts(new, detail):
    """What goes to Teams/Slack. 'generic' (default) never puts a client name in chat."""
    if not new:
        return {"send": False}
    counts = {k: sum(1 for h in new if h["kind"] == k) for k in KIND_LABEL}
    summary = "; ".join(f"{KIND_LABEL[k]}: {n}" for k, n in counts.items() if n)
    text = f"watch: {len(new)} new item(s) to report. {summary}. Watch log is DIGEST.md in the private repo."
    if detail == "full":
        text += "\n" + "\n".join(f"- {h['client']}: {mt.defang(h['victim'])} ({KIND_LABEL[h['kind']]})" for h in new)
    return {"send": True, "text": text}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--watchlist", default=os.path.join(ROOT, "watchlist.json"))
    ap.add_argument("--config", default=os.path.join(ROOT, "watch.json"))
    ap.add_argument("--sick-call-log", help="sick-call's log/ directory (a clone of the public repo is fine)")
    ap.add_argument("--feed-file", action="append", help="read a saved feed file instead of fetching (repeatable)")
    ap.add_argument("--lookback", type=int, default=7, help="days of claims and advisories to consider")
    ap.add_argument("--sick-call-days", type=int, default=30,
                    help="days of sick-call advisories to consider (needs action stays open well past a week)")
    ap.add_argument("--leak-only", action="store_true",
                    help="a between-watches check: leak sites only, appended to the day's log (sick-call is daily)")
    ap.add_argument("--auto", action="store_true",
                    help="scheduled runs: full watch once a day at or after 10:00 UTC, leak-only otherwise")
    ap.add_argument("--now", help="HH:MM UTC for the log entry (default: now)")
    ap.add_argument("--today", help="YYYY-MM-DD (default: today, UTC)")
    ap.add_argument("--root", default=ROOT, help="where out/, state/ and DIGEST.md go")
    ap.add_argument("--demo", action="store_true", help="example clients and fixture feeds; fetches nothing")
    a = ap.parse_args()
    if a.demo:
        fx = os.path.join(ROOT, "tests", "fixtures")
        a.watchlist = os.path.join(ROOT, "watchlist.example.json")
        a.feed_file = [os.path.join(fx, "ransomlook.json")] + (a.feed_file or [])
        a.sick_call_log = os.path.join(fx, "sick-call-log")
        a.today = a.today or "2026-11-21"
        a.now = a.now or "10:41"
    run(a)


if __name__ == "__main__":
    main()
