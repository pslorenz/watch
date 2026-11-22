"""Leak-site claim feeds. Each adapter downloads the whole recent feed and returns plain records:
{"source", "victim", "website", "group", "discovered", "url", "text"}.

Nothing here sends a client name, domain, or vendor to anyone. Matching happens locally in match.py.

Endpoints are configurable (watch.json "feeds") because public APIs move. Check each one's terms:
ransomware.live's free v2 API is marked for personal use; an MSP running this for clients should
self-host RansomLook (open source) or buy a commercial feed and point the adapter at it.
"""
import json, os, urllib.request

DEFAULT_FEEDS = {
    "ransomlook": {"enabled": True, "url": "https://www.ransomlook.io/api/recent"},
    "ransomware_live": {"enabled": False, "url": "https://api.ransomware.live/v2/recentvictims"},
}
UA = {"User-Agent": "watch (github.com/pslorenz/watch)"}


def _get(url, timeout=60):
    if url.startswith("file://") or os.path.exists(url):
        with open(url.removeprefix("file://")) as fh:
            return json.load(fh)
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return json.loads(r.read().decode())


def _pick(d, *keys):
    for k in keys:
        if d.get(k):
            return str(d[k])
    return ""


def normalize_record(source, d):
    """Field names differ by feed and by API version; take the first one present."""
    return {"source": source,
            "victim": _pick(d, "post_title", "victim", "title", "name"),
            "website": _pick(d, "website", "domain", "url_victim"),
            "group": _pick(d, "group_name", "group", "actor"),
            "discovered": _pick(d, "discovered", "attackdate", "published", "date")[:10],
            "url": _pick(d, "post_url", "link", "url"),
            "text": _pick(d, "description", "content", "summary")[:2000]}


def fetch(feeds=None):
    """Returns (records, errors). A dead feed is reported, never fatal: the digest says what was checked."""
    feeds = {**DEFAULT_FEEDS, **(feeds or {})}
    records, errors, checked = [], [], []
    for name, cfg in feeds.items():
        if not cfg.get("enabled"):
            continue
        try:
            data = _get(cfg["url"])
            rows = data if isinstance(data, list) else data.get("victims") or data.get("data") or data.get("posts") or []
            got = [normalize_record(name, r) for r in rows if isinstance(r, dict)]
            records += [r for r in got if r["victim"]]
            checked.append(f"{name} ({len(got)})")
        except Exception as e:                                       # noqa: BLE001  report and carry on
            errors.append(f"{name}: {e.__class__.__name__}: {e}")
    return records, errors, checked
