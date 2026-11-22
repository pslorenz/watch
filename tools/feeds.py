"""Leak-site claim feeds. Each adapter downloads the whole recent feed and returns plain records:
{"source", "victim", "website", "group", "discovered", "url", "text"}.

Nothing here sends a client name, domain, or vendor to anyone. Matching happens locally in match.py.

Endpoints are configurable (watch.json "feeds") because public APIs move. Check each one's terms.
ransomware.live: the Pro API (api-pro.ransomware.live, personal token from my.ransomware.live) is free,
but commercial use, including paid MSP services, needs the owner's written approval; output that uses
it must credit and link ransomware.live; don't poll more than every 30 minutes (daily is plenty).
Tokens come from an environment variable, never from watch.json.
"""
import json, os, urllib.request

DEFAULT_FEEDS = {
    "ransomlook": {"enabled": True, "url": "https://www.ransomlook.io/api/recent",
                   "attribution": "RansomLook (ransomlook.io)"},
    # Path and header name: confirm against the Pro API docs at my.ransomware.live before enabling.
    "ransomware_live": {"enabled": False, "url": "https://api-pro.ransomware.live/victims/recent",
                        "token_env": "RANSOMWARE_LIVE_TOKEN", "token_header": "X-API-KEY",
                        "attribution": "Ransomware.live (https://www.ransomware.live)"},
}
UA = {"User-Agent": "watch (github.com/pslorenz/watch)"}


def _get(url, headers=None, timeout=60):
    if url.startswith("file://") or os.path.exists(url):
        with open(url.removeprefix("file://")) as fh:
            return json.load(fh)
    with urllib.request.urlopen(urllib.request.Request(url, headers={**UA, **(headers or {})}), timeout=timeout) as r:
        return json.loads(r.read().decode())


def _pick(d, *keys):
    for k in keys:
        if d.get(k):
            return str(d[k])
    return ""


def normalize_record(source, d):
    """Field names differ by feed and by API version; take the first one present."""
    url = _pick(d, "post_url", "link", "url")
    if not url.startswith("https://") or ".onion" in url:
        url = ""                       # relative paths and onion links point at the gang's site, not ours to keep
    return {"source": source,
            "victim": _pick(d, "post_title", "victim", "title", "name"),
            "website": _pick(d, "website", "domain", "url_victim"),
            "group": _pick(d, "group_name", "group", "actor"),
            "discovered": _pick(d, "discovered", "attackdate", "published", "date")[:10],
            "url": url,
            "text": _pick(d, "description", "content", "summary")[:2000]}


def fetch(feeds=None):
    """Returns (records, errors, checked, credits). A dead feed is reported, never fatal: the digest says what was checked."""
    feeds = {k: {**DEFAULT_FEEDS.get(k, {}), **v} for k, v in {**DEFAULT_FEEDS, **(feeds or {})}.items()}
    records, errors, checked, credits = [], [], [], []
    for name, cfg in feeds.items():
        if not cfg.get("enabled"):
            continue
        headers = {}
        if cfg.get("token_env"):
            token = os.environ.get(cfg["token_env"])
            if not token:
                errors.append(f"{name}: set the {cfg['token_env']} environment variable (Actions secret)")
                continue
            headers[cfg.get("token_header", "X-API-KEY")] = token
        try:
            data = _get(cfg["url"], headers)
            rows = data if isinstance(data, list) else data.get("victims") or data.get("data") or data.get("posts") or []
            got = [normalize_record(name, r) for r in rows if isinstance(r, dict)]
            records += [r for r in got if r["victim"]]
            checked.append(f"{name} ({len(got)})")
            if cfg.get("attribution"):
                credits.append(cfg["attribution"])
        except Exception as e:                                       # noqa: BLE001  report and carry on
            errors.append(f"{name}: {e.__class__.__name__}: {e}")
    return records, errors, checked, credits
