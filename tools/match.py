"""Matching client watchlists against outside records, without ever sending client names anywhere.

Two kinds of evidence, kept apart on purpose:
  domain  - the client's domain is the victim's website, or appears in the post. High confidence.
  name    - a client name or alias appears as whole words in the victim name. Needs review:
            "Summit Dental" in Ohio is not "Summit Dental" in Raleigh.
"""
import re

# Corporate and practice suffixes stripped before name matching, so "Acme Dental, PLLC" == "acme dental".
SUFFIXES = {"inc", "incorporated", "llc", "l l c", "ltd", "limited", "corp", "corporation", "co", "company",
            "pllc", "pc", "pa", "lp", "llp", "plc", "gmbh", "sa", "ag", "bv", "the", "group", "holdings"}
MIN_ALIAS_LEN = 6        # shorter names ("acme", "abc") only match on domain unless marked "exact"


def normalize(name):
    s = re.sub(r"[^a-z0-9 ]+", " ", (name or "").lower())
    words = [w for w in s.split() if w]
    while words and words[-1] in SUFFIXES:
        words.pop()
    while words and words[0] == "the":
        words.pop(0)
    return " ".join(words)


def registrable(domain):
    """example.co.uk / www.example.com -> best-effort registrable domain. Good enough for matching."""
    d = (domain or "").lower().strip()
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split(":")[0]
    d = d[4:] if d.startswith("www.") else d
    parts = d.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"co", "com", "org", "net", "ac", "gov", "edu"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


def whole_words(needle, hay):
    return bool(needle) and re.search(r"(?<![a-z0-9])" + re.escape(needle) + r"(?![a-z0-9])", hay) is not None


def match_entity(entity, victim, website="", text=""):
    """entity: {"name", "aliases", "domains", "exact"}. Returns (confidence, matched_on) or None."""
    doms = {registrable(d) for d in entity.get("domains", []) if d}
    site = registrable(website) if website else ""
    blob = f"{victim} {website} {text}".lower()
    for d in sorted(doms):
        if d and (d == site or whole_words(d, blob)):
            return "domain", d
    v = normalize(victim)
    exact = {normalize(x) for x in entity.get("exact", [])}
    for alias in [entity.get("name", "")] + entity.get("aliases", []):
        n = normalize(alias)
        if not n:
            continue
        if n in exact and n == v:
            return "name", alias
        if len(n) >= MIN_ALIAS_LEN and whole_words(n, v):
            return "name", alias
    return None


def canonical(vendor):
    """'ConnectWise, Inc.' -> 'connectwise'. Vendor names compared after normalize()."""
    return normalize(vendor)


def defang(s):
    """For anything a person reads: hxxps[://]example[.]com. Raw values stay in the JSON record,
    where tools (Winnow) need the real domain and nobody clicks. Also stops Teams/Slack link previews
    from fetching victim or leak-site pages on our behalf."""
    if not s:
        return s
    s = re.sub(r"(?i)\bhttp(s?)://", r"hxxp\1[://]", s)
    return re.sub(r"(?<=[a-z0-9])\.(?=[a-z0-9-]+(?:[./:?\s\"')]|$))", "[.]", s, flags=re.I)
