# Changelog

## [0.1.0] - unreleased

Codename watch. First scaffold.

### Added
- Leak-site claim matching for clients and their vendors (domain match, or reviewed name match), done locally on whole feeds.
- Vendor advisories from sick-call's daily log: clients whose vendors are confined to quarters or on light duty.
- Daily record (`out/`), `DIGEST.md`, and generic alerts for new items only.
- Private-repo workflow that refuses to run with client data in a public repo; `WATCHLIST_JSON` secret support.
- `viewer.html`: offline, local-only table view.
- The digest is a watch log: turnover line, "All quiet" on quiet days, feeds checked, and "End of watch."
- Feed-sourced names, domains and URLs are defanged in the log, alerts and viewer; raw values stay in the JSON record. Relative and onion links from feeds are dropped, and post descriptions are never stored.
- The same claim from two feeds is one hit, with the other sources listed.
- A watch every 4 hours: timestamped (Zulu) entries in the day's log. The first watch at or after 10:00 UTC is the full watch (leak sites plus sick-call); the rest check leak sites only and keep the day's sick-call items.
- Token-based feeds (ransomware.live Pro) read their token from an environment variable, and the log credits each feed used.
