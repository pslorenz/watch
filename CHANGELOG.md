# Changelog

## [0.1.0] - unreleased

Codename watch. First scaffold.

### Added
- Leak-site claim matching for clients and their vendors (domain match, or reviewed name match), done locally on whole feeds.
- Vendor advisories from sick-call's daily log: clients whose vendors are confined to quarters or on light duty.
- Daily record (`out/`), `DIGEST.md`, and generic alerts for new items only.
- Private-repo workflow that refuses to run with client data in a public repo; `WATCHLIST_JSON` secret support.
- `viewer.html`: offline, local-only table view.
