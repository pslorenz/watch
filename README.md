# watch

**Is a client, or one of a client's vendors, on fire?**

> [!WARNING]
> Codename, pre-alpha, personal project. Leak-site posts are claims made by criminals, not confirmed breaches. Verify with the client before anyone says the word "breach."

watch is the third piece next to [sick-call](https://github.com/pslorenz/sick-call), which covers what's being exploited, and Winnow, which covers what you run. Every day it answers three questions for each client:

| Check | Question | Source |
|---|---|---|
| Client on a leak site | Has a ransomware group named this client? | Leak-site claim feeds (RansomLook by default) |
| Vendor on a leak site | Has a group named a vendor this client depends on (practice software, CPA platform, RMM)? | Same feeds, matched against each client's vendor list |
| Vendor at sick call | Does a vendor this client runs have an advisory confined to quarters or on light duty? | sick-call's public daily log |

What it doesn't do: general threat news, keyword alerts on headlines, onion crawling, or IOC enrichment. Those are other tools. Most of them produce the noise sick-call exists to filter.

## How it handles client data

A client list plus each client's vendor stack is a target list. watch is built so that list never leaves your hands:

- **Matching is local.** watch downloads the whole recent feed and matches on your machine or runner. It never searches a feed for a client's name, because that search would tell the feed operator who your clients are.
- **No server.** Output is files: a JSON record per day, `DIGEST.md`, and `alerts.json`. You view them wherever you already have authentication.
- **Generic alerts by default.** A Teams or Slack alert says how many new items there are and where to look, and never names the client. Set `"alert_detail": "full"` only if the channel is restricted.
- **The workflow refuses to run with client data in a public repo.** If the repo isn't private, it fails before reading the watchlist.

### Matching rules

- **Domain match** is high confidence: the client's domain is the victim's website, or appears in the post.
- **Name match** needs review: a client name or alias appears as whole words in the victim name, after dropping suffixes like LLC, PLLC, and Inc. "Summit Dental" in Ohio isn't your Summit Dental.
- **Names shorter than 6 characters** ("Acme", "ABC") match only on domain, unless you list them under `exact`, in which case they must match the whole victim name.

## Using it at your MSP

1. **Create a private repo and push a mirror of this one into it.** Don't fork: a fork of a public repo is public.
   ```bash
   git clone --bare https://github.com/pslorenz/watch && cd watch.git && git push --mirror https://github.com/YOUR-ORG/watch-private
   ```
2. **Add your watchlist** as the `WATCHLIST_JSON` Actions secret, using the format in `watchlist.example.json`. A secret keeps the client list out of git history, even in the private repo. If you'd rather commit the file, use `git add -f watchlist.json`; it's git-ignored on purpose.
3. **Optional:** copy `watch.example.json` to `watch.json` to change feeds or alert detail.
4. **Optional:** add a `WATCH_WEBHOOK` secret for Slack or Teams. The payload is `{"text": ...}`. Slack incoming webhooks take that as-is. A Teams Workflows webhook needs a flow that reads the `text` field.
5. **Optional:** set the `SICK_CALL_REPO` Actions variable if you run your own sick-call copy. The default is `pslorenz/sick-call`.

The daily workflow runs at 10:41 UTC, after sick-call. It commits `out/`, `state/`, and `DIGEST.md` to your private repo, and alerts only on new items. It uses a few minutes a day of the private-repo Actions allowance.

**Don't** publish the output with GitHub Pages. Pages from a private repo are public unless your org has Enterprise Cloud private Pages.

### Viewing

- **DIGEST.md** in the private repo, behind GitHub sign-in and MFA.
- **viewer.html:** download it once, open it locally, and load a day's `out/YYYY-MM-DD.json`. The file is read in that browser tab only. Nothing is uploaded or fetched.
- If you want a hosted dashboard, put it behind your own VPN, ZTNA, or SSO. Never on a public IP with a login page in front of it.

## Feeds

| Feed | Default | Notes |
|---|---|---|
| RansomLook | on | Open source, no API key, and you can self-host it. |
| ransomware.live v2 | off | The free API is marked for personal use. An MSP running this for clients should use the commercial API or self-hosted RansomLook. |

Endpoints are set in `watch.json`, because public APIs move. If a feed fails, the digest says so ("no news from a dead feed is not good news"), and the rest of the run still completes.

## Try it

```bash
python3 tools/watch.py --demo --root /tmp/watch-demo && cat /tmp/watch-demo/DIGEST.md
python3 -m unittest discover -s tests -t .
```

The demo uses three fictional clients, a saved feed, and a saved sick-call log. Nothing is fetched.

## Layout

```
tools/watch.py       daily run: match, dedupe, record, digest, alerts
tools/match.py       name and domain matching (local only)
tools/feeds.py       leak-site feed adapters
viewer.html          local, offline table view of a day's record
watchlist.example.json, watch.example.json
docs/record.md       the watch.hit/1 record, for Winnow and anything else downstream
tests/               fixtures only; no network, no real client data
```

## Roadmap

- **0.1:** the three checks, the daily workflow, and the viewer. Backtest name matching against a month of claims to measure false positives before trusting name matches.
- **0.2:** more feeds (self-hosted RansomLook and commercial APIs), a per-client quiet list for known false positives, and a weekly digest.
- **Later:** hand off to Winnow: a vendor hit becomes a check on that client's fleet.

## License

Apache-2.0 for code and CC BY 4.0 for docs, the same as sick-call.
