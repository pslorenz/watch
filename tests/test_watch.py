"""watch tests. Fixtures only: no network, no real client data."""
import json, os, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import match as mt  # noqa: E402
import watch as wt  # noqa: E402


def demo(root, *extra):
    r = subprocess.run([sys.executable, "tools/watch.py", "--demo", "--root", root, *extra],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    with open(os.path.join(root, "out", "2026-11-21.json")) as fh:
        return json.load(fh)


class Matching(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(mt.normalize("Acme Dental, PLLC"), "acme dental")
        self.assertEqual(mt.normalize("The Summit Group, Inc."), "summit")

    def test_registrable(self):
        self.assertEqual(mt.registrable("https://www.example.com/path"), "example.com")
        self.assertEqual(mt.registrable("shop.example.co.uk"), "example.co.uk")

    def test_domain_beats_name(self):
        c = {"name": "Pinecrest Family Dental", "domains": ["pinecrestdental.example"]}
        self.assertEqual(mt.match_entity(c, "PFD Holdings", "www.pinecrestdental.example"),
                         ("domain", "pinecrestdental.example"))

    def test_short_names_need_domain(self):
        c = {"name": "Acme Tool", "aliases": ["ACME"], "domains": ["acmetool.example"]}
        self.assertIsNone(mt.match_entity(c, "Acme Corp", "acmecorp.example"))          # "acme" is too short
        self.assertIsNone(mt.match_entity(c, "Acme Tooling Supply"))                     # whole words only
        self.assertEqual(mt.match_entity(c, "Acme Tool LLC")[0], "name")

    def test_exact_short_alias(self):
        c = {"name": "ABC", "exact": ["ABC"], "domains": []}
        self.assertEqual(mt.match_entity(c, "ABC Inc.")[0], "name")
        self.assertIsNone(mt.match_entity(c, "ABC Supply Co"))                           # exact means exact


class Demo(unittest.TestCase):
    def test_hits(self):
        with tempfile.TemporaryDirectory() as t:
            rec = demo(t)
        kinds = {(h["kind"], h["client"]) for h in rec["hits"]}
        self.assertIn(("leak_claim", "pinecrest"), kinds)                  # domain match
        self.assertIn(("leak_claim", "harbormain"), kinds)                 # alias name match
        self.assertIn(("vendor_leak_claim", "pinecrest"), kinds)           # Henry Schein One claimed
        self.assertIn(("vendor_vuln", "pinecrest"), kinds)                 # SonicWall confined to quarters
        self.assertIn(("vendor_vuln", "harbormain"), kinds)                # Fortinet light duty
        self.assertIn(("vendor_vuln", "acmetool"), kinds)                  # "Ubiquiti Inc" == "Ubiquiti"
        self.assertNotIn(("leak_claim", "acmetool"), kinds)                # Acme Corp is someone else
        self.assertFalse(any("connectwise" in h["matched_on"] for h in rec["hits"]))   # watching: no alert
        pine = next(h for h in rec["hits"] if h["kind"] == "leak_claim" and h["client"] == "pinecrest")
        self.assertEqual((pine["confidence"], pine["date"]), ("domain", "2026-11-19"))  # old October claim filtered
        self.assertTrue(all(h["schema"] == "watch.hit/1" for h in rec["hits"]))

    def test_only_new_items_alert(self):
        with tempfile.TemporaryDirectory() as t:
            demo(t)
            with open(os.path.join(t, "out", "alerts.json")) as fh:
                first = json.load(fh)
            rec = demo(t)
            with open(os.path.join(t, "out", "alerts.json")) as fh:
                second = json.load(fh)
        self.assertTrue(first["send"])
        self.assertFalse(second["send"])
        self.assertFalse(any(h["new"] for h in rec["hits"]))

    def test_generic_alerts_name_no_clients(self):
        with tempfile.TemporaryDirectory() as t:
            demo(t)
            with open(os.path.join(t, "out", "alerts.json")) as fh:
                text = json.load(fh)["text"]
        for name in ("Pinecrest", "Harbor", "Acme", "pinecrest", "harbormain"):
            self.assertNotIn(name, text)

    def test_digest_language(self):
        with tempfile.TemporaryDirectory() as t:
            demo(t)
            with open(os.path.join(t, "DIGEST.md")) as fh:
                md = fh.read()
        self.assertIn("# Watch log, 2026-11-21", md)
        self.assertIn("**Turnover:** 6 new this watch", md)
        self.assertIn("claims by criminals", md)
        self.assertIn("needs review", md)
        self.assertIn("Confined to quarters", md)
        self.assertIn("End of watch.", md)

    def test_dead_feed_is_reported_not_fatal(self):
        with tempfile.TemporaryDirectory() as t:
            rec = demo(t, "--feed-file", os.path.join(t, "missing.json"))
        self.assertTrue(rec["errors"])
        self.assertTrue(rec["hits"])                                       # the good feed still counted


class WatchLog(unittest.TestCase):
    def run_watch(self, t, now, *extra):
        r = subprocess.run([sys.executable, "tools/watch.py", "--watchlist", os.path.join(ROOT, "watchlist.example.json"),
                            "--feed-file", os.path.join(ROOT, "tests", "fixtures", "ransomlook.json"),
                            "--sick-call-log", os.path.join(ROOT, "tests", "fixtures", "sick-call-log"),
                            "--today", "2026-11-21", "--now", now, "--root", t, *extra],
                           cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(t, "out", "2026-11-21.json")) as fh:
            return json.load(fh)

    def test_day_of_watches(self):
        with tempfile.TemporaryDirectory() as t:
            r1 = self.run_watch(t, "02:41", "--auto")              # before 10:00: leak sites only
            r2 = self.run_watch(t, "11:58", "--auto")              # first after 10:00 (late start): full
            r3 = self.run_watch(t, "14:41", "--auto")              # full already done: leak-only again
            with open(os.path.join(t, "DIGEST.md")) as fh:
                md = fh.read()
        self.assertEqual([e["full"] for e in r3["entries"]], [False, True, False])
        self.assertFalse(any(h["kind"] == "vendor_vuln" for h in r1["hits"]))
        self.assertTrue(any(h["kind"] == "vendor_vuln" for h in r3["hits"]))   # carried from the full watch
        self.assertIn("0241Z  3 new to report", md)
        self.assertIn("1158Z  3 new to report: client's vendor at sick call.", md)
        self.assertIn("1441Z  All quiet. Feeds checked: ransomlook.json (6).", md)

    def test_feed_down_entry(self):
        with tempfile.TemporaryDirectory() as t:
            r = subprocess.run([sys.executable, "tools/watch.py", "--watchlist", os.path.join(ROOT, "watchlist.example.json"),
                                "--feed-file", os.path.join(t, "gone.json"), "--leak-only",
                                "--today", "2026-11-21", "--now", "22:41", "--root", t],
                               cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(t, "DIGEST.md")) as fh:
                md = fh.read()
        self.assertIn("2241Z  Feed down:", md)
        self.assertIn("Nothing checked this watch.", md)


class Defang(unittest.TestCase):
    def test_defang(self):
        self.assertEqual(mt.defang("https://www.example.com/x"), "hxxps[://]www[.]example[.]com/x")
        self.assertEqual(mt.defang("pinecrestdental.example"), "pinecrestdental[.]example")
        self.assertEqual(mt.defang("Law Offices of Cynthia A. de Petris"), "Law Offices of Cynthia A. de Petris")
        self.assertEqual(mt.defang("Acme Inc."), "Acme Inc.")

    def test_nothing_live_in_human_output(self):
        """Digest and alerts never carry a clickable URL or bare domain from feed data."""
        import re
        with tempfile.TemporaryDirectory() as t:
            cfg = os.path.join(t, "watch.json")
            with open(cfg, "w") as fh:
                json.dump({"alert_detail": "full"}, fh)
            demo(t, "--config", cfg, "--feed-file", os.path.join(ROOT, "tests", "fixtures", "ransomware_live.json"))
            with open(os.path.join(t, "DIGEST.md")) as fh:
                md = fh.read()
            with open(os.path.join(t, "out", "alerts.json")) as fh:
                al = json.load(fh)["text"]
        for text in (md, al):
            self.assertNotRegex(text, r"https?://")
            self.assertNotRegex(text, r"[a-z0-9]\.example\b")
        self.assertIn("pinecrestdental[.]example", md)


class Feeds(unittest.TestCase):
    def test_cross_feed_dedupe(self):
        with tempfile.TemporaryDirectory() as t:
            rec = demo(t, "--feed-file", os.path.join(ROOT, "tests", "fixtures", "ransomware_live.json"))
        pine = [h for h in rec["hits"] if h["kind"] == "leak_claim" and h["client"] == "pinecrest"]
        self.assertEqual(len(pine), 1)                                   # one claim, two feeds
        self.assertEqual(pine[0]["also_seen_in"], ["ransomware_live.json"])
        self.assertEqual(pine[0]["url"], "")                             # onion link dropped

    def test_token_feed_without_token_is_reported(self):
        import feeds as fd
        os.environ.pop("RANSOMWARE_LIVE_TOKEN", None)
        r, e, c, cr = fd.fetch({"ransomlook": {"enabled": False}, "ransomware_live": {"enabled": True}})
        self.assertEqual(r, [])
        self.assertIn("RANSOMWARE_LIVE_TOKEN", e[0])

    def test_attribution_in_log(self):
        with tempfile.TemporaryDirectory() as t:
            cfg = os.path.join(t, "watch.json")
            with open(cfg, "w") as fh:
                json.dump({"feeds": {"ransomlook": {"enabled": False},
                                     "rl_file": {"enabled": True, "attribution": "Ransomware.live (https://www.ransomware.live)",
                                                 "url": os.path.join(ROOT, "tests", "fixtures", "ransomware_live.json")}}}, fh)
            r = subprocess.run([sys.executable, "tools/watch.py", "--watchlist", os.path.join(ROOT, "watchlist.example.json"),
                                "--config", cfg, "--today", "2026-11-21", "--root", t],
                               cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(t, "DIGEST.md")) as fh:
                md = fh.read()
        self.assertIn("Leak-site data: Ransomware.live", md)

    def test_quiet_watch(self):
        with tempfile.TemporaryDirectory() as t:
            empty = os.path.join(t, "empty.json")
            with open(empty, "w") as fh:
                json.dump({"clients": []}, fh)
            r = subprocess.run([sys.executable, "tools/watch.py", "--watchlist", empty, "--feed-file",
                                os.path.join(ROOT, "tests", "fixtures", "ransomlook.json"), "--today", "2026-11-21",
                                "--root", t], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(t, "DIGEST.md")) as fh:
                md = fh.read()
        self.assertIn("**All quiet.** Nothing to report.", md)


    def test_field_names_vary(self):
        import feeds as fd
        a = fd.normalize_record("x", {"victim": "Foo LLC", "domain": "foo.example", "group": "akira",
                                      "attackdate": "2026-11-20 01:00"})
        self.assertEqual((a["victim"], a["website"], a["group"], a["discovered"]),
                         ("Foo LLC", "foo.example", "akira", "2026-11-20"))


if __name__ == "__main__":
    unittest.main()
