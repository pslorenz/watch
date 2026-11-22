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
        self.assertIn("claims by criminals", md)
        self.assertIn("needs review", md)
        self.assertIn("Confined to quarters", md)

    def test_dead_feed_is_reported_not_fatal(self):
        with tempfile.TemporaryDirectory() as t:
            rec = demo(t, "--feed-file", os.path.join(t, "missing.json"))
        self.assertTrue(rec["errors"])
        self.assertTrue(rec["hits"])                                       # the good feed still counted


class Feeds(unittest.TestCase):
    def test_field_names_vary(self):
        import feeds as fd
        a = fd.normalize_record("x", {"victim": "Foo LLC", "domain": "foo.example", "group": "akira",
                                      "attackdate": "2026-11-20 01:00"})
        self.assertEqual((a["victim"], a["website"], a["group"], a["discovered"]),
                         ("Foo LLC", "foo.example", "akira", "2026-11-20"))


if __name__ == "__main__":
    unittest.main()
