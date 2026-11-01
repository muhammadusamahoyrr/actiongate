"""Tests agreement.py on dummy labels: python bench/tools/test_agreement.py

The labels here are synthetic and exist only to exercise the script; they
are not annotations of any item.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agreement  # noqa: E402


class AgreementTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        d = self.dir.name
        key = [{"id": f"b{i}", "source": "heldout-b", "reference": "benign" if i % 2 else "secret"} for i in range(4)]
        key += [{"id": f"a{i}", "source": "public-audit", "ref_id": f"q{i}"} for i in range(4)]
        akey = [{"id": f"q{i}", "stopped_by": "facts-only" if i < 2 else "vocab-only"} for i in range(4)]
        self.key = self.write("key.jsonl", "\n".join(json.dumps(k) for k in key))
        self.akey = self.write("akey.jsonl", "\n".join(json.dumps(k) for k in akey))
        ref = {k["id"]: k.get("reference", "benign") for k in key}
        h1 = dict(ref)
        h2 = dict(ref, b0="destructive", a0="opaque")  # two disagreements with h1
        ag = dict(ref)
        self.h1 = self.labels("h1.json", "human-1", h1)
        self.h2 = self.labels("h2.json", "human-2", h2)
        self.ag = self.labels("ag.json", "agent", ag)

    def tearDown(self):
        self.dir.cleanup()

    def write(self, name, text):
        p = os.path.join(self.dir.name, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    def labels(self, name, who, lab):
        return self.write(name, json.dumps({"annotator": who, "labels": [{"id": i, "label": l} for i, l in lab.items()]}))

    def run_main(self, args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            agreement.main(args)
        return out.getvalue()

    def test_kappa(self):
        self.assertAlmostEqual(agreement.kappa(["a", "b"], ["a", "b"]), 1.0)
        # po = 0.5, pe = 0.5 -> 0
        self.assertAlmostEqual(agreement.kappa(["a", "a", "b", "b"], ["a", "b", "a", "b"]), 0.0)

    def test_pairs_and_disagreements(self):
        out = self.run_main([self.key, self.akey, self.h1, self.h2, "--agent", self.ag])
        self.assertIn("human vs human: human-1 vs human-2", out)
        self.assertIn("human vs agent: human-1 vs agent", out)
        self.assertIn("human vs agent: human-2 vs agent", out)
        self.assertIn("all (8 items): agreement 6/8", out)
        self.assertIn("secret->destructive 1", out)
        self.assertIn("benign->opaque 1", out)
        self.assertIn("destructive 1", out)

    def test_duplicate_annotator_rejected(self):
        with self.assertRaises(SystemExit):
            self.run_main([self.key, self.akey, self.h1, self.h1])


if __name__ == "__main__":
    unittest.main()
