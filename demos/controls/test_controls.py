"""Offline failure gates; run with python3 -I demos/controls/test_controls.py."""
import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
from common import CASES, PAGE, extend, frame, intended_chain, log_offset, sha


class ControlsTest(unittest.TestCase):
    def test_all_presenters_replay_both_checked_receipts(self):
        directory = Path(__file__).resolve().parent
        for filename, runtime in (("azure-controls.json", False), ("azure-controls-real-runtimes.json", True)):
            receipt = directory.parents[1] / "docs/results" / filename
            for shell in ("basic", "java-base64", "app-sandbox", "java-sql-inj", "af-alg"):
                with self.subTest(shell=shell, fixture=filename):
                    p = subprocess.run([directory / (shell+".sh"), "--receipt", receipt],
                                       capture_output=True, text=True, check=True)
                    self.assertIn("offline replay", p.stdout)
                    for label in ("Upstream:", "Before:", "Active:", "Restored:", "Positive control:"):
                        self.assertIn(label, p.stdout)
                    if shell == "app-sandbox":
                        self.assertIn("Ubuntu PHP-FPM worker" if runtime else "PHP-FPM-named Python fixture", p.stdout)
                    if shell == "java-sql-inj":
                        self.assertIn("H2 JDBC" if runtime else "mock JDBC / SQLite", p.stdout)
                    if shell == "java-base64":
                        self.assertIn("post-unload decode not measured", p.stdout)

    def test_presenter_rejects_missing_contradictory_and_unsupported_evidence(self):
        directory = Path(__file__).resolve().parent
        template = (directory.parents[1] / "docs/results/azure-controls.json").read_text()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipt.json"
            for change, expected in (("missing-file", 1), ("invalid-json", 1), ("missing-row", 1),
                                     ("inconsistent", 1), ("unattested", 1), ("unsupported", 3)):
                with self.subTest(change=change):
                    data = json.loads(template)
                    if change == "missing-row":
                        del data["controls"]["basic"]
                    elif change == "inconsistent":
                        data["controls"]["basic"]["after_unload"] = "present"
                    elif change == "unattested":
                        data["attestation"]["fresh_before_and_after"] = False
                    elif change == "unsupported":
                        data["controls"]["basic"] = {"status": "unsupported", "reason": "signed_pair_not_staged"}
                    if change != "missing-file":
                        path.write_text("{" if change == "invalid-json" else json.dumps(data))
                    p = subprocess.run([directory / "basic.sh", "--receipt", path], capture_output=True, text=True)
                    self.assertEqual(p.returncode, expected)
                    self.assertNotIn("Positive control:", p.stdout)

    def test_only_owned_pairs_advance_final_chain(self):
        controls = {name: {"status": "unsupported"} for name in CASES}
        pairs = {name: ["", "", "03" * 32] for name in CASES}
        baseline = "0a" * 32
        controls["java-base64"] = {"status": "verified", "lifecycle": "preserved_preexisting"}
        self.assertEqual(intended_chain(baseline, pairs, controls), baseline)
        controls["basic"] = {"status": "verified", "lifecycle": "owned_pair"}
        self.assertEqual(intended_chain(baseline, pairs, controls),
                         extend(extend(baseline, "basic", "load", "03" * 32), "basic", "unload", "03" * 32))
        controls["basic"]["lifecycle"] = "preserved_preexisting"
        with self.assertRaisesRegex(ValueError, "unexpected preexisting"):
            intended_chain(baseline, pairs, controls)
        del controls["basic"]
        with self.assertRaisesRegex(ValueError, "incomplete"):
            intended_chain(baseline, pairs, controls)

    def test_evidence_page_fits_but_unbounded_output_is_refused(self):
        data = {"first": base64.b64encode(os.urandom(PAGE)).decode(), "sha": "a" * 64, "pages": 2}
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            frame(data)
        encoded = stream.getvalue().strip().split(":", 1)[1]
        self.assertLess(len(encoded), 3800)
        self.assertEqual(json.loads(zlib.decompress(base64.b64decode(encoded))), data)
        with self.assertRaisesRegex(ValueError, "limit"):
            frame(base64.b64encode(os.urandom(8192)).decode())

    def test_only_identical_log_suffix_can_reconstruct_the_original_quote(self):
        earlier = b'{"nonce":"old","logs":{"firmware":"same"}}\n'
        latest = b'{"nonce":"new","some":"added","logs":{"firmware":"same"}}\n'
        suffix = earlier[log_offset(earlier):]
        self.assertEqual(latest[:log_offset(latest)] + suffix, latest)
        different_boot = latest.replace(b"same", b"new!")
        self.assertNotEqual(sha(suffix), sha(different_boot[log_offset(different_boot):]))


if __name__ == "__main__":
    unittest.main()
