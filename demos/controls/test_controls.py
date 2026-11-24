"""Offline failure gates; run with python3 -I demos/controls/test_controls.py."""
import base64
import contextlib
import io
import json
import os
import sys
import unittest
import zlib
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
from common import CASES, PAGE, extend, frame, intended_chain, log_offset, sha


class ControlsTest(unittest.TestCase):
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
