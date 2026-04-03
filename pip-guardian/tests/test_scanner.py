import unittest

from guardian.scanner import _score_pattern_findings, scan_package


class TestScanner(unittest.TestCase):
    def test_executable_pth_flagged(self):
        findings = _score_pattern_findings("pkg/demo.pth", "import os\n")
        self.assertTrue(any("Executable import found in .pth file" in f["reason"] for f in findings))

    def test_known_compromised_version_blocks(self):
        report = scan_package("litellm", requested_version="1.82.8")
        self.assertTrue(report.get("known_compromise"))
        self.assertGreaterEqual(report.get("malicious_score", 0), 100)


if __name__ == "__main__":
    unittest.main()
