import unittest

from guardian.policy_engine import evaluate_risk


class TestPolicyEngine(unittest.TestCase):
    def test_unknown_risk_warns(self):
        decision = evaluate_risk({"risk": "unknown"}, policy={"block_if_version_younger_than_hours": 5, "warn_if_version_younger_than_hours": 48})
        self.assertEqual(decision, "WARN")

    def test_block_before_warn(self):
        report = {
            "package": "demo",
            "version": "1.0.0",
            "hours_since_upload": 1.5,
            "maintainer": "safe-maintainer",
            "is_yanked": False,
            "release_count": 10,
        }
        decision = evaluate_risk(report, policy={"block_if_version_younger_than_hours": 5, "warn_if_version_younger_than_hours": 48})
        self.assertEqual(decision, "BLOCK")

    def test_recent_warn(self):
        report = {
            "package": "demo",
            "version": "1.0.0",
            "hours_since_upload": 12,
            "maintainer": "safe-maintainer",
            "is_yanked": False,
            "release_count": 10,
        }
        decision = evaluate_risk(report, policy={"block_if_version_younger_than_hours": 5, "warn_if_version_younger_than_hours": 48})
        self.assertEqual(decision, "WARN")

    def test_old_release_allowed(self):
        report = {
            "package": "demo",
            "version": "1.0.0",
            "hours_since_upload": 200,
            "maintainer": "safe-maintainer",
            "is_yanked": False,
            "release_count": 10,
        }
        decision = evaluate_risk(report, policy={"block_if_version_younger_than_hours": 5, "warn_if_version_younger_than_hours": 48})
        self.assertEqual(decision, "ALLOW")

    def test_known_compromise_blocks(self):
        report = {
            "package": "litellm",
            "version": "1.82.8",
            "hours_since_upload": 100,
            "maintainer": "safe-maintainer",
            "is_yanked": False,
            "release_count": 50,
            "known_compromise": True,
        }
        decision = evaluate_risk(
            report,
            policy={
                "block_if_version_younger_than_hours": 5,
                "warn_if_version_younger_than_hours": 48,
                "block_if_malicious_score_at_least": 80,
                "warn_if_malicious_score_at_least": 50,
                "block_on_executable_pth": True,
            },
        )
        self.assertEqual(decision, "BLOCK")

    def test_malicious_score_warns(self):
        report = {
            "package": "demo",
            "version": "1.0.0",
            "hours_since_upload": 200,
            "maintainer": "safe-maintainer",
            "is_yanked": False,
            "release_count": 50,
            "malicious_score": 55,
        }
        decision = evaluate_risk(
            report,
            policy={
                "block_if_version_younger_than_hours": 5,
                "warn_if_version_younger_than_hours": 48,
                "block_if_malicious_score_at_least": 80,
                "warn_if_malicious_score_at_least": 50,
                "block_on_executable_pth": True,
            },
        )
        self.assertEqual(decision, "WARN")


if __name__ == "__main__":
    unittest.main()
