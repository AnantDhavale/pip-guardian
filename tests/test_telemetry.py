import os
import unittest
from unittest.mock import patch

from guardian.telemetry import build_event, telemetry_enabled


class TestTelemetry(unittest.TestCase):
    def test_disabled_by_default(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(telemetry_enabled())

    def test_enabled_truthy_flag(self):
        with patch.dict(os.environ, {"GUARDIAN_TELEMETRY": "1"}, clear=True):
            self.assertTrue(telemetry_enabled())

    def test_build_event_shape(self):
        with patch.dict(os.environ, {"GUARDIAN_TELEMETRY_USER_ID": "customer-acme"}, clear=True):
            event = build_event(
                target="litellm==1.82.8",
                package_name="litellm",
                command="install",
                decision="BLOCK",
                installed=False,
                exit_code=1,
                json_mode=True,
            )
        self.assertEqual(event["event"], "guardian_install")
        self.assertEqual(event["package_name"], "litellm")
        self.assertEqual(event["telemetry_user_id"], "customer-acme")
        self.assertIn("install_id", event)
        self.assertIn("host_hash", event)


if __name__ == "__main__":
    unittest.main()
