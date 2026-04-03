import unittest

from guardian.cli import _extract_flag, _extract_name_and_exact_version


class TestCliHelpers(unittest.TestCase):
    def test_extract_name_and_version(self):
        name, version = _extract_name_and_exact_version("litellm==1.82.8")
        self.assertEqual(name, "litellm")
        self.assertEqual(version, "1.82.8")

    def test_extract_name_without_version(self):
        name, version = _extract_name_and_exact_version("requests")
        self.assertEqual(name, "requests")
        self.assertIsNone(version)

    def test_extract_flag(self):
        found, args = _extract_flag(["install", "requests", "--json"], "--json")
        self.assertTrue(found)
        self.assertEqual(args, ["install", "requests"])


if __name__ == "__main__":
    unittest.main()
