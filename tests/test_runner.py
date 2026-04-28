import unittest
from pathlib import Path

from aws_findings_metadata.runner import resolve_output_paths


class RunnerTest(unittest.TestCase):
    def test_resolve_output_paths_uses_shared_timestamp_for_missing_paths(self):
        output_file, log_file = resolve_output_paths(None, None, timestamp="20260428T120000Z")

        self.assertEqual(output_file, Path("output/enriched-findings-20260428T120000Z.csv"))
        self.assertEqual(log_file, Path("logs/enriched-findings-20260428T120000Z.jsonl"))

    def test_resolve_output_paths_preserves_explicit_paths(self):
        output_file, log_file = resolve_output_paths(
            "custom/out.csv",
            "custom/run.jsonl",
            timestamp="20260428T120000Z",
        )

        self.assertEqual(output_file, Path("custom/out.csv"))
        self.assertEqual(log_file, Path("custom/run.jsonl"))


if __name__ == "__main__":
    unittest.main()

