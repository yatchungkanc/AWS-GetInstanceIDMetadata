import tempfile
import unittest
from pathlib import Path

from aws_findings_metadata.agents import ActivityLogger, FindingsIngestionAgent


class FindingsIngestionAgentTest(unittest.TestCase):
    def test_parses_utf16_tsv_and_groups_by_account_title_severity(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "findings.csv"
            log_file = tmp_path / "logs" / "run.jsonl"
            source.write_text(
                "\t".join(
                    [
                        "Account ID",
                        "Account Name",
                        "Finding ID",
                        "Resource ID",
                        "Region",
                        "Vuln Title",
                        "Severity Level",
                        "Status",
                        "BU ID",
                        "Description",
                        "First Detected (Cloud Config Findings)",
                        "Id (Cloud Config Vulns)",
                        "Last Detected (Cloud Config Findings)",
                        "Region",
                        "Remediation",
                    ]
                )
                + "\n"
                + "\t".join(
                    [
                        "123456789012",
                        "prod",
                        "finding-1",
                        "i-abc123",
                        "us-east-1",
                        "Missing Agent",
                        "Critical",
                        "Open",
                        "DENG",
                        "description",
                        "01/01/2026 00:00:00",
                        "VULN-1",
                        "02/01/2026 00:00:00",
                        "us-west-2",
                        "fix it",
                    ]
                )
                + "\n"
                + "\t".join(
                    [
                        "123456789012",
                        "prod",
                        "finding-2",
                        "i-def456",
                        "us-east-2",
                        "Missing Agent",
                        "Critical",
                        "Open",
                        "DENG",
                        "description",
                        "01/01/2026 00:00:00",
                        "VULN-1",
                        "02/01/2026 00:00:00",
                        "us-west-1",
                        "fix it",
                    ]
                )
                + "\n",
                encoding="utf-16",
            )

            logger = ActivityLogger(log_file)
            try:
                groups = FindingsIngestionAgent(logger).parse(source)
            finally:
                logger.close()

            self.assertEqual(len(groups), 1)
            self.assertEqual(groups[0].account_id, "123456789012")
            self.assertEqual(groups[0].vuln_title, "Missing Agent")
            self.assertEqual(groups[0].severity, "Critical")
            self.assertEqual([item.region for item in groups[0].items], ["us-east-1", "us-east-2"])
            self.assertEqual(groups[0].items[0].source_fields["finding_id"], "finding-1")


if __name__ == "__main__":
    unittest.main()

