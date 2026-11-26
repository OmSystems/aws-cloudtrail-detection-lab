import json
from cloudtrail_analyzer.reporting import write_markdown_report
from cloudtrail_analyzer.reporting import write_json_report


def test_json_report_contains_findings_and_summary(tmp_path):
    findings = [
        {
            "rule_id": "S3-001",
            "rule_name": "Public S3 Bucket ACL",
            "severity": "HIGH",
            "event_name": "PutBucketAcl",
            "bucket_name": "company-data",
            "description": "S3 bucket ACL grants public read access."
        }
    ]

    output_path = tmp_path / "findings.json"

    write_json_report(findings, output_path)

    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert report["schema_version"] == "1.0"
    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["severity_counts"]["HIGH"] == 1
    assert report["summary"]["severity_counts"]["MEDIUM"] == 0
    assert report["summary"]["severity_counts"]["LOW"] == 0
    assert report["findings"] == findings


def test_json_report_handles_empty_findings(tmp_path):
    output_path = tmp_path / "findings.json"

    write_json_report([], output_path)

    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert report["summary"]["total_findings"] == 0
    assert report["summary"]["severity_counts"] == {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }
    assert report["findings"] == []


def test_json_report_creates_missing_output_directory(tmp_path):
    output_path = tmp_path / "nested" / "reports" / "findings.json"

    write_json_report([], output_path)

    assert output_path.exists()

def test_markdown_report_contains_summary_and_finding_details(tmp_path):
    findings = [
        {
            "rule_id": "S3-001",
            "rule_name": "Public S3 Bucket ACL",
            "severity": "HIGH",
            "event_name": "PutBucketAcl",
            "bucket_name": "company-data",
            "description": "S3 bucket ACL grants public read access."
        }
    ]

    output_path = tmp_path / "findings.md"

    write_markdown_report(findings, output_path)

    report = output_path.read_text(encoding="utf-8")

    assert "# CloudTrail Security Findings" in report
    assert "Total findings: 1" in report
    assert "HIGH: 1" in report
    assert "MEDIUM: 0" in report
    assert "LOW: 0" in report
    assert "S3-001" in report
    assert "PutBucketAcl" in report
    assert "company-data" in report
    assert "S3 bucket ACL grants public read access." in report


def test_markdown_report_handles_empty_findings(tmp_path):
    output_path = tmp_path / "findings.md"

    write_markdown_report([], output_path)

    report = output_path.read_text(encoding="utf-8")

    assert "Total findings: 0" in report
    assert "No security findings detected." in report


def test_markdown_report_supports_different_resource_types(tmp_path):
    findings = [
        {
            "rule_id": "EC2-001",
            "rule_name": "Public AMI Sharing",
            "severity": "HIGH",
            "image_id": "ami-0123456789abcdef0",
            "description": "AMI made public."
        },
        {
            "rule_id": "AUTH-001",
            "rule_name": "Console Login Failure Burst",
            "severity": "HIGH",
            "source_ip": "203.0.113.10",
            "description": "Multiple failed login attempts."
        }
    ]

    output_path = tmp_path / "findings.md"

    write_markdown_report(findings, output_path)

    report = output_path.read_text(encoding="utf-8")

    assert "**AMI:** ami-0123456789abcdef0" in report
    assert "**Source IP:** 203.0.113.10" in report


def test_markdown_report_creates_missing_output_directory(tmp_path):
    output_path = tmp_path / "nested" / "reports" / "findings.md"

    write_markdown_report([], output_path)

    assert output_path.exists()

def test_markdown_report_lists_mitre_attack(tmp_path):
    findings = [
        {
            "rule_id": "SEC-001",
            "rule_name": "Security Service Deletion or Shutdown",
            "severity": "HIGH",
            "mitre_attack": [
                {
                    "id": "T1562.008",
                    "name": "Impair Defenses: Disable or Modify Cloud Logs",
                    "tactic": "Defense Evasion",
                }
            ],
        }
    ]
    output = tmp_path / "findings.md"

    write_markdown_report(findings, output)

    assert "T1562.008 (Impair Defenses: Disable or Modify Cloud Logs)" in output.read_text(
        encoding="utf-8"
    )
