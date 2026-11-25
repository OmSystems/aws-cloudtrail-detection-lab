import json
from pathlib import Path


def write_json_report(findings, output_path):
    """
    Write security findings to a structured JSON report.
    """

    severity_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        severity = finding.get("severity")

        if severity in severity_counts:
            severity_counts[severity] += 1

    report = {
        "schema_version": "1.0",
        "summary": {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
        },
        "findings": findings,
    }

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8",
    )
def write_markdown_report(findings, output_path):
    """
    Write security findings to a human-readable Markdown report.
    """

    severity_order = ["HIGH", "MEDIUM", "LOW"]

    severity_counts = {
        severity: 0 for severity in severity_order
    }

    for finding in findings:
        severity = finding.get("severity")

        if severity in severity_counts:
            severity_counts[severity] += 1

    lines = [
        "# CloudTrail Security Findings",
        "",
        "## Summary",
        "",
        f"- Total findings: {len(findings)}",
    ]

    for severity in severity_order:
        lines.append(
            f"- {severity}: {severity_counts[severity]}"
        )

    lines.extend(["", "## Findings", ""])

    if not findings:
        lines.append("No security findings detected.")

    else:
        for severity in severity_order:

            severity_findings = [
                finding
                for finding in findings
                if finding.get("severity") == severity
            ]

            for finding in severity_findings:

                rule_id = finding.get("rule_id", "Unknown")
                rule_name = finding.get("rule_name", "Unknown rule")

                lines.extend([
                    f"### {severity} — {rule_id}: {rule_name}",
                    "",
                ])

                if "event_name" in finding:
                    lines.append(
                        f"- **Event:** {finding['event_name']}"
                    )

                resource_fields = {
                    "bucket_name": "Bucket",
                    "image_id": "AMI",
                    "event_time": "Time",
                    "first_event_time": "First failure",
                    "last_event_time": "Last failure",
                    "actor": "Actor",
                    "source_ip": "Source IP",
                    "aws_region": "Region",
                    "event_id": "Event ID",
                }

                for field, label in resource_fields.items():
                    if finding.get(field):
                        lines.append(
                            f"- **{label}:** {finding[field]}"
                        )

                if finding.get("failed_attempts"):
                    lines.append(
                        f"- **Failed attempts:** {finding['failed_attempts']}"
                    )

                if finding.get("targeted_users"):
                    lines.append(
                        "- **Targeted users:** "
                        + ", ".join(finding["targeted_users"])
                    )

                if finding.get("event_ids"):
                    lines.append(
                        "- **Event IDs:** "
                        + ", ".join(finding["event_ids"])
                    )

                description = finding.get(
                    "description",
                    "No description available."
                )

                lines.extend([
                    f"- **Description:** {description}",
                    "",
                ])

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )