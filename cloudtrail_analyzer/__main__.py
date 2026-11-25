from pathlib import Path

from cloudtrail_analyzer.engine import run_detection
from cloudtrail_analyzer.loader import load_events
from cloudtrail_analyzer.reporting import (
    write_json_report,
    write_markdown_report,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATASET_PATHS = [
    "datasets/s3-public/public-bucket-acl.json",
    "datasets/security-service-deletion/security-events.json",
    "datasets/login-failures/console-login-burst.json",
    "datasets/ami-public/public-ami-sharing.json",
]


def main():
    all_events = []

    for dataset_path in DATASET_PATHS:
        full_path = PROJECT_ROOT / dataset_path
        events = load_events(full_path)
        all_events.extend(events)

    findings = run_detection(all_events)

    json_output = PROJECT_ROOT / "reports" / "findings.json"
    markdown_output = PROJECT_ROOT / "reports" / "findings.md"

    write_json_report(findings, json_output)
    write_markdown_report(findings, markdown_output)

    print(f"Events analyzed: {len(all_events)}")
    print(f"Findings detected: {len(findings)}")
    print(f"JSON report: {json_output}")
    print(f"Markdown report: {markdown_output}")


if __name__ == "__main__":
    main()
