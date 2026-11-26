import argparse
import sys
from pathlib import Path

from cloudtrail_analyzer.engine import run_detection
from cloudtrail_analyzer.loader import load_events, load_events_from_paths
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


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m cloudtrail_analyzer",
        description=(
            "Run the detection rules. With no paths, analyze the bundled "
            "fixtures and refresh reports/. With paths, analyze those "
            "CloudTrail files or directories (.json, .jsonl, .ndjson, .gz)."
        ),
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="CloudTrail log files or directories to analyze",
    )
    parser.add_argument(
        "--output-dir",
        help="with paths: also write findings.json and findings.md here",
    )

    return parser


def count_rule_relevant_events(events):
    """Count the events each rule can match, so you can see whether an input
    is able to exercise a rule at all."""
    counts = {
        "S3-001  PutBucketAcl": 0,
        "SEC-001 StopLogging/DeleteTrail/DeleteDetector": 0,
        "EC2-001 ModifyImageAttribute": 0,
        "AUTH-001 failed ConsoleLogin": 0,
    }

    for event in events:
        name = event.get("eventName")

        if name == "PutBucketAcl":
            counts["S3-001  PutBucketAcl"] += 1
        elif name in ("StopLogging", "DeleteTrail", "DeleteDetector"):
            counts["SEC-001 StopLogging/DeleteTrail/DeleteDetector"] += 1
        elif name == "ModifyImageAttribute":
            counts["EC2-001 ModifyImageAttribute"] += 1
        elif name == "ConsoleLogin":
            response = event.get("responseElements")

            if (
                isinstance(response, dict)
                and response.get("ConsoleLogin") == "Failure"
            ):
                counts["AUTH-001 failed ConsoleLogin"] += 1

    return counts


def analyze_paths(paths, output_dir=None):
    """Analyze user-supplied logs. Returns a process exit code."""
    try:
        events, loaded_files, errors = load_events_from_paths(paths)
    except FileNotFoundError as error:
        print(error, file=sys.stderr)
        return 1

    for path, message in errors:
        print(f"Skipped {path}: {message}", file=sys.stderr)

    print(f"Files loaded: {len(loaded_files)} (skipped: {len(errors)})")

    if not loaded_files:
        print("No CloudTrail files could be loaded.", file=sys.stderr)
        return 1

    findings = run_detection(events)

    print(f"Events analyzed: {len(events)}")
    print("Events each rule can match in this input:")

    for label, count in count_rule_relevant_events(events).items():
        print(f"  {label}: {count}")

    print(f"Findings detected: {len(findings)}")

    for finding in findings:
        when = finding.get("event_time") or finding.get("first_event_time", "")
        who = finding.get("actor") or finding.get("source_ip", "")
        what = finding.get("event_name", "")

        print(
            f"  {finding['rule_id']} {finding['severity']} "
            f"{what} {when} {who}".rstrip()
        )

    if output_dir:
        out = Path(output_dir)
        write_json_report(findings, out / "findings.json")
        write_markdown_report(findings, out / "findings.md")
        print(f"Reports written to {out}")

    return 0


def main(argv=None):
    args = build_parser().parse_args([] if argv is None else argv)

    if args.paths:
        return analyze_paths(args.paths, args.output_dir)

    if args.output_dir:
        print("--output-dir only applies when paths are given", file=sys.stderr)
        return 2

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

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
