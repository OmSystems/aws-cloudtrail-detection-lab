import gzip
import json
from pathlib import Path

LOG_SUFFIXES = (
    ".json",
    ".jsonl",
    ".ndjson",
    ".json.gz",
    ".jsonl.gz",
    ".ndjson.gz",
)


def _read_text(path):
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            return handle.read()

    return path.read_text(encoding="utf-8")


def _validate_records(records):
    if not isinstance(records, list):
        raise ValueError("Records must be a list")

    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Each CloudTrail record must be a dictionary")

    return records


def _parse_json_document(data):
    """Validate one parsed JSON document and return its CloudTrail records.

    Accepts a CloudTrail log file ({"Records": [...]}) or one bare event.
    """
    if not isinstance(data, dict):
        raise ValueError("CloudTrail JSON must contain a dictionary at the top level")

    if "Records" in data:
        return _validate_records(data["Records"])

    if "eventName" in data:
        return [data]

    raise ValueError("Missing Records field in CloudTrail JSON")


def _parse_ndjson(lines):
    """Parse newline-delimited JSON: one event (or one log file) per line."""
    records = []

    for number, line in lines:
        try:
            item = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(
                "Not valid JSON or newline-delimited JSON "
                f"(line {number}: {error.msg})"
            ) from error

        records.extend(_parse_json_document(item))

    return records


def _parse_content(content):
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        lines = [
            (number, line)
            for number, line in enumerate(content.splitlines(), start=1)
            if line.strip()
        ]

        # One bad line is plain invalid JSON, not NDJSON.
        if len(lines) < 2:
            raise

        return _parse_ndjson(lines)

    return _parse_json_document(data)


def load_events(file_path):
    """Load CloudTrail events from one file.

    Supports a CloudTrail log file ({"Records": [...]}), newline-delimited
    JSON (one event per line, as many SIEM and Athena exports produce), a
    single bare event, and any of these gzip-compressed (.gz).
    """
    path = Path(file_path)

    return _parse_content(_read_text(path))


def find_log_files(paths):
    """Expand files and directories into a sorted list of log files."""
    found = []

    for raw_path in paths:
        path = Path(raw_path)

        if path.is_dir():
            found.extend(
                sorted(
                    candidate
                    for candidate in path.rglob("*")
                    if candidate.is_file()
                    and candidate.name.lower().endswith(LOG_SUFFIXES)
                )
            )
        elif path.is_file():
            found.append(path)
        else:
            raise FileNotFoundError(f"No such file or directory: {path}")

    return found


def load_events_from_paths(paths):
    """Load events from files and directories, skipping unreadable files.

    Returns (events, loaded_files, errors) where errors is a list of
    (path, message) so one bad file does not hide the rest.
    """
    events = []
    loaded_files = []
    errors = []

    for path in find_log_files(paths):
        try:
            events.extend(load_events(path))
        except (ValueError, OSError, EOFError) as error:
            errors.append((path, str(error)))
        else:
            loaded_files.append(path)

    return events, loaded_files, errors
