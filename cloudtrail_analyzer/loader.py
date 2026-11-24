import json
from pathlib import Path


def load_events(file_path):
    path = Path(file_path)
    content = path.read_text(encoding="utf-8")
    data = json.loads(content)

    if not isinstance(data, dict):
        raise ValueError("CloudTrail JSON must contain a dictionary at the top level")

    if "Records" not in data:
        raise ValueError("Missing Records field in CloudTrail JSON")

    records = data["Records"]

    if not isinstance(records, list):
        raise ValueError("Records must be a list")

    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Each CloudTrail record must be a dictionary")

    return records