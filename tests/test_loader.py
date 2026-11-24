import json
import pytest

from cloudtrail_analyzer.loader import load_events


def test_load_events_returns_records(tmp_path):
    sample_data = {
        "Records": [
            {"eventName": "ConsoleLogin"},
            {"eventName": "PutBucketPolicy"}
        ]
    }

    file_path = tmp_path / "cloudtrail.json"
    file_path.write_text(json.dumps(sample_data), encoding="utf-8")

    result = load_events(file_path)

    assert result == sample_data["Records"]
    assert len(result) == 2


def test_load_events_raises_error_when_records_missing(tmp_path):
    sample_data = {
        "eventVersion": "1.08"
    }

    file_path = tmp_path / "invalid_cloudtrail.json"
    file_path.write_text(json.dumps(sample_data), encoding="utf-8")

    with pytest.raises(ValueError, match="Missing Records field"):
        load_events(file_path)


def test_load_events_rejects_non_dictionary_json(tmp_path):
    file_path = tmp_path / "invalid_cloudtrail.json"
    file_path.write_text(json.dumps(["event1", "event2"]), encoding="utf-8")

    with pytest.raises(ValueError, match="dictionary"):
        load_events(file_path)


def test_load_events_rejects_non_list_records(tmp_path):
    sample_data = {
        "Records": {"eventName": "ConsoleLogin"}
    }

    file_path = tmp_path / "invalid_cloudtrail.json"
    file_path.write_text(json.dumps(sample_data), encoding="utf-8")

    with pytest.raises(ValueError, match="Records must be a list"):
        load_events(file_path)


def test_load_events_rejects_non_dictionary_record(tmp_path):
    sample_data = {
        "Records": [
            {"eventName": "ConsoleLogin"},
            "invalid_record"
        ]
    }

    file_path = tmp_path / "invalid_cloudtrail.json"
    file_path.write_text(json.dumps(sample_data), encoding="utf-8")

    with pytest.raises(ValueError, match="Each CloudTrail record must be a dictionary"):
        load_events(file_path)


def test_load_events_accepts_empty_records(tmp_path):
    sample_data = {
        "Records": []
    }

    file_path = tmp_path / "empty_cloudtrail.json"
    file_path.write_text(json.dumps(sample_data), encoding="utf-8")

    result = load_events(file_path)

    assert result == []


def test_load_events_rejects_invalid_json(tmp_path):
    file_path = tmp_path / "invalid_cloudtrail.json"
    file_path.write_text("{invalid json}", encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        load_events(file_path)


def test_load_events_raises_error_when_file_does_not_exist(tmp_path):
    file_path = tmp_path / "nonexistent.json"

    with pytest.raises(FileNotFoundError):
        load_events(file_path)