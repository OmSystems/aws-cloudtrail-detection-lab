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

STOP_LOGGING = {
    "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "StopLogging",
    "eventID": "e1",
}
DELETE_TRAIL = {
    "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "DeleteTrail",
    "eventID": "e2",
}


def test_load_events_reads_newline_delimited_json(tmp_path):
    file_path = tmp_path / "events.jsonl"
    file_path.write_text(
        json.dumps(STOP_LOGGING) + "\n\n" + json.dumps(DELETE_TRAIL) + "\n",
        encoding="utf-8",
    )

    assert load_events(file_path) == [STOP_LOGGING, DELETE_TRAIL]


def test_load_events_reads_ndjson_lines_that_are_log_files(tmp_path):
    file_path = tmp_path / "events.json"
    file_path.write_text(
        json.dumps({"Records": [STOP_LOGGING]})
        + "\n"
        + json.dumps({"Records": [DELETE_TRAIL]}),
        encoding="utf-8",
    )

    assert load_events(file_path) == [STOP_LOGGING, DELETE_TRAIL]


def test_load_events_reads_single_bare_event(tmp_path):
    file_path = tmp_path / "event.json"
    file_path.write_text(json.dumps(STOP_LOGGING), encoding="utf-8")

    assert load_events(file_path) == [STOP_LOGGING]


def test_load_events_reads_gzip_log_file(tmp_path):
    import gzip

    file_path = tmp_path / "log.json.gz"

    with gzip.open(file_path, "wt", encoding="utf-8") as handle:
        handle.write(json.dumps({"Records": [STOP_LOGGING]}))

    assert load_events(file_path) == [STOP_LOGGING]


def test_load_events_reads_gzip_ndjson(tmp_path):
    import gzip

    file_path = tmp_path / "log.jsonl.gz"

    with gzip.open(file_path, "wt", encoding="utf-8") as handle:
        handle.write(json.dumps(STOP_LOGGING) + "\n" + json.dumps(DELETE_TRAIL))

    assert load_events(file_path) == [STOP_LOGGING, DELETE_TRAIL]


def test_ndjson_with_a_bad_line_names_the_line(tmp_path):
    file_path = tmp_path / "events.jsonl"
    file_path.write_text(
        json.dumps(STOP_LOGGING) + "\n{not json}\n", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="line 2"):
        load_events(file_path)


def test_ndjson_rejects_non_dictionary_lines(tmp_path):
    file_path = tmp_path / "events.jsonl"
    file_path.write_text(
        json.dumps(STOP_LOGGING) + "\n" + json.dumps(["x"]) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="dictionary"):
        load_events(file_path)


def test_load_events_from_paths_walks_directories_and_skips_bad_files(tmp_path):
    from cloudtrail_analyzer.loader import load_events_from_paths

    (tmp_path / "sub").mkdir()
    (tmp_path / "a.json").write_text(
        json.dumps({"Records": [STOP_LOGGING]}), encoding="utf-8"
    )
    (tmp_path / "sub" / "b.jsonl").write_text(
        json.dumps(DELETE_TRAIL), encoding="utf-8"
    )
    (tmp_path / "broken.json").write_text("{nope", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("ignored", encoding="utf-8")

    events, loaded, errors = load_events_from_paths([tmp_path])

    assert events == [STOP_LOGGING, DELETE_TRAIL]
    assert [p.name for p in loaded] == ["a.json", "b.jsonl"]
    assert [p.name for p, _ in errors] == ["broken.json"]


def test_load_events_from_paths_rejects_missing_path(tmp_path):
    from cloudtrail_analyzer.loader import load_events_from_paths

    with pytest.raises(FileNotFoundError):
        load_events_from_paths([tmp_path / "nope"])
