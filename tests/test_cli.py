import json

from cloudtrail_analyzer import __main__ as cli


def test_main_generates_reports_from_datasets(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "PROJECT_ROOT", tmp_path)

    dataset_paths = [
        "datasets/s3-public/public-bucket-acl.json",
        "datasets/security-service-deletion/security-events.json",
        "datasets/login-failures/console-login-burst.json",
        "datasets/ami-public/public-ami-sharing.json",
    ]

    for dataset_path in dataset_paths:
        full_path = tmp_path / dataset_path
        full_path.parent.mkdir(parents=True, exist_ok=True)

        records = []

        if "s3-public" in dataset_path:
            records.append({
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutBucketAcl",
                "requestParameters": {
                    "bucketName": "test-company-data",
                    "AccessControlPolicy": {
                        "AccessControlList": {
                            "Grant": [
                                {
                                    "Grantee": {
                                        "URI": (
                                            "http://acs.amazonaws.com/"
                                            "groups/global/AllUsers"
                                        )
                                    },
                                    "Permission": "READ",
                                }
                            ]
                        }
                    }
                }
            })

        full_path.write_text(
            json.dumps({"Records": records}),
            encoding="utf-8",
        )

    cli.main()

    json_path = tmp_path / "reports" / "findings.json"
    markdown_path = tmp_path / "reports" / "findings.md"

    assert json_path.exists()
    assert markdown_path.exists()

    report = json.loads(json_path.read_text(encoding="utf-8"))

    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["severity_counts"]["HIGH"] == 1
    assert report["findings"][0]["rule_id"] == "S3-001"
    assert report["findings"][0]["bucket_name"] == "test-company-data"

    markdown = markdown_path.read_text(encoding="utf-8")
    assert "test-company-data" in markdown

    output = capsys.readouterr().out
    assert "Events analyzed: 1" in output
    assert "Findings detected: 1" in output


def _write_log(path, events):
    path.write_text(json.dumps({"Records": events}), encoding="utf-8")


STOP_EVENT = {
    "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "StopLogging",
    "eventID": "e1",
    "eventTime": "2026-01-01T00:00:00Z",
    "userIdentity": {"arn": "arn:aws:iam::111122223333:user/test"},
}


def test_paths_mode_prints_findings_and_rule_coverage(tmp_path, capsys):
    log = tmp_path / "log.json"
    _write_log(log, [STOP_EVENT])

    exit_code = cli.main([str(log)])

    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Files loaded: 1 (skipped: 0)" in output
    assert "Events analyzed: 1" in output
    assert "SEC-001 StopLogging/DeleteTrail/DeleteDetector: 1" in output
    assert "S3-001  PutBucketAcl: 0" in output
    assert "Findings detected: 1" in output
    assert "SEC-001 HIGH StopLogging" in output


def test_paths_mode_does_not_touch_repo_reports(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "PROJECT_ROOT", tmp_path / "repo")
    log = tmp_path / "log.json"
    _write_log(log, [STOP_EVENT])

    cli.main([str(log)])

    assert not (tmp_path / "repo").exists()


def test_paths_mode_writes_reports_to_output_dir(tmp_path):
    log = tmp_path / "log.json"
    out = tmp_path / "out"
    _write_log(log, [STOP_EVENT])

    cli.main([str(log), "--output-dir", str(out)])

    report = json.loads((out / "findings.json").read_text(encoding="utf-8"))

    assert report["summary"]["total_findings"] == 1
    assert (out / "findings.md").exists()


def test_paths_mode_counts_failed_console_logins(tmp_path, capsys):
    log = tmp_path / "log.json"
    failure = {
        "eventName": "ConsoleLogin",
        "responseElements": {"ConsoleLogin": "Failure"},
    }
    success = {
        "eventName": "ConsoleLogin",
        "responseElements": {"ConsoleLogin": "Success"},
    }
    _write_log(log, [failure, failure, success])

    cli.main([str(log)])

    assert "AUTH-001 failed ConsoleLogin: 2" in capsys.readouterr().out


def test_paths_mode_reports_skipped_files(tmp_path, capsys):
    good = tmp_path / "good.json"
    bad = tmp_path / "bad.json"
    _write_log(good, [STOP_EVENT])
    bad.write_text("{nope", encoding="utf-8")

    exit_code = cli.main([str(tmp_path)])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Files loaded: 1 (skipped: 1)" in captured.out
    assert "Skipped" in captured.err and "bad.json" in captured.err


def test_paths_mode_fails_when_nothing_loads(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")

    assert cli.main([str(bad)]) == 1
    assert "No CloudTrail files could be loaded" in capsys.readouterr().err


def test_paths_mode_fails_for_missing_path(tmp_path, capsys):
    assert cli.main([str(tmp_path / "missing")]) == 1
    assert "No such file or directory" in capsys.readouterr().err


def test_output_dir_without_paths_is_rejected(capsys):
    assert cli.main(["--output-dir", "x"]) == 2
