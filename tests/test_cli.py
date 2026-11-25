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
