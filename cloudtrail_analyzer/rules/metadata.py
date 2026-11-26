"""Single source of truth for rule identity, severity and MITRE ATT&CK mapping.

Severities and mappings are assigned by the project author. Rationale:

- S3-001  HIGH    a public read grant exposes bucket data unless Block Public
                  Access overrides it (the rule cannot tell).
- SEC-001 HIGH    a successful stop/delete of a security service removes
                  visibility, which attackers do to hide later activity.
- EC2-001 HIGH    a public AMI can leak secrets and code to anyone.
- AUTH-001 MEDIUM failed logins alone do not show that a credential worked.
"""

VALID_SEVERITIES = ("HIGH", "MEDIUM", "LOW")

RULE_METADATA = {
    "S3-001": {
        "rule_name": "Public S3 Bucket ACL",
        "severity": "HIGH",
        "mitre_attack": [
            {
                "id": "T1530",
                "name": "Data from Cloud Storage",
                "tactic": "Collection",
            },
        ],
    },
    "SEC-001": {
        "rule_name": "Security Service Deletion or Shutdown",
        "severity": "HIGH",
        "mitre_attack": [
            {
                "id": "T1562.008",
                "name": "Impair Defenses: Disable or Modify Cloud Logs",
                "tactic": "Defense Evasion",
            },
        ],
    },
    "AUTH-001": {
        "rule_name": "Console Login Failure Burst",
        "severity": "MEDIUM",
        "mitre_attack": [
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
            },
        ],
    },
    "EC2-001": {
        "rule_name": "Public AMI Sharing",
        "severity": "HIGH",
        "mitre_attack": [
            {
                "id": "T1537",
                "name": "Transfer Data to Cloud Account",
                "tactic": "Exfiltration",
            },
        ],
    },
}


def rule_fields(rule_id):
    """Return the identity fields every finding of this rule must carry."""
    meta = RULE_METADATA[rule_id]

    return {
        "rule_id": rule_id,
        "rule_name": meta["rule_name"],
        "severity": meta["severity"],
        "mitre_attack": [dict(technique) for technique in meta["mitre_attack"]],
    }
