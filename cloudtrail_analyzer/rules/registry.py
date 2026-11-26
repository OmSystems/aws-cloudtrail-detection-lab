"""Rule registry: the engine runs whatever is listed here.

To add a rule: write the detection function, add its metadata in
metadata.py, and append one Rule(...) entry below. engine.py needs no change.
"""
from dataclasses import dataclass
from typing import Callable

from cloudtrail_analyzer.rules.console_login_failures import (
    detect_console_login_failures,
)
from cloudtrail_analyzer.rules.public_ami_sharing import detect_public_ami_sharing
from cloudtrail_analyzer.rules.s3_public_access import detect_public_s3_acl
from cloudtrail_analyzer.rules.security_service_deletion import (
    detect_security_service_deletion,
)

EVENT = "event"
BATCH = "batch"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    scope: str
    func: Callable

    def __post_init__(self):
        if self.scope not in (EVENT, BATCH):
            raise ValueError(f"Unknown rule scope: {self.scope!r}")


# EVENT rules take one event and return a finding dict or None.
# BATCH rules take the full event list and return a list of findings.
RULES = [
    Rule("S3-001", EVENT, detect_public_s3_acl),
    Rule("SEC-001", EVENT, detect_security_service_deletion),
    Rule("EC2-001", EVENT, detect_public_ami_sharing),
    Rule("AUTH-001", BATCH, detect_console_login_failures),
]
