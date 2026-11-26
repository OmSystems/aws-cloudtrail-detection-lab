from cloudtrail_analyzer.rules import registry


def run_detection(events):
    """
    Run every registered detection rule and combine findings.

    Event-scope findings come first in event order, then batch-scope findings.
    """

    findings = []

    event_rules = [r for r in registry.RULES if r.scope == registry.EVENT]
    batch_rules = [r for r in registry.RULES if r.scope == registry.BATCH]

    for event in events:
        for rule in event_rules:
            finding = rule.func(event)

            if finding is not None:
                findings.append(finding)

    for rule in batch_rules:
        findings.extend(rule.func(events))

    return findings
