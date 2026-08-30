from scanner.rules import XSS_RULES


def test_xss_rules_are_defined():
    assert XSS_RULES


def test_rule_ids_are_unique():
    rule_ids = [rule.rule_id for rule in XSS_RULES]

    assert len(rule_ids) == len(set(rule_ids))


def test_rules_have_required_metadata():
    for rule in XSS_RULES:
        assert rule.rule_id
        assert rule.pattern
        assert rule.description
        assert rule.severity


def test_expected_rule_categories_exist():
    rule_ids = {rule.rule_id for rule in XSS_RULES}

    assert "SCRIPT_TAG" in rule_ids
    assert "EVENT_HANDLER" in rule_ids
    assert "JAVASCRIPT_SCHEME" in rule_ids
    assert "IFRAME_TAG" in rule_ids
    assert "SVG_TAG" in rule_ids
    assert "OBJECT_TAG" in rule_ids
