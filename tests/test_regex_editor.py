from sift.detectors.regex import scan_line


def test_detects_aws_key():
    line = "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
    findings = scan_line(line)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "aws-access-key"


def test_detects_password_assignment():
    line = "password = supersecret123"
    findings = scan_line(line)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "password-assignment"


def test_no_false_positive_on_normal_line():
    line = "username = admin"
    findings = scan_line(line)

    assert findings == []
