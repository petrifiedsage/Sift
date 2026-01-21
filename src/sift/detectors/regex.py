import re
from typing import List, Dict

# ---- Regex rules ----
# Each rule has: id, description, pattern, base_score
REGEX_RULES = [
    {
        "id": "aws-access-key",
        "description": "AWS Access Key ID",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "score": 80,
    },
    {
        "id": "generic-api-key",
        "description": "Generic API key",
        "pattern": r"(?i)(api[_-]?key|secret|token)[\"' ]*[:=][\"' ]*[A-Za-z0-9_\-]{16,}",
        "score": 70,
    },
    {
        "id": "password-assignment",
        "description": "Hardcoded password",
        "pattern": r"(?i)(password|passwd|pwd)[\"' ]*[:=][\"' ]*.+",
        "score": 65,
    },
]


def scan_line(line: str) -> List[Dict]:
    """Scan a single line for regex-based secrets."""
    findings = []

    for rule in REGEX_RULES:
        if re.search(rule["pattern"], line):
            findings.append(
                {
                    "rule_id": rule["id"],
                    "description": rule["description"],
                    "score": rule["score"],
                }
            )

    return findings
