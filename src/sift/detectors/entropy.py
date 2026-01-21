import math
import re
from typing import List, Dict


MIN_TOKEN_LENGTH = 16
ENTROPY_THRESHOLD = 3.8


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0

    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1

    entropy = 0.0
    length = len(s)

    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def extract_candidate_tokens(line: str) -> List[str]:
    """
    Extract possible secret-like tokens from a line.
    """
    # Split on whitespace and common delimiters
    tokens = re.split(r"[ \t\n\r\"'=,:(){}[\]]+", line)
    return [
        t for t in tokens
        if len(t) >= MIN_TOKEN_LENGTH and t.isprintable()
    ]


def scan_line(line: str) -> List[Dict]:
    findings = []

    tokens = extract_candidate_tokens(line)

    for token in tokens:
        entropy = shannon_entropy(token)
        if entropy >= ENTROPY_THRESHOLD:
            findings.append(
                {
                    "rule_id": "high-entropy-string",
                    "description": "High entropy string (possible secret)",
                    "score": 55,
                    "entropy": round(entropy, 2),
                }
            )

    return findings
