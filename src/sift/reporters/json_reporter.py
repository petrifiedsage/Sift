import json


def write_json(findings, output_file="sift-report.json"):
    with open(output_file, "w") as f:
        json.dump(findings, f, indent=2)

def generate_json_report(findings):
    """
    Generate a JSON-safe report from findings.
    No secret values are included.
    """
    return {
        "summary": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f["classification"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["classification"] == "HIGH"),
            "medium": sum(1 for f in findings if f["classification"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["classification"] == "LOW"),
        },
        "findings": [
            {
                "file": f["file"],
                "line": f["line"],
                "rule_id": f["rule_id"],
                "description": f["description"],
                "score": f["score"],
                "classification": f["classification"],
                "detectors": sorted(list(f.get("detectors", []))),
            }
            for f in findings
        ],
    }
