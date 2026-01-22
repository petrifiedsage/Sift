import json
from datetime import datetime


def generate_sarif(findings, tool_name="sift", version="0.1.0"):
    sarif = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": version,
                        "informationUri": "https://github.com/yourname/sift",
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }

    rule_index = {}

    for f in findings:
        rule_id = f["rule_id"]

        if rule_id not in rule_index:
            rule_index[rule_id] = len(rule_index)
            sarif["runs"][0]["tool"]["driver"]["rules"].append(
                {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {
                        "text": f.get("description", rule_id)
                    },
                    "defaultConfiguration": {
                        "level": "error" if f["classification"] in {"HIGH", "CRITICAL"} else "warning"
                    }
                }
            )

        sarif["runs"][0]["results"].append(
            {
                "ruleId": rule_id,
                "ruleIndex": rule_index[rule_id],
                "level": "error" if f["classification"] in {"HIGH", "CRITICAL"} else "warning",
                "message": {
                    "text": f"{f['classification']} secret detected"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f["file"]
                            },
                            "region": {
                                "startLine": f["line"]
                            }
                        }
                    }
                ]
            }
        )

    return sarif
