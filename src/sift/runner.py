from pathlib import Path
from sift.reporters.console import print_report
from sift.detectors.regex import scan_line
from sift.scoring import compute_score, classify_score
from sift.detectors.entropy import scan_line as entropy_scan


IGNORE_DIRS = {
    ".git",
    "venv",
    ".venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".pytest_cache",
}

IGNORE_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".exe",
    ".dll",
    ".zip",
    ".tar",
    ".gz",
}

def _should_ignore(path: Path) -> bool:
    for part in path.parts:
        if part in IGNORE_DIRS:
            return True
    if path.suffix in IGNORE_EXTENSIONS:
        return True
    return False



def run_scan(path: str, staged: bool, fail_threshold: int) -> int:
    findings = []

    files = _get_staged_files() if staged else Path(path).rglob("*")

    for file in files:
        if _should_ignore(file):
            continue
        if not _is_text_file(file):
            continue

        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                for lineno, line in enumerate(f, start=1):
                    matches = scan_line(line)
                    for match in matches:
                        is_config = file.suffix in {".env", ".yaml", ".yml", ".json"}

                        final_score = compute_score(
                            match["score"],
                            in_config_file=is_config,
                        )

                        findings.append(
                            {
                                "file": str(file),
                                "line": lineno,
                                "score": final_score,
                                "classification": classify_score(final_score),
                                "rule_id": match["rule_id"],
                                "description": match["description"],
                            }
                        )

                    # entropy detector
                    entropy_matches = entropy_scan(line)
                    for match in entropy_matches:
                        is_config = file.suffix in {".env", ".yaml", ".yml", ".json"}

                        final_score = compute_score(
                            match["score"],
                            in_config_file=is_config,
                        )

                        findings.append(
                            {
                                "file": str(file),
                                "line": lineno,
                                "score": final_score,
                                "classification": classify_score(final_score),
                                "rule_id": match["rule_id"],
                                "description": match["description"],
                                "entropy": match["entropy"],
                            }
                        )


        except Exception:
            # never crash on unreadable files
            continue

    print_report(findings)

    max_score = max((f["score"] for f in findings), default=0)
    return 1 if max_score >= fail_threshold else 0


def _get_staged_files():
    import subprocess

    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        capture_output=True,
        text=True,
    )
    return [Path(p) for p in result.stdout.splitlines()]


def _is_text_file(path: Path) -> bool:
    return path.is_file() and path.suffix not in {
        ".png", ".jpg", ".jpeg", ".gif",
        ".zip", ".exe", ".pdf"
    }
