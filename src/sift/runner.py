from pathlib import Path
from sift.reporters.console import print_report



def run_scan(path: str, staged: bool, fail_threshold: int) -> int:
    findings = []

    files = _get_staged_files() if staged else Path(path).rglob("*")

    for file in files:
        if not _is_text_file(file):
            continue

        # detectors will plug in here
        pass

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
