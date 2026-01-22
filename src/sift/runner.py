from pathlib import Path
import fnmatch
import subprocess

from sift.reporters.console import print_report
from sift.detectors.regex import scan_line as regex_scan
from sift.detectors.entropy import scan_line as entropy_scan
from sift.scoring import compute_score, classify_score


# ----------------------------
# Ignore rules
# ----------------------------

IGNORE_DIRS = {
    ".git", "venv", ".venv", "__pycache__",
    "node_modules", "dist", "build",
    ".pytest_cache", "tests", "reporters",".github",
}

IGNORE_FILES = {"SOURCES.txt"}

IGNORE_EXTENSIONS = {
    ".pyc", ".pyo", ".exe", ".dll",
    ".zip", ".tar", ".gz", ".whl",
    ".egg", ".md", ".sarif", ".json",
}


def _should_ignore(path: Path) -> bool:
    for part in path.parts:
        if part in IGNORE_DIRS or part.endswith(".egg-info"):
            return True
    if path.name in IGNORE_FILES:
        return True
    if path.suffix in IGNORE_EXTENSIONS:
        return True
    return False


def _load_siftignore(base_path: Path):
    ignore_file = base_path / ".siftignore"
    if not ignore_file.exists():
        return []

    patterns = []
    with open(ignore_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)

    return patterns


def _matches_siftignore(path: Path, patterns, base_path: Path) -> bool:
    try:
        rel_path = path.relative_to(base_path).as_posix().lstrip("./")
    except ValueError:
        return False

    # exact filename match
    if path.name in patterns:
        return True

    for pattern in patterns:
        # directory pattern
        if pattern.endswith("/") and rel_path.startswith(pattern.rstrip("/")):
            return True

        if fnmatch.fnmatch(rel_path, pattern):
            return True

    return False


# ----------------------------
# Finding merge logic
# ----------------------------

def _merge_finding(findings, key, new_finding):
    if key not in findings:
        findings[key] = new_finding
        findings[key]["detectors"] = {new_finding["rule_id"]}
        return

    existing = findings[key]
    existing["detectors"].add(new_finding["rule_id"])

    # boost score when multiple detectors agree
    existing["score"] = min(existing["score"] + 15, 100)
    existing["classification"] = classify_score(existing["score"])


# ----------------------------
# Git helpers
# ----------------------------

def _get_staged_files():
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        capture_output=True,
        text=True,
    )
    return [Path(p) for p in result.stdout.splitlines()]


# ----------------------------
# Main scan function
# ----------------------------

def run_scan(path: str, staged: bool, fail_threshold: int, return_findings=False):
    findings = {}
    base_path = Path(path).resolve()
    ignore_patterns = _load_siftignore(base_path)

    files = _get_staged_files() if staged else base_path.rglob("*")

    for file in files:
        if not file.is_file():
            continue

        if _should_ignore(file):
            continue

        if _matches_siftignore(file, ignore_patterns, base_path):
            continue

        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                for lineno, line in enumerate(f, start=1):
                    is_config = file.suffix in {".env", ".yaml", ".yml", ".json"}

                    # -------- REGEX DETECTOR --------
                    for match in regex_scan(line):
                        key = (str(file), lineno)
                        score = compute_score(
                            match["score"],
                            in_config_file=is_config,
                        )

                        finding = {
                            "file": str(file),
                            "line": lineno,
                            "score": score,
                            "classification": classify_score(score),
                            "rule_id": match["rule_id"],
                            "description": match["description"],
                        }

                        _merge_finding(findings, key, finding)

                    # -------- ENTROPY DETECTOR --------
                    for match in entropy_scan(line):
                        key = (str(file), lineno)
                        score = compute_score(
                            match["score"],
                            in_config_file=is_config,
                        )

                        finding = {
                            "file": str(file),
                            "line": lineno,
                            "score": score,
                            "classification": classify_score(score),
                            "rule_id": match["rule_id"],
                            "description": match["description"],
                            "entropy": match["entropy"],
                        }

                        _merge_finding(findings, key, finding)

        except Exception:
            continue

    final_findings = list(findings.values())
    print_report(final_findings)

    max_score = max((f["score"] for f in final_findings), default=0)

    if max_score >= fail_threshold:
        print("\n[ERROR] Scan failed: high-risk secrets detected.")
        print("[INFO] Resolve the issues above or add false positives to .siftignore\n")
        exit_code = 1
    else:
        print("\n[OK] Scan passed: no high-risk secrets found.")
        exit_code = 0

    if return_findings:
        return exit_code, final_findings

    return exit_code
