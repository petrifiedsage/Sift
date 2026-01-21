from pathlib import Path
from sift.reporters.console import print_report
from sift.detectors.regex import scan_line as regex_scan
from sift.detectors.entropy import scan_line as entropy_scan
from sift.scoring import compute_score, classify_score
import fnmatch


# ignore rules (already discussed)
IGNORE_DIRS = {
    ".git", "venv", ".venv", "__pycache__",
    "node_modules", "dist", "build",
    ".pytest_cache",
}

IGNORE_FILES = {"SOURCES.txt"}

IGNORE_EXTENSIONS = {
    ".pyc", ".pyo", ".exe", ".dll",
    ".zip", ".tar", ".gz", ".whl",
    ".egg", ".md",
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

def _matches_siftignore(path: Path, patterns, base_path: Path) -> bool:
    try:
        rel_path = path.relative_to(base_path).as_posix()
    except ValueError:
        return False

    for pattern in patterns:
        # directory pattern
        if pattern.endswith("/") and rel_path.startswith(pattern.rstrip("/")):
            return True

        if fnmatch.fnmatch(rel_path, pattern):
            return True

    return False



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


def run_scan(path: str, staged: bool, fail_threshold: int) -> int:
    findings = {}  # key: (file, line)

    files = _get_staged_files() if staged else Path(path).rglob("*")

    for file in files:
        if _should_ignore(file) or not file.is_file():
            continue

        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                for lineno, line in enumerate(f, start=1):

                    is_config = file.suffix in {".env", ".yaml", ".yml", ".json"}

                    # =========================
                    # 🔍 REGEX DETECTOR (HERE)
                    # =========================
                    regex_matches = regex_scan(line)
                    for match in regex_matches:
                        key = (str(file), lineno)

                        final_score = compute_score(
                            match["score"],
                            in_config_file=is_config,
                        )

                        finding = {
                            "file": str(file),
                            "line": lineno,
                            "score": final_score,
                            "classification": classify_score(final_score),
                            "rule_id": match["rule_id"],
                            "description": match["description"],
                        }

                        _merge_finding(findings, key, finding)

                    # =========================
                    # 🧠 ENTROPY DETECTOR (HERE)
                    # =========================
                    entropy_matches = entropy_scan(line)
                    for match in entropy_matches:
                        key = (str(file), lineno)

                        final_score = compute_score(
                            match["score"],
                            in_config_file=is_config,
                        )

                        finding = {
                            "file": str(file),
                            "line": lineno,
                            "score": final_score,
                            "classification": classify_score(final_score),
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
