from pathlib import Path
from sift.runner import run_scan


def install_hook():
    hook_path = Path(".git/hooks/pre-commit")

    hook_content = """#!/bin/sh
echo "🔍 Running sift pre-commit scan..."
sift scan --staged --fail-threshold 60
STATUS=$?

if [ $STATUS -ne 0 ]; then
  echo ""
  echo "❌ Commit blocked by sift"
  echo "🔒 Potential secrets detected."
  echo ""
  echo "👉 Fix the issues above, or:"
  echo "   - Move secrets to environment variables"
  echo "   - Rotate exposed credentials"
  echo "   - Add false positives to .siftignore"
  echo ""
  exit 1
fi

exit 0
"""

    hook_path.write_text(hook_content, encoding="utf-8")
    hook_path.chmod(0o755)
