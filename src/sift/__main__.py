import sys
import json
import click
from pathlib import Path

from sift.runner import run_scan
from sift.precommit import install_hook
from sift.reporters.sarif_reporter import generate_sarif
from sift.reporters.json_reporter import generate_json_report


@click.group()
def cli():
    """sift — secrets exposure detector"""
    pass


@cli.command()
@click.option(
    "--path",
    default=".",
    type=click.Path(exists=True, file_okay=False),
    help="Path to scan",
)
@click.option(
    "--staged",
    is_flag=True,
    help="Scan only staged git files",
)
@click.option(
    "--fail-threshold",
    default=60,
    type=int,
    help="Fail if risk score >= threshold",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["console", "json", "sarif"]),
    default="console",
    help="Output format",
)
@click.option(
    "--output",
    type=click.Path(),
    help="Output file (for json/sarif)",
)
def scan(path, staged, fail_threshold, output_format, output):
    """
    Scan source code for exposed secrets.
    """
    # run_scan returns (exit_code, findings)
    exit_code, findings = run_scan(
        path=path,
        staged=staged,
        fail_threshold=fail_threshold,
        return_findings=True,
    )

    # ---- Output handling ----
    if output_format == "json":
        report = generate_json_report(findings)
        output_path = output or "sift-report.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    elif output_format == "sarif":
        sarif = generate_sarif(findings)
        output_path = output or "sift.sarif"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)

    # console output is already handled inside runner
    sys.exit(exit_code)


@cli.command("hook-install")
def hook_install():
    """Install git pre-commit hook for sift."""
    install_hook()
    click.echo("[OK] Pre-commit hook installed")


if __name__ == "__main__":
    cli()
