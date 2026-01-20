import click
from sift.runner import run_scan


@click.group()
def cli():
    """sift — filter secrets before they leak."""
    pass


@cli.command()
@click.option("--path", default=".", help="Path to scan")
@click.option("--staged", is_flag=True, help="Scan only staged git files")
@click.option("--fail-threshold", default=60, help="Fail if score >= threshold")
def scan(path, staged, fail_threshold):
    """Scan files for exposed secrets."""
    exit_code = run_scan(path, staged, fail_threshold)
    raise SystemExit(exit_code)


@cli.command()
def hook_install():
    """Install git pre-commit hook."""
    from sift.precommit import install_hook
    install_hook()
    click.echo("✅ Pre-commit hook installed")


if __name__ == "__main__":
    cli()
