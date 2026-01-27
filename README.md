# Sift

**Sift** is an offline, pre-commit secrets detector that scans source code for exposed credentials and sensitive data before they leak into repositories.

## Features

- **Pre-commit Scanning** — Detect secrets before they're committed
- **Offline-First** — No external API calls, full privacy and speed
- **Multi-Layer Detection** — Regex patterns, entropy analysis, and contextual checks
- **Risk Scoring** — Categorize findings by severity
- **Flexible Configuration** — Customize detection rules and thresholds
- **Multiple Report Formats** — JSON and console output
- **Git Integration** — Seamless pre-commit hook installation

## Installation

```bash
pip install sift
```

## Usage

```bash
# Scan all files
sift scan

# Scan only staged files (pre-commit hook)
sift scan --staged

# Install as git pre-commit hook
sift hook-install

# Generate JSON report
sift scan --output report.json
```

## Configuration

Create a `.siftrc.json` or add configuration to your project:

```json
{
  "patterns": ["api_key", "password", "token"],
  "entropy_threshold": 3.5,
  "exclude_paths": [".git", "node_modules"]
}
```

## Contributing

Contributions welcome! Open an issue or submit a pull request.

## License

MIT