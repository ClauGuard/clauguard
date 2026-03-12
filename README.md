# clauguard

Universal dependency security scanner. Detects and audits dependencies across all major ecosystems in a single command.

## What it does

- **Vulnerability scanning** — checks all dependencies against [OSV.dev](https://osv.dev) (aggregates GitHub Advisory, NVD, and ecosystem-specific databases)
- **Supply chain integrity** — detects typosquatting, suspicious maintainer changes, and repository injection risks
- **License compliance** — classifies licenses by risk level (copyleft, weak copyleft, permissive, unknown)
- **Outdated dependencies** — flags dependencies with newer versions available

## Supported ecosystems

| Ecosystem | Manifest files |
|-----------|---------------|
| npm | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Composer (PHP) | `composer.json`, `composer.lock` |
| pip (Python) | `requirements.txt`, `Pipfile`, `pyproject.toml`, `poetry.lock` |
| Go | `go.mod`, `go.sum` |
| Cargo (Rust) | `Cargo.toml`, `Cargo.lock` |
| RubyGems | `Gemfile`, `Gemfile.lock` |
| Maven | `pom.xml` |
| Gradle | `build.gradle`, `build.gradle.kts` |
| NuGet (.NET) | `*.csproj`, `packages.config` |
| Swift | `Package.swift` |
| CocoaPods | `Podfile`, `Podfile.lock` |
| Pub (Dart/Flutter) | `pubspec.yaml`, `pubspec.lock` |

## Install

```bash
go install github.com/ClauGuard/clauguard@latest
```

Or build from source:

```bash
git clone https://github.com/ClauGuard/clauguard.git
cd clauguard
go build -o clauguard .
```

## Usage

```bash
# Scan current directory
clauguard

# Scan a specific project
clauguard scan /path/to/project

# JSON output (for CI/CD pipelines)
clauguard -f json

# Include dev dependencies
clauguard --dev

# Skip specific checks
clauguard --skip-vuln
clauguard --skip-license
clauguard --skip-outdated
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No issues found |
| 1 | Non-critical issues (medium/low vulnerabilities) |
| 2 | Critical issues (high/critical vulnerabilities or integrity issues) |

## CI/CD integration

```yaml
# GitHub Actions
- name: Security scan
  run: |
    go install github.com/ClauGuard/clauguard@latest
    clauguard -f json > scan-results.json
```

## License

MIT
