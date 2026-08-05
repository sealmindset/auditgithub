#!/usr/bin/env python3
"""Export OSS dependency and vulnerability data from Syft/Grype JSON to CSV."""

import argparse
import csv
import json
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

DEPS_COLUMNS = [
    "repository", "package_name", "version", "type",
    "package_manager", "license", "purl",
]

VULNS_COLUMNS = [
    "repository", "package_name", "version", "type",
    "license", "purl", "vuln_id", "severity",
    "description", "fixed_version", "cvss_score", "data_source",
]


def parse_syft_json(path: Path, repo_name: str) -> list[dict]:
    """Parse a Syft SBOM JSON (CycloneDX or native) into dependency rows."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Skipping {path}: {e}")
        return []

    artifacts = data.get("artifacts", [])
    is_cyclonedx = False
    if not artifacts:
        artifacts = data.get("components", [])
        is_cyclonedx = True

    rows = []
    for art in artifacts:
        if is_cyclonedx:
            name = art.get("name", "")
            version = art.get("version", "")
            type_ = art.get("type", "")
            package_manager = ""
            properties = art.get("properties", [])
            for prop in properties:
                if prop.get("name") == "syft:package:type":
                    package_manager = prop.get("value", "")
                    break

            licenses = []
            for lic in art.get("licenses", []):
                if "license" in lic:
                    licenses.append(lic["license"].get("id") or lic["license"].get("name") or "")
                elif "expression" in lic:
                    licenses.append(lic["expression"])
            license_str = ", ".join(filter(None, licenses))
            purl = art.get("purl", "")
        else:
            name = art.get("name", "")
            version = art.get("version", "")
            type_ = art.get("type", "")
            package_manager = art.get("foundBy", "")
            raw_licenses = art.get("licenses", [])
            if isinstance(raw_licenses, list):
                license_str = ", ".join(str(l) for l in raw_licenses if l)
            else:
                license_str = str(raw_licenses)
            purl = art.get("purl", "")

        rows.append({
            "repository": repo_name,
            "package_name": name,
            "version": version,
            "type": type_ or package_manager,
            "package_manager": package_manager or type_,
            "license": license_str,
            "purl": purl,
        })

    return rows


def parse_grype_json(path: Path, repo_name: str) -> list[dict]:
    """Parse a Grype vulnerability JSON into vulnerability rows."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Skipping {path}: {e}")
        return []

    rows = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        licenses = artifact.get("licenses", [])
        if isinstance(licenses, list):
            license_str = ", ".join(str(l) for l in licenses if l)
        else:
            license_str = str(licenses)

        fix = vuln.get("fix", {})
        fix_versions = fix.get("versions", []) if isinstance(fix, dict) else []
        fixed_version = ", ".join(str(v) for v in fix_versions) if fix_versions else ""

        cvss_list = vuln.get("cvss", [])
        cvss_score = ""
        if cvss_list and isinstance(cvss_list, list):
            metrics = cvss_list[0].get("metrics", {})
            if isinstance(metrics, dict):
                cvss_score = metrics.get("baseScore", "")

        rows.append({
            "repository": repo_name,
            "package_name": artifact.get("name", ""),
            "version": artifact.get("version", ""),
            "type": artifact.get("type", ""),
            "license": license_str,
            "purl": artifact.get("purl", ""),
            "vuln_id": vuln.get("id", ""),
            "severity": vuln.get("severity", ""),
            "description": vuln.get("description", ""),
            "fixed_version": fixed_version,
            "cvss_score": str(cvss_score),
            "data_source": vuln.get("dataSource", ""),
        })

    return rows


def discover_repos(report_dir: Path, repo_filter: set[str] | None = None) -> list[tuple[str, Path]]:
    """Find repo directories in the report dir that have Syft or Grype output."""
    repos = []
    for entry in sorted(report_dir.iterdir()):
        if not entry.is_dir():
            continue
        if repo_filter and entry.name not in repo_filter:
            continue
        repos.append((entry.name, entry))
    return repos


def export_dependencies_csv(repos: list[tuple[str, Path]], output_path: Path) -> int:
    """Export dependencies CSV from Syft SBOM files. Returns row count."""
    total = 0
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=DEPS_COLUMNS)
        writer.writeheader()
        for repo_name, repo_dir in repos:
            syft_path = repo_dir / f"{repo_name}_syft_repo.json"
            if not syft_path.exists():
                syft_path = repo_dir / f"{repo_name}_syft_image.json"
            if not syft_path.exists():
                continue
            rows = parse_syft_json(syft_path, repo_name)
            writer.writerows(rows)
            total += len(rows)
    return total


def export_vulnerabilities_csv(repos: list[tuple[str, Path]], output_path: Path) -> int:
    """Export vulnerabilities CSV from Grype files. Returns row count."""
    total = 0
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=VULNS_COLUMNS)
        writer.writeheader()
        for repo_name, repo_dir in repos:
            grype_path = repo_dir / f"{repo_name}_grype_repo.json"
            if not grype_path.exists():
                grype_path = repo_dir / f"{repo_name}_grype_image.json"
            if not grype_path.exists():
                continue
            rows = parse_grype_json(grype_path, repo_name)
            writer.writerows(rows)
            total += len(rows)
    return total


def export_oss_reports(
    report_dir: Path,
    output_dir: Path,
    deps_file: str = "oss_dependencies.csv",
    vulns_file: str = "oss_vulnerabilities.csv",
    repo_filter: set[str] | None = None,
) -> tuple[Path, Path, int, int]:
    """Main export function. Returns (deps_path, vulns_path, deps_count, vulns_count)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    repos = discover_repos(report_dir, repo_filter)
    logger.info(f"Found {len(repos)} repo directories to process")

    deps_path = output_dir / deps_file
    vulns_path = output_dir / vulns_file

    deps_count = export_dependencies_csv(repos, deps_path)
    logger.info(f"Wrote {deps_count} dependencies to {deps_path}")

    vulns_count = export_vulnerabilities_csv(repos, vulns_path)
    logger.info(f"Wrote {vulns_count} vulnerabilities to {vulns_path}")

    return deps_path, vulns_path, deps_count, vulns_count


def main():
    parser = argparse.ArgumentParser(
        description="Export OSS dependency and vulnerability data to CSV"
    )
    parser.add_argument(
        "--report-dir", type=str, default="vulnerability_reports",
        help="Directory containing scan output (default: vulnerability_reports/)",
    )
    parser.add_argument(
        "--output-dir", type=str, default="exports/csv",
        help="Output directory for CSVs (default: exports/csv/)",
    )
    parser.add_argument(
        "--repos", type=str, default=None,
        help="Comma-separated list of repo names to include (default: all)",
    )
    parser.add_argument(
        "--deps-file", type=str, default="oss_dependencies.csv",
        help="Filename for dependencies CSV (default: oss_dependencies.csv)",
    )
    parser.add_argument(
        "--vulns-file", type=str, default="oss_vulnerabilities.csv",
        help="Filename for vulnerabilities CSV (default: oss_vulnerabilities.csv)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    report_dir = Path(args.report_dir)
    if not report_dir.is_dir():
        logger.error(f"Report directory not found: {report_dir}")
        sys.exit(1)

    repo_filter = None
    if args.repos:
        repo_filter = set(r.strip() for r in args.repos.split(","))

    deps_path, vulns_path, deps_count, vulns_count = export_oss_reports(
        report_dir=report_dir,
        output_dir=Path(args.output_dir),
        deps_file=args.deps_file,
        vulns_file=args.vulns_file,
        repo_filter=repo_filter,
    )

    print(f"\nOSS Export Complete:")
    print(f"  Dependencies: {deps_count:,} rows → {deps_path}")
    print(f"  Vulnerabilities: {vulns_count:,} rows → {vulns_path}")


if __name__ == "__main__":
    main()
