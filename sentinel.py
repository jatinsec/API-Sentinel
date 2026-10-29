#!/usr/bin/env python3
"""
API-Sentinel — a structured API security assessment and evidence organizer.

It does not attack anything itself. It helps a researcher:
  1. work from a reusable OWASP-API-Top-10-based checklist (checklist.json),
  2. record manual test cases (expected vs actual behavior + evidence refs),
  3. generate a Markdown or JSON assessment report from those records.

See README.md for full usage and limitations.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_CHECKLIST = Path(__file__).parent / "checklist.json"


def load_checklist(path: Path = DEFAULT_CHECKLIST) -> dict:
    return json.loads(path.read_text())


def flatten_checks(checklist: dict) -> dict[str, dict]:
    """Map check_id -> check dict (with its category attached)."""
    out = {}
    for cat in checklist["categories"]:
        for check in cat["checks"]:
            out[check["id"]] = {**check, "category": cat["name"], "category_id": cat["id"]}
    return out


def load_assessment(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {"target": None, "tester": None, "created": _now(), "test_cases": []}


def save_assessment(assessment: dict, path: Path) -> None:
    path.write_text(json.dumps(assessment, indent=2, sort_keys=False))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def record_test_case(
    assessment: dict,
    check_id: str,
    checks_by_id: dict,
    endpoint: str,
    expected: str,
    actual: str,
    result: str,
    evidence: str | None = None,
) -> dict:
    """Append one manual test-case record. Returns the record for convenience."""
    if check_id not in checks_by_id:
        raise ValueError(f"Unknown check id: {check_id!r} (see checklist.json for valid ids)")
    if result not in ("pass", "fail", "not_applicable", "blocked"):
        raise ValueError(f"Invalid result: {result!r} (expected pass/fail/not_applicable/blocked)")

    check = checks_by_id[check_id]
    record = {
        "check_id": check_id,
        "check_title": check["title"],
        "category": check["category"],
        "owasp": check.get("owasp"),
        "endpoint": endpoint,
        "expected": expected,
        "actual": actual,
        "result": result,
        "evidence": evidence,
        "recorded_at": _now(),
    }
    assessment.setdefault("test_cases", []).append(record)
    return record


def render_markdown_report(assessment: dict) -> str:
    lines = [
        f"# API Security Assessment — {assessment.get('target') or 'UNNAMED TARGET'}",
        "",
        f"**Tester:** {assessment.get('tester') or 'unspecified'}  ",
        f"**Created:** {assessment.get('created')}  ",
        f"**Test cases recorded:** {len(assessment.get('test_cases', []))}",
        "",
        "> This report records only what was actually tested. A check with no recorded test case",
        "> is not covered by this assessment and is not implied to be secure.",
        "",
        "| Check | Category | OWASP | Endpoint | Result | Evidence |",
        "|---|---|---|---|---|---|",
    ]
    for tc in assessment.get("test_cases", []):
        evidence = (tc.get("evidence") or "").replace("|", "\\|") or "—"
        lines.append(
            f"| {tc['check_id']} — {tc['check_title']} | {tc['category']} | {tc.get('owasp','—')} "
            f"| `{tc['endpoint']}` | **{tc['result'].upper()}** | {evidence} |"
        )

    failed = [tc for tc in assessment.get("test_cases", []) if tc["result"] == "fail"]
    if failed:
        lines += ["", "## Findings (result = FAIL)", ""]
        for tc in failed:
            lines += [
                f"### {tc['check_id']} — {tc['check_title']}",
                f"- **Endpoint:** `{tc['endpoint']}`",
                f"- **Expected:** {tc['expected']}",
                f"- **Actual:** {tc['actual']}",
                f"- **Evidence:** {tc.get('evidence') or 'none recorded'}",
                "",
            ]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description="API security assessment & evidence organizer.")
    sub = p.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list-checks", help="List all checklist items.")
    p_list.add_argument("--checklist", type=Path, default=DEFAULT_CHECKLIST)

    p_rec = sub.add_parser("record", help="Record one manual test case.")
    p_rec.add_argument("--assessment", type=Path, required=True)
    p_rec.add_argument("--checklist", type=Path, default=DEFAULT_CHECKLIST)
    p_rec.add_argument("--check-id", required=True)
    p_rec.add_argument("--endpoint", required=True)
    p_rec.add_argument("--expected", required=True)
    p_rec.add_argument("--actual", required=True)
    p_rec.add_argument("--result", required=True, choices=["pass", "fail", "not_applicable", "blocked"])
    p_rec.add_argument("--evidence", default=None)
    p_rec.add_argument("--target", default=None, help="Set/overwrite the assessment target name.")
    p_rec.add_argument("--tester", default=None)

    p_rep = sub.add_parser("report", help="Render a Markdown or JSON report from an assessment file.")
    p_rep.add_argument("--assessment", type=Path, required=True)
    p_rep.add_argument("--format", choices=["md", "json"], default="md")
    p_rep.add_argument("--out", type=Path, required=True)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "list-checks":
        checklist = load_checklist(args.checklist)
        for cat in checklist["categories"]:
            print(f"\n[{cat['id']}] {cat['name']}")
            for check in cat["checks"]:
                print(f"  {check['id']:14s} {check['title']}  ({check.get('owasp','')})")
        return 0

    if args.command == "record":
        checklist = load_checklist(args.checklist)
        checks_by_id = flatten_checks(checklist)
        assessment = load_assessment(args.assessment)
        if args.target:
            assessment["target"] = args.target
        if args.tester:
            assessment["tester"] = args.tester
        try:
            record = record_test_case(
                assessment, args.check_id, checks_by_id,
                args.endpoint, args.expected, args.actual, args.result, args.evidence,
            )
        except ValueError as e:
            print(f"[!] {e}", file=sys.stderr)
            return 1
        save_assessment(assessment, args.assessment)
        print(f"[+] Recorded {record['check_id']} -> {record['result'].upper()} on {record['endpoint']}")
        return 0

    if args.command == "report":
        assessment = load_assessment(args.assessment)
        if args.format == "md":
            args.out.write_text(render_markdown_report(assessment))
        else:
            args.out.write_text(json.dumps(assessment, indent=2))
        print(f"[+] Wrote {args.format} report to {args.out}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
