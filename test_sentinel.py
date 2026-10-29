"""Tests for API-Sentinel. Run with: pytest test_sentinel.py -v"""

import json
import threading
import time
import urllib.request
from pathlib import Path

import pytest

import sentinel
import demo_api


CHECKLIST = sentinel.load_checklist()
CHECKS_BY_ID = sentinel.flatten_checks(CHECKLIST)


# --- checklist -----------------------------------------------------------

def test_checklist_loads_and_has_categories():
    assert CHECKLIST["categories"]
    assert any(c["id"] == "BOLA" for c in CHECKLIST["categories"])


def test_flatten_checks_contains_known_ids():
    assert "BOLA-01" in CHECKS_BY_ID
    assert CHECKS_BY_ID["BOLA-01"]["category"] == "Broken Object Level Authorization"


# --- recording -------------------------------------------------------------

def test_record_test_case_appends_record():
    assessment = {"test_cases": []}
    rec = sentinel.record_test_case(
        assessment, "BOLA-01", CHECKS_BY_ID,
        endpoint="GET /orders/{id}",
        expected="403 for another user's order",
        actual="200 with full order body",
        result="fail",
        evidence="curl output: 200 OK",
    )
    assert len(assessment["test_cases"]) == 1
    assert rec["result"] == "fail"
    assert rec["owasp"] == "API1:2023"


def test_record_rejects_unknown_check_id():
    with pytest.raises(ValueError):
        sentinel.record_test_case({}, "NOT-A-REAL-ID", CHECKS_BY_ID, "e", "x", "y", "pass")


def test_record_rejects_invalid_result():
    with pytest.raises(ValueError):
        sentinel.record_test_case({}, "BOLA-01", CHECKS_BY_ID, "e", "x", "y", "maybe")


def test_assessment_round_trip(tmp_path: Path):
    path = tmp_path / "assessment.json"
    assessment = sentinel.load_assessment(path)
    sentinel.record_test_case(assessment, "AUTH-01", CHECKS_BY_ID, "GET /me", "401", "401", "pass")
    sentinel.save_assessment(assessment, path)

    reloaded = sentinel.load_assessment(path)
    assert len(reloaded["test_cases"]) == 1
    assert reloaded["test_cases"][0]["check_id"] == "AUTH-01"


# --- report rendering --------------------------------------------------------

def test_markdown_report_includes_failed_findings():
    assessment = {
        "target": "demo-api",
        "tester": "jatin",
        "created": "2026-01-01T00:00:00Z",
        "test_cases": [],
    }
    sentinel.record_test_case(
        assessment, "BOLA-01", CHECKS_BY_ID, "GET /orders/2",
        expected="403", actual="200 full order body", result="fail", evidence="PoC-1",
    )
    md = sentinel.render_markdown_report(assessment)
    assert "demo-api" in md
    assert "BOLA-01" in md
    assert "## Findings (result = FAIL)" in md
    assert "PoC-1" in md


def test_json_report_round_trips(tmp_path: Path):
    assessment = {"target": "t", "tester": "x", "created": "now", "test_cases": []}
    path = tmp_path / "assessment.json"
    sentinel.save_assessment(assessment, path)
    out = tmp_path / "report.json"
    rc = sentinel.main(["report", "--assessment", str(path), "--format", "json", "--out", str(out)])
    assert rc == 0
    assert json.loads(out.read_text())["target"] == "t"


# --- executable example against the real demo lab API ------------------------

@pytest.fixture(scope="module")
def demo_server():
    srv = demo_api.run(port=0)  # port=0 -> OS picks a free port
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def _get(url: str, token: str | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_demo_api_me_is_correctly_scoped(demo_server):
    status, body = _get(f"{demo_server}/me", token="alice-token")
    assert status == 200
    assert body["username"] == "alice"


def test_demo_api_unauthenticated_requests_are_rejected(demo_server):
    status, _ = _get(f"{demo_server}/orders/1")
    assert status == 401


def test_demo_api_bola_finding_is_reproducible(demo_server):
    """This reproduces the BOLA defect the demo API ships with on purpose:
    bob's token can read alice's order. This is what AUTH-checklist item
    BOLA-01 is designed to catch, and the assessment sample below records
    exactly this as a FAIL."""
    status, body = _get(f"{demo_server}/orders/1", token="bob-token")  # order 1 belongs to alice (user_id 1)
    assert status == 200  # VULNERABLE: should have been 403
    assert body["owner_id"] == 1
    assert body["item"] == "widget"


def test_demo_api_bfla_finding_is_reproducible(demo_server):
    """Any authenticated non-admin can reach /admin/stats — BFLA-01 FAIL case."""
    status, body = _get(f"{demo_server}/admin/stats", token="bob-token")
    assert status == 200  # VULNERABLE: should have been 403 for a non-admin
    assert "total_orders" in body
