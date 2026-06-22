import json
from readiness.assessor import assess
from readiness.report import to_json, render_html


def _result(tmp_path):
    p = tmp_path / "d.csv"
    p.write_text("name,ssn\nA,123-45-6789\n", encoding="utf-8")
    return assess(str(p), standards=["hipaa"])


def test_to_json_roundtrips(tmp_path):
    obj = json.loads(to_json(_result(tmp_path)))
    assert obj["summary"]["verdict"] == "findings" and obj["phi_coverage"]["SSN"] == 1


def test_render_html_is_self_contained_and_escaped(tmp_path):
    html_out = render_html(_result(tmp_path))
    assert html_out.startswith("<!DOCTYPE html>") and "</html>" in html_out
    assert "Data-Protection Readiness" in html_out
    assert "SSN" in html_out  # phi coverage section
    # red-line framing present (scan-assist, not certified)
    assert "scan-assist" in html_out.lower() and "not" in html_out.lower()


def test_render_html_clean_says_no_findings(tmp_path):
    p = tmp_path / "ok.txt"
    p.write_text("nothing here", encoding="utf-8")
    html_out = render_html(assess(str(p), standards=["hipaa"]))
    assert "No findings" in html_out
