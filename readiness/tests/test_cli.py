from readiness.__main__ import main


def test_cli_findings_writes_html_and_exits_1(tmp_path):
    p = tmp_path / "d.csv"
    p.write_text("name,ssn\nA,123-45-6789\n", encoding="utf-8")
    out = tmp_path / "report.html"
    rc = main([str(p), "--standards", "hipaa", "--html-out", str(out)])
    assert rc == 1  # findings present
    body = out.read_text(encoding="utf-8")
    assert "Data-Protection Readiness" in body and "SSN" in body


def test_cli_clean_exits_0(tmp_path, capsys):
    p = tmp_path / "ok.txt"
    p.write_text("nothing here", encoding="utf-8")
    assert main([str(p), "--standards", "hipaa", "--json"]) == 0


def test_cli_missing_target_exits_2(tmp_path):
    assert main([str(tmp_path / "nope.csv"), "--standards", "hipaa"]) == 2
