import json

from src.reporting.incident_report import build_report, to_markdown, verify_report
from src.utils.defang import defang_all

SCAN = {
    "target": "http://xn--gogle-kva.com/login?next=http://x.test",
    "kind": "qr",
    "risk_score": 88,
    "verdict": "malicious",
    "findings": ["Punycode homoglyph detected", "URL shortener used"],
    "redirect_chain": ["https://bit.ly/abc", "http://xn--gogle-kva.com"],
}


def test_severity_and_defanging():
    report = build_report(SCAN)
    assert report["incident"]["severity"] == "critical"
    blob = json.dumps(report) + to_markdown(report)
    assert "http://" not in blob and "https://" not in blob


def test_attack_mapping_and_actions():
    report = build_report(SCAN)
    ids = [t["id"] for t in report["classification"]["attack_techniques"]]
    assert "T1566.002" in ids
    actions = " ".join(report["containment_eradication_recovery"]["recommended_actions"])
    assert "Punycode" in actions and "shortened" in actions


def test_integrity_detects_tampering():
    report = build_report(SCAN)
    assert verify_report(report)
    report["incident"]["severity"] = "low"
    assert not verify_report(report)


def test_defang_all():
    assert defang_all("http://a.com/?r=http://b.com") == "hxxp://a[.]com/?r=hxxp://b[.]com"