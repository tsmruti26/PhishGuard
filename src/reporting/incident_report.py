"""Security incident report generator.

Structure follows NIST SP 800-61 (detection and analysis, containment/eradication/recovery,
post-incident activity). Techniques are mapped to MITRE ATT&CK. All indicators are defanged.
"""
import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from src.utils.defang import defang_all

SCHEMA_VERSION = "phishguard.incident/1.0"
KINDS = ("qr", "domain")
VERDICTS = ("safe", "suspicious", "malicious")
TLP_LEVELS = ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED")
# Assumes a 0-100 risk score. Adjust to match your scoring engine.
SEVERITY_THRESHOLDS = ((80, "critical"), (60, "high"), (40, "medium"), (0, "low"))
ID_RE = re.compile(r"INC-\d{8}-[0-9A-F]{8}")

VECTOR = {"qr": "QR code phishing (quishing)", "domain": "Look-alike / typosquatted domain"}
TITLE_PREFIX = {"malicious": "Malicious", "suspicious": "Suspicious", "safe": "Reviewed, no threat found:"}

ATTACK = {
    "qr": [
        {"id": "T1566.002", "name": "Phishing: Spearphishing Link", "tactic": "Initial Access"},
        {"id": "T1204.001", "name": "User Execution: Malicious Link", "tactic": "Execution"},
    ],
    "domain": [
        {"id": "T1583.001", "name": "Acquire Infrastructure: Domains", "tactic": "Resource Development"},
        {"id": "T1566.002", "name": "Phishing: Spearphishing Link", "tactic": "Initial Access"},
    ],
}

ACTIONS_BY_FINDING = [
    (("shorten",), "Block the shortened link and its resolved destination at the web proxy and DNS filter."),
    (("ip address", "ip_address", "raw ip"),
     "Block the destination IP at the egress firewall; raw-IP landing pages are rarely legitimate."),
    (("homoglyph", "punycode", "xn--", "unicode"),
     "Add both the Punycode and Unicode forms of the domain to the DNS blocklist."),
]
BASE_ACTIONS = [
    "Preserve the original QR image or URL and the scan output as evidence before any cleanup.",
    "Search proxy, DNS and email logs for other users who contacted the indicators below.",
    "If anyone entered credentials, reset them, revoke active sessions and re-enrol MFA.",
    "Submit the indicators to the registrar or hosting provider for takedown and to your threat-intel platform.",
]
PREVENTIVE = [
    "Run an awareness reminder on scanning unsolicited QR codes.",
    "Enable DNS filtering for newly registered and look-alike domains.",
    "Review browser IDN display policy so Punycode is shown for mixed-script domains.",
]


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean(value, max_len=300):
    text = "".join(ch for ch in str(value) if ch.isprintable()).replace("`", "'")
    return text.strip()[:max_len]


def severity_for(score):
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "low"


def _digest(report):
    body = {k: v for k, v in report.items() if k != "integrity"}
    data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    key = os.environ.get("PHISHGUARD_REPORT_KEY")
    if key:
        return "HMAC-SHA256", hmac.new(key.encode("utf-8"), data, hashlib.sha256).hexdigest()
    return "SHA-256", hashlib.sha256(data).hexdigest()


def verify_report(report):
    algorithm, digest = _digest(report)
    stored = report.get("integrity", {})
    return stored.get("algorithm") == algorithm and hmac.compare_digest(
        str(stored.get("digest", "")), digest)


def build_report(scan, reporter="unassigned", tlp="TLP:AMBER"):
    kind, verdict = scan.get("kind"), scan.get("verdict")
    if kind not in KINDS:
        raise ValueError("kind must be 'qr' or 'domain'")
    if verdict not in VERDICTS:
        raise ValueError("verdict must be safe, suspicious or malicious")
    if tlp not in TLP_LEVELS:
        raise ValueError("invalid TLP level")
    try:
        score = max(0.0, min(100.0, float(scan.get("risk_score", 0))))
    except (TypeError, ValueError):
        raise ValueError("risk_score must be a number")
    target = _clean(scan.get("target", ""))
    if not target:
        raise ValueError("target is required")
    findings_raw = scan.get("findings") or []
    chain_raw = scan.get("redirect_chain") or []
    if not isinstance(findings_raw, list) or not isinstance(chain_raw, list):
        raise ValueError("findings and redirect_chain must be lists")
    findings = [_clean(f, 200) for f in findings_raw][:50]
    chain = [_clean(h, 500) for h in chain_raw][:10]

    now = _now()
    incident_id = f"INC-{datetime.now(timezone.utc):%Y%m%d}-{secrets.token_hex(4).upper()}"
    severity = severity_for(score)

    indicators = [{"type": "url" if kind == "qr" else "domain",
                   "value": defang_all(target), "note": "Scanned target"}]
    for i, hop in enumerate(chain, 1):
        note = "Final destination" if (i == len(chain) and len(chain) > 1) else f"Redirect hop {i}"
        indicators.append({"type": "url", "value": defang_all(hop), "note": note})

    lowered = [f.lower() for f in findings]
    specific = [action for keys, action in ACTIONS_BY_FINDING
                if any(k in f for f in lowered for k in keys)]
    if kind == "domain":
        specific.append("Monitor the domain for new DNS records and TLS certificate issuance.")

    report = {
        "schema": SCHEMA_VERSION,
        "incident": {
            "id": incident_id,
            "title": f"{TITLE_PREFIX[verdict]} {VECTOR[kind].lower()}: {defang_all(target)[:80]}",
            "severity": severity,
            "status": "open",
            "tlp": tlp,
            "detected_at": now,
            "reported_at": now,
            "reporter": _clean(reporter, 80) or "unassigned",
        },
        "classification": {
            "category": "Phishing (suspected credential harvesting)",
            "vector": VECTOR[kind],
            "attack_techniques": ATTACK[kind],
        },
        "detection_and_analysis": {
            "detection_source": "PhishGuard automated scan",
            "verdict": verdict,
            "risk_score": round(score, 1),
            "findings": findings,
            "indicators_defanged": indicators,
        },
        "containment_eradication_recovery": {
            "recommended_actions": specific + BASE_ACTIONS,
            "completed_actions": [],
        },
        "impact_assessment": {
            "affected_users": "To be determined",
            "data_exposure": "To be determined",
            "business_impact": "To be determined",
        },
        "timeline": [
            {"ts": now, "event": "Threat detected by PhishGuard scan"},
            {"ts": now, "event": "Incident report generated"},
        ],
        "post_incident": {"lessons_learned": [], "preventive_measures": PREVENTIVE},
    }
    algorithm, digest = _digest(report)
    report["integrity"] = {"algorithm": algorithm, "digest": digest}
    return report


def _bullets(items, empty="None recorded"):
    return [f"- {x}" for x in items] if items else [f"- {empty}"]


def to_markdown(r):
    inc, cls = r["incident"], r["classification"]
    det = r["detection_and_analysis"]
    ccr, imp, post = r["containment_eradication_recovery"], r["impact_assessment"], r["post_incident"]
    lines = [
        f"# Security Incident Report: {inc['id']}",
        f"**{inc['title']}**",
        "",
        f"> {inc['tlp']}: share only as permitted by this TLP level",
        "",
        "## 1. Incident Summary",
        f"- **Severity:** {inc['severity'].upper()}",
        f"- **Status:** {inc['status']}",
        f"- **Category:** {cls['category']}",
        f"- **Attack vector:** {cls['vector']}",
        f"- **Detected (UTC):** {inc['detected_at']}",
        f"- **Reporter:** {inc['reporter']}",
        "",
        "## 2. Detection and Analysis",
        f"- **Detection source:** {det['detection_source']}",
        f"- **Verdict:** {det['verdict']} (risk score {det['risk_score']}/100)",
        "",
        "### Findings",
        *_bullets(det["findings"]),
        "",
        "### Indicators of Compromise (defanged)",
        *[f"- `{i['value']}` ({i['type']}): {i['note']}" for i in det["indicators_defanged"]],
        "",
        "### MITRE ATT&CK Mapping",
        *[f"- {t['id']}: {t['name']} ({t['tactic']})" for t in cls["attack_techniques"]],
        "",
        "## 3. Containment, Eradication and Recovery",
        "### Recommended actions",
        *[f"- [ ] {a}" for a in ccr["recommended_actions"]],
        "",
        "### Completed actions",
        *_bullets(ccr["completed_actions"]),
        "",
        "## 4. Impact Assessment",
        f"- **Affected users:** {imp['affected_users']}",
        f"- **Data exposure:** {imp['data_exposure']}",
        f"- **Business impact:** {imp['business_impact']}",
        "",
        "## 5. Timeline (UTC)",
        *[f"- {t['ts']}: {t['event']}" for t in r["timeline"]],
        "",
        "## 6. Post-Incident Activity",
        "### Lessons learned",
        *_bullets(post["lessons_learned"], "To be completed after resolution"),
        "",
        "### Preventive measures",
        *_bullets(post["preventive_measures"]),
        "",
        "## 7. Integrity",
        f"- **{r['integrity']['algorithm']}:** `{r['integrity']['digest']}`",
        f"- **Schema:** {r['schema']}",
        "",
    ]
    return "\n".join(lines)


def save_report(report, out_dir="reports"):
    incident_id = report["incident"]["id"]
    if not ID_RE.fullmatch(incident_id):
        raise ValueError("invalid incident id")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path, md_path = out / f"{incident_id}.json", out / f"{incident_id}.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(to_markdown(report), encoding="utf-8")
    return json_path, md_path


def main():
    p = argparse.ArgumentParser(description="Generate a PhishGuard security incident report")
    p.add_argument("--target", required=True)
    p.add_argument("--kind", choices=KINDS, required=True)
    p.add_argument("--risk", type=float, required=True, help="risk score 0-100")
    p.add_argument("--verdict", choices=VERDICTS, required=True)
    p.add_argument("--finding", action="append", default=[], help="repeatable")
    p.add_argument("--chain", action="append", default=[], help="redirect hop, repeatable")
    p.add_argument("--reporter", default="unassigned")
    p.add_argument("--tlp", choices=TLP_LEVELS, default="TLP:AMBER")
    p.add_argument("--out", default="reports")
    p.add_argument("--store", action="store_true", help="also save the scan and incident to the database")
    a = p.parse_args()

    scan = {"target": a.target, "kind": a.kind, "risk_score": a.risk, "verdict": a.verdict,
            "findings": a.finding, "redirect_chain": a.chain}
    report = build_report(scan, reporter=a.reporter, tlp=a.tlp)
    json_path, md_path = save_report(report, a.out)
    print(f"Wrote {json_path} and {md_path}")

    if a.store:
        from src.db import store
        store.init_db()
        scan_id = store.insert_scan(_clean(a.target), a.kind, a.risk, a.verdict, json.dumps(scan))
        inc = report["incident"]
        store.insert_incident(inc["id"], scan_id, inc["title"], inc["severity"], report=report)
        print(f"Stored scan {scan_id} and incident {inc['id']}")


if __name__ == "__main__":
    main()