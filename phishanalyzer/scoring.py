"""Heuristic triage flags for a parsed email.

This is NOT a malware/phishing verdict engine — it's a checklist of common
red flags surfaced for a human analyst to weigh, matching what an analyst
would eyeball manually across the other tabs. Keep additions here narrow and
explainable; each flag should point at a concrete piece of evidence.
"""

import re

RISKY_ATTACHMENT_EXTS = {
    ".exe", ".scr", ".js", ".vbs", ".vbe", ".wsf", ".jar", ".bat", ".cmd",
    ".ps1", ".hta", ".docm", ".xlsm", ".pptm", ".html", ".htm", ".iso", ".lnk",
}

URGENCY_KEYWORDS = [
    "verify your account", "account suspended", "urgent action required",
    "confirm your identity", "unusual activity", "click here immediately",
    "your account will be", "payment failed", "invoice overdue",
    "reset your password", "security alert", "final notice",
]

_IP_LITERAL_URL_RE = re.compile(r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
_EMAIL_ADDR_RE = re.compile(r'[\w.+-]+@[\w.-]+')


class Flag:
    def __init__(self, severity, label, detail=""):
        self.severity = severity  # "HIGH" | "MEDIUM" | "LOW"
        self.label = label
        self.detail = detail


def _domain_of(addr):
    """addr may be a bare address or a raw "Name <addr>" header value."""
    if not addr:
        return ""
    m = _EMAIL_ADDR_RE.search(addr)
    return m.group(0).split("@")[-1].lower() if m else ""


def evaluate(results):
    flags = []

    auth = results.get("authentication", {})
    details = results.get("details", {})
    body = results.get("body", {})
    urls = results.get("urls", [])
    attachments = results.get("attachments", [])

    if auth.get("spf_pass") in ("FAIL", "SOFTFAIL", "NONE"):
        flags.append(Flag("MEDIUM", "SPF did not pass",
                           f"SPF result: {auth.get('spf_pass')}"))
    if auth.get("dkim_result") in ("FAIL", "NONE"):
        flags.append(Flag("MEDIUM", "DKIM did not pass",
                           f"DKIM result: {auth.get('dkim_result')}"))
    if auth.get("dmarc_pass") in ("FAIL", "NONE"):
        flags.append(Flag("MEDIUM", "DMARC did not pass",
                           f"DMARC result: {auth.get('dmarc_pass')}"))

    from_domain = _domain_of(details.get("sender", ""))
    # return_path_domain in the authentication results is already a bare domain
    return_domain = (auth.get("return_path_domain") or "").lower()
    reply_domain = _domain_of(details.get("reply_to", ""))

    if from_domain and return_domain and from_domain != return_domain:
        flags.append(Flag("MEDIUM", "From domain differs from Return-Path domain",
                           f"From: {from_domain}  vs  Return-Path: {return_domain}"))
    if from_domain and reply_domain and from_domain != reply_domain:
        flags.append(Flag("HIGH", "Reply-To domain differs from From domain",
                           f"From: {from_domain}  vs  Reply-To: {reply_domain}"))

    ip_literal_urls = [u["url"] for u in urls if _IP_LITERAL_URL_RE.match(u["url"])]
    if ip_literal_urls:
        flags.append(Flag("HIGH", "URL(s) point directly at an IP address",
                           ", ".join(ip_literal_urls[:5])))

    risky_atts = [
        a["filename"] for a in attachments
        if any(a["filename"].lower().endswith(ext) for ext in RISKY_ATTACHMENT_EXTS)
    ]
    if risky_atts:
        flags.append(Flag("HIGH", "Attachment(s) with risky extension",
                           ", ".join(risky_atts)))

    combined_text = " ".join([
        details.get("subject", "") or "",
        body.get("plain", "") or "",
    ]).lower()
    hit_keywords = [kw for kw in URGENCY_KEYWORDS if kw in combined_text]
    if hit_keywords:
        flags.append(Flag("LOW", "Urgency/social-engineering phrasing found",
                           ", ".join(hit_keywords[:5])))

    mal_urls = [u["url"] for u in urls if u.get("vt_result") and "MALICIOUS" in str(u["vt_result"])]
    if mal_urls:
        flags.append(Flag("HIGH", "VirusTotal flagged URL(s) as malicious",
                           ", ".join(mal_urls[:5])))

    mal_atts = [
        a["filename"] for a in attachments
        if a.get("vt_result") and "MALICIOUS" in str(a["vt_result"])
    ]
    if mal_atts:
        flags.append(Flag("HIGH", "VirusTotal flagged attachment(s) as malicious",
                           ", ".join(mal_atts)))

    return flags


def overall_verdict(flags):
    if any(f.severity == "HIGH" for f in flags):
        return "HIGH"
    if any(f.severity == "MEDIUM" for f in flags):
        return "MEDIUM"
    if flags:
        return "LOW"
    return "LOW"
