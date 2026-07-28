"""Collect indicators of compromise from parsed results and export them."""

import csv
import json


def collect_iocs(results):
    iocs = []
    details = results.get("details", {})
    auth = results.get("authentication", {})

    if details.get("sender"):
        iocs.append({"type": "email_address", "value": details["sender"], "context": "From"})
    if details.get("originating_ip"):
        iocs.append({
            "type": "ip", "value": details["originating_ip"],
            "context": f"Originating IP (rDNS: {details.get('rdns', '')})",
        })
    if auth.get("from_domain"):
        iocs.append({"type": "domain", "value": auth["from_domain"], "context": "From domain"})
    if auth.get("return_path_domain"):
        iocs.append({
            "type": "domain", "value": auth["return_path_domain"],
            "context": "Return-Path domain",
        })
    if details.get("reply_to"):
        iocs.append({"type": "email_address", "value": details["reply_to"], "context": "Reply-To"})

    for u in results.get("urls", []):
        iocs.append({
            "type": "url", "value": u["url"],
            "context": u.get("vt_result") or "not scanned",
        })

    for a in results.get("attachments", []):
        iocs.append({
            "type": "sha256", "value": a["sha256"],
            "context": f"{a['filename']} ({a.get('vt_result') or 'not scanned'})",
        })
        iocs.append({"type": "md5", "value": a["md5"], "context": a["filename"]})

    return iocs


def export_csv(path, iocs):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["type", "value", "context"])
        writer.writeheader()
        writer.writerows(iocs)


def export_json(path, iocs):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(iocs, f, indent=2)
