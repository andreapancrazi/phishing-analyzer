# PhishAnalyzer

A desktop tool for analyzing suspicious `.eml` and `.msg` files offline. Built
for triaging phishing reports without forwarding the sample anywhere.

## Features

- Parses RFC-5322 (`.eml`) and Outlook (`.msg`) files
- SPF / DKIM / DMARC and header authentication checks
- Originating IP + reverse DNS, transmission (`Received`) hop trace
- URL and attachment extraction with optional VirusTotal lookups
- Heuristic triage flags (urgency language, mismatched sender domains,
  risky attachment types, IP-literal links, etc.)
- IOC export (CSV/JSON)
- Email viewer with safe-by-default HTML rendering: remote images and
  stylesheets are blocked unless explicitly allowed, so opening a sample
  can't tip off the sender via tracking pixels
- Link clicks require confirmation and show the real destination first

## Install

Requires Python 3.10+.

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```
python main.py
```

Open an `.eml` or `.msg` file from the UI or drag one onto the drop zone.

VirusTotal lookups are optional — add an API key under Settings to enable
URL/attachment scanning.

## Notes

This is a triage aid, not a verdict engine. The heuristic flags point at
evidence worth a human look; they don't classify anything as malicious on
their own.
