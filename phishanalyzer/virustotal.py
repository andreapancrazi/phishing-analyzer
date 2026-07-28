"""VirusTotal API v3 client: URL/hash lookups with rate limiting.

Notes for analysts:
- Attachment hashes are looked up only (GET /files/{sha256}). The attachment
  content itself is never uploaded to VirusTotal, so scanning an attachment
  never sends potentially sensitive data to a third party.
- The free VT API tier allows ~4 requests/minute. All requests go through a
  shared RateLimiter so bulk scans pace themselves instead of hitting 429s.
"""

import base64
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


class RateLimiter:
    """Simple rolling-window limiter: at most `max_calls` per `period` seconds."""

    def __init__(self, max_calls=4, period=60.0):
        self.max_calls = max(1, max_calls)
        self.period = period
        self._calls = []
        self._lock = threading.Lock()

    def update_rate(self, max_calls):
        with self._lock:
            self.max_calls = max(1, max_calls)

    def acquire(self):
        while True:
            with self._lock:
                now = time.monotonic()
                self._calls = [t for t in self._calls if now - t < self.period]
                if len(self._calls) < self.max_calls:
                    self._calls.append(now)
                    return
                wait = self.period - (now - self._calls[0]) + 0.05
            time.sleep(max(wait, 0.05))


class VirusTotalAPI:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key, requests_per_minute=4):
        self.api_key = api_key
        self.rate_limiter = RateLimiter(max_calls=requests_per_minute, period=60.0)

    def set_api_key(self, api_key):
        self.api_key = api_key

    def set_rate(self, requests_per_minute):
        self.rate_limiter.update_rate(requests_per_minute)

    def _get(self, endpoint):
        if not self.api_key:
            return {"error": "No API key configured. Go to Settings > Set VirusTotal API Key"}
        self.rate_limiter.acquire()
        req = urllib.request.Request(
            f"{self.BASE}/{endpoint}",
            headers={"x-apikey": self.api_key}
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"not_found": True}
            return {"error": f"HTTP {e.code}: {e.reason}"}
        except Exception as e:
            return {"error": str(e)}

    def _post(self, endpoint, data, content_type="application/x-www-form-urlencoded"):
        if not self.api_key:
            return {"error": "No API key configured"}
        self.rate_limiter.acquire()
        encoded = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
        req = urllib.request.Request(
            f"{self.BASE}/{endpoint}",
            data=encoded,
            headers={"x-apikey": self.api_key, "Content-Type": content_type},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            return {"error": f"HTTP {e.code}: {body}"}
        except Exception as e:
            return {"error": str(e)}

    def scan_url(self, url, poll_timeout=30, poll_interval=5):
        """Look up a URL, submitting it for analysis if VT hasn't seen it yet."""
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        existing = self._get(f"urls/{url_id}")
        if "error" in existing:
            return existing
        if not existing.get("not_found"):
            return existing

        submitted = self._post("urls", {"url": url})
        if "error" in submitted:
            return submitted
        analysis_id = submitted.get("data", {}).get("id")
        if not analysis_id:
            return {"error": "Submission did not return an analysis id"}

        deadline = time.monotonic() + poll_timeout
        while time.monotonic() < deadline:
            analysis = self._get(f"analyses/{analysis_id}")
            if "error" in analysis:
                return analysis
            status = analysis.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                return analysis
            time.sleep(poll_interval)

        return {"error": "Analysis still pending after timeout — try again shortly"}

    def scan_hash(self, sha256):
        return self._get(f"files/{sha256}")

    @staticmethod
    def _stats_from(data):
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats") or attrs.get("stats")
        return stats

    def parse_url_result(self, data):
        if "error" in data:
            return data["error"]
        if data.get("not_found"):
            return "Not found in VirusTotal (never scanned)"
        stats = self._stats_from(data)
        if not stats:
            return "Result parsing error"
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        total = sum(stats.values())
        verdict = "CLEAN" if mal == 0 and sus == 0 else "MALICIOUS"
        return f"{verdict} — {mal} malicious, {sus} suspicious / {total} engines"

    def parse_file_result(self, data):
        if "error" in data:
            return data["error"]
        if data.get("not_found"):
            return "Unknown to VirusTotal (hash not in database)"
        stats = self._stats_from(data)
        if not stats:
            return "Not found in VT database"
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        total = sum(stats.values())
        verdict = "CLEAN" if mal == 0 and sus == 0 else "MALICIOUS"
        return f"{verdict} — {mal} malicious, {sus} suspicious / {total} engines"
