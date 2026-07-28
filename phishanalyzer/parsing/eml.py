"""RFC-5322 (.eml) email parsing."""

import re
import socket
import hashlib
import ipaddress
from email import policy
from email.parser import BytesParser

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


class EmailAnalyzer:
    def __init__(self, raw_bytes, source_note=""):
        self.raw_bytes = raw_bytes
        self.source_note = source_note
        self.msg = BytesParser(policy=policy.compat32).parsebytes(raw_bytes)
        self.results = {}
        self._parse_all()

    def _decode_header(self, header_val):
        if not header_val:
            return ""
        try:
            from email.header import decode_header
            parts = decode_header(str(header_val))
            result = []
            for part, charset in parts:
                if isinstance(part, bytes):
                    try:
                        result.append(part.decode(charset or "utf-8", errors="replace"))
                    except Exception:
                        result.append(part.decode("latin-1", errors="replace"))
                else:
                    result.append(str(part))
            return " ".join(result)
        except Exception:
            return str(header_val)

    def _get_header(self, name):
        val = self.msg.get(name)
        if val:
            return self._decode_header(val)
        return ""

    def _parse_all(self):
        self._parse_details()
        self._parse_authentication()
        self._parse_urls()
        self._parse_attachments()
        self._parse_transmission()
        self._parse_xheaders()
        self._parse_body()

    def _parse_details(self):
        from_raw = self._get_header("From")
        display_name, sender_addr = self._split_address(from_raw)

        to_raw = self._get_header("To")
        cc_raw = self._get_header("Cc")

        self.results["details"] = {
            "from_raw": from_raw,
            "display_name": display_name,
            "sender": sender_addr,
            "to": to_raw,
            "cc": cc_raw,
            "subject": self._get_header("Subject"),
            "in_reply_to": self._get_header("In-Reply-To"),
            "timestamp": self._get_header("Date"),
            "reply_to": self._get_header("Reply-To"),
            "message_id": self._get_header("Message-ID"),
            "return_path": self._get_header("Return-Path"),
            "originating_ip": self._extract_originating_ip(),
            "rdns": self._rdns_lookup(self._extract_originating_ip()),
        }

    def _split_address(self, raw):
        if not raw:
            return "", ""
        raw = raw.strip()
        match = re.match(r'^"?([^"<]*)"?\s*<([^>]*)>\s*$', raw)
        if match:
            name = match.group(1).strip().strip('"')
            addr = match.group(2).strip()
            return name, addr
        # No angle brackets — the whole value is the address itself.
        return "", raw.strip('"')

    def _extract_originating_ip(self):
        received_headers = self.msg.get_all("Received") or []
        for hdr in reversed(received_headers):
            ip_match = re.search(
                r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', str(hdr)
            )
            if ip_match:
                ip = ip_match.group(1)
                try:
                    addr = ipaddress.ip_address(ip)
                    if not addr.is_private and not addr.is_loopback:
                        return ip
                except Exception:
                    pass
        # Fallback: first IP found
        for hdr in self.msg.get_all("Received") or []:
            ip_match = re.search(
                r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', str(hdr)
            )
            if ip_match:
                return ip_match.group(1)
        return ""

    def _rdns_lookup(self, ip):
        if not ip:
            return ""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "N/A"

    def _parse_authentication(self):
        auth_results = self._get_header("Authentication-Results")
        received_spf = self._get_header("Received-SPF")
        dkim_sig = self._get_header("DKIM-Signature")

        spf_pass = self._extract_spf_result(auth_results, received_spf)
        dkim_result = self._extract_dkim_result(auth_results)
        dmarc_result = self._extract_dmarc_result(auth_results)

        from_raw = self._get_header("From")
        _, sender = self._split_address(from_raw)
        from_domain = sender.split("@")[-1] if "@" in sender else ""

        return_path = self._get_header("Return-Path").strip("<>")
        return_domain = return_path.split("@")[-1] if "@" in return_path else ""
        orig_ip = self._extract_originating_ip()

        dkim_info = self._parse_dkim_signature(dkim_sig)

        self.results["authentication"] = {
            "spf_pass": spf_pass,
            "originating_ip": orig_ip,
            "rdns": self._rdns_lookup(orig_ip),
            "return_path_domain": return_domain,
            "spf_record": self._lookup_spf(from_domain),
            "dkim_result": dkim_result,
            "dkim_signatures": [dkim_info] if dkim_sig else [],
            "dmarc_pass": dmarc_result,
            "from_domain": from_domain,
            "dmarc_record": self._lookup_dmarc(from_domain),
            "auth_results_raw": auth_results,
        }

    def _extract_spf_result(self, auth_results, received_spf):
        for text in [auth_results, received_spf]:
            if not text:
                continue
            text_lower = text.lower()
            if "spf=pass" in text_lower:
                return "PASS"
            elif "spf=fail" in text_lower:
                return "FAIL"
            elif "spf=softfail" in text_lower:
                return "SOFTFAIL"
            elif "spf=neutral" in text_lower:
                return "NEUTRAL"
            elif "spf=none" in text_lower:
                return "NONE"
        if received_spf:
            if "pass" in received_spf.lower():
                return "PASS"
        return "UNKNOWN"

    def _extract_dkim_result(self, auth_results):
        if not auth_results:
            return "UNKNOWN"
        ar_lower = auth_results.lower()
        if "dkim=pass" in ar_lower:
            return "PASS"
        elif "dkim=fail" in ar_lower:
            return "FAIL"
        elif "dkim=none" in ar_lower:
            return "NONE"
        return "UNKNOWN"

    def _extract_dmarc_result(self, auth_results):
        if not auth_results:
            return "UNKNOWN"
        ar_lower = auth_results.lower()
        if "dmarc=pass" in ar_lower:
            return "PASS"
        elif "dmarc=fail" in ar_lower:
            return "FAIL"
        elif "dmarc=none" in ar_lower:
            return "NONE"
        return "UNKNOWN"

    def _parse_dkim_signature(self, dkim_sig):
        if not dkim_sig:
            return {}
        info = {}
        fields = {
            "s": "selector",
            "d": "signing_domain",
            "a": "algorithm",
            "v": "verification",
        }
        for key, label in fields.items():
            match = re.search(rf'\b{key}=([^;]+)', str(dkim_sig))
            if match:
                info[label] = match.group(1).strip()
        return info

    def _lookup_spf(self, domain):
        if not domain:
            return ""
        if HAS_DNS:
            try:
                answers = dns.resolver.resolve(domain, "TXT")
                for r in answers:
                    txt = r.to_text().strip('"')
                    if txt.startswith("v=spf1"):
                        return txt
            except Exception:
                pass
        return "(DNS lookup unavailable)"

    def _lookup_dmarc(self, domain):
        if not domain:
            return ""
        if HAS_DNS:
            try:
                answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
                for r in answers:
                    txt = r.to_text().strip('"')
                    if "v=DMARC1" in txt:
                        return txt
            except Exception:
                pass
        return "(DNS lookup unavailable)"

    def _parse_urls(self):
        body_text = self._get_all_body_text()
        url_pattern = re.compile(
            r'https?://[^\s<>"\')\]]+|'
            r'www\.[^\s<>"\')\]]+'
        )
        urls = list(set(url_pattern.findall(body_text)))
        self.results["urls"] = [{"url": u, "vt_result": None} for u in urls]

    def _get_all_body_text(self):
        texts = []
        if self.msg.is_multipart():
            for part in self.msg.walk():
                ct = part.get_content_type()
                if ct in ("text/plain", "text/html"):
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        texts.append(payload.decode(charset, errors="replace"))
                    except Exception:
                        pass
        else:
            try:
                payload = self.msg.get_payload(decode=True)
                if payload:
                    charset = self.msg.get_content_charset() or "utf-8"
                    texts.append(payload.decode(charset, errors="replace"))
            except Exception:
                pass
        return "\n".join(texts)

    def _parse_attachments(self):
        attachments = []
        for part in self.msg.walk():
            cd = part.get("Content-Disposition", "")
            if "attachment" in cd or "inline" in cd:
                filename = part.get_filename() or "unnamed"
                payload = part.get_payload(decode=True)
                if payload:
                    md5 = hashlib.md5(payload).hexdigest()
                    sha256 = hashlib.sha256(payload).hexdigest()
                    attachments.append({
                        "filename": filename,
                        "size": len(payload),
                        "md5": md5,
                        "sha256": sha256,
                        "content_type": part.get_content_type(),
                        "vt_result": None,
                        "data": payload,
                    })
        self.results["attachments"] = attachments

    def _parse_transmission(self):
        received = self.msg.get_all("Received") or []
        hops = []
        for i, hdr in enumerate(reversed(received)):
            hdr_str = str(hdr)
            # Extract timestamp
            ts_match = re.search(
                r';\s*(.+?)(?:\n|$)', hdr_str, re.DOTALL
            )
            timestamp = ts_match.group(1).strip() if ts_match else ""
            # Extract server info
            by_match = re.search(r'by\s+([^\s]+)', hdr_str)
            from_match = re.search(r'from\s+([^\s]+)', hdr_str)
            hops.append({
                "hop": i + 1,
                "raw": hdr_str.strip(),
                "from": from_match.group(1) if from_match else "",
                "by": by_match.group(1) if by_match else "",
                "timestamp": timestamp,
            })
        self.results["transmission"] = hops

    def _parse_xheaders(self):
        x_headers_list = [
            "X-TNET-ASAV", "X-Auth-ID", "X-Type", "X-Client-IP",
            "X-Mailer", "X-Classification-ID", "X-TNETIN-SenderInfo",
            "X-VadeSecIn-SpamState", "X-VadeSecIn-SpamScore",
            "X-VadeSecIn-SpamCause", "X-TNETIN-Information",
            "X-TNETIN-MsgID", "X-TNETIN-SpamCheck", "X-TNETIN-From",
            "X-Spam-Status",
        ]
        x_headers = {}
        for h in x_headers_list:
            val = self._get_header(h)
            if val:
                x_headers[h] = val
        # Also grab any other X- headers
        for key in self.msg.keys():
            if key.lower().startswith("x-") and key not in x_headers:
                x_headers[key] = self._get_header(key)
        self.results["xheaders"] = x_headers

    def _parse_body(self):
        plain = ""
        html_body = ""
        source = self.raw_bytes.decode("utf-8", errors="replace")

        if self.msg.is_multipart():
            for part in self.msg.walk():
                ct = part.get_content_type()
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        text = payload.decode(charset, errors="replace")
                        if ct == "text/plain" and not plain:
                            plain = text
                        elif ct == "text/html" and not html_body:
                            html_body = text
                except Exception:
                    pass
        else:
            try:
                payload = self.msg.get_payload(decode=True)
                if payload:
                    charset = self.msg.get_content_charset() or "utf-8"
                    text = payload.decode(charset, errors="replace")
                    ct = self.msg.get_content_type()
                    if ct == "text/html":
                        html_body = text
                    else:
                        plain = text
            except Exception:
                pass

        self.results["body"] = {
            "plain": plain,
            "html": html_body,
            "source": source,
            "source_note": self.source_note,
        }
