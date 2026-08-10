"""4-mode email viewer: Rendered / Plain Text / HTML / Source."""

import html
import re
import tkinter as tk
from tkinter import messagebox

from ..sanitizer import sanitize_html
from .theme import COLORS, FONTS
from .widgets import StyledScrolledText


class EmailViewTab(tk.Frame):
    """
    4-mode email viewer:
      - Rendered  : live HTML render via tkhtmlview (falls back to cleaned text)
      - Plain Text: text/plain body
      - HTML      : raw HTML source with syntax tinting
      - Source    : full RFC-5322 raw bytes

    Rendered mode runs the HTML through sanitizer.sanitize_html() before display.
    By default this blocks remote images/stylesheets so opening a phishing sample
    can't silently notify the sender (tracking pixels) — see safe_mode_default.

    tkhtmlview is a pure-Python HTML-in-Tkinter widget (no native/compiled
    parser touching attacker-controlled markup) chosen deliberately over
    webview-style widgets for this reason. It also opens link clicks via
    webbrowser.open() by default — that's rebound below to a confirmation
    dialog so a click inside a phishing sample never silently launches the
    system browser.
    """

    def __init__(self, parent, safe_mode_default=True):
        super().__init__(parent, bg=COLORS["bg_panel"])
        self._body = {}
        self._has_webview = False
        self._webview = None
        self._webview_label = None
        self.safe_mode_default = safe_mode_default
        self._safe_mode = safe_mode_default
        self._blocked_count = 0
        self._build()

    def _try_load_webview(self):
        if self._has_webview or self._webview is not None:
            return
        try:
            from tkhtmlview import HTMLScrolledText   # type: ignore
            frm = HTMLScrolledText(self._render_host, html="")
            frm.pack(fill="both", expand=True)
            self._webview = frm
            self._has_webview = True
        except Exception:
            self._has_webview = False

    def _guard_links(self):
        """Replace tkhtmlview's default click-to-open-browser binding with a
        confirmation dialog that shows the real destination URL first."""
        parser = getattr(self._webview, "html_parser", None)
        for slot in getattr(parser, "hlink_slots", []):
            self._webview.tag_unbind(slot.tag_name, "<Button-1>")
            self._webview.tag_bind(
                slot.tag_name, "<Button-1>",
                lambda e, url=slot.URL: self._on_link_clicked(url),
            )

    def _on_link_clicked(self, url):
        if messagebox.askyesno(
            "Open link?",
            f"This link points to:\n\n{url}\n\n"
            "Opening it will launch your default web browser. If this is a "
            "phishing sample, the destination may be malicious.\n\nContinue?",
            icon="warning",
        ):
            import webbrowser
            webbrowser.open(url)

    @staticmethod
    def _html_to_text(html_src):
        """Strip tags, decode entities, collapse whitespace."""
        import html as html_mod
        text = re.sub(r'<(style|script)[^>]*>.*?</\1>', ' ', html_src,
                      flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<(br|p|div|tr|li|h[1-6])\b[^>]*>', '\n', text,
                      flags=re.IGNORECASE)
        text = re.sub(r'<[^>]+>', '', text)
        text = html_mod.unescape(text)
        text = re.sub(r'\n{3,}', '\n\n', text)
        return text.strip()

    def _build(self):
        top = tk.Frame(self, bg=COLORS["bg_panel"])
        top.pack(fill="x", padx=20, pady=(16, 0))

        tk.Label(top, text="▸ EMAIL CONTENT", font=FONTS["sans_lg"],
                 fg=COLORS["accent"], bg=COLORS["bg_panel"]).pack(side="left")

        strip = tk.Frame(self, bg=COLORS["bg"])
        strip.pack(fill="x", padx=20, pady=(8, 0))

        self.mode = tk.StringVar(value="rendered")

        self._mode_btns = {}
        modes = [
            ("🖥  Rendered",   "rendered"),
            ("📄  Plain Text", "plain"),
            ("</>  HTML",      "html"),
            ("⊞  Source",     "source"),
        ]
        for label, val in modes:
            btn = tk.Button(
                strip,
                text=label,
                font=("Helvetica", 9, "bold"),
                relief="flat",
                padx=14, pady=6,
                cursor="hand2",
                command=lambda v=val: self._switch_mode(v),
            )
            btn.pack(side="left", padx=(0, 2))
            self._mode_btns[val] = btn
        self._highlight_btn("rendered")

        # ── safe-mode banner (only visible in Rendered mode) ────────────────
        self._safe_banner = tk.Frame(self, bg="#fef3c7")
        self._safe_label = tk.Label(
            self._safe_banner, text="", font=FONTS["label"],
            fg=COLORS["warn_yellow"], bg="#fef3c7", anchor="w", padx=10, pady=4,
        )
        self._safe_label.pack(side="left")
        self._safe_btn = tk.Button(
            self._safe_banner, text="Load remote content", font=("Helvetica", 8, "bold"),
            fg=COLORS["bg"], bg=COLORS["warn_yellow"], relief="flat",
            padx=8, pady=2, cursor="hand2", command=self._on_load_remote_clicked,
        )
        self._safe_btn.pack(side="right", padx=8, pady=4)

        tk.Frame(self, bg=COLORS["border"], height=1).pack(fill="x", pady=(8, 0))

        self._content_frame = tk.Frame(self, bg=COLORS["bg_panel"])
        self._content_frame.pack(fill="both", expand=True)

        self._render_outer = tk.Frame(
            self._content_frame,
            bg="#ffffff",
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        self._render_host = tk.Frame(self._render_outer, bg="#ffffff")
        self._render_host.pack(fill="both", expand=True)
        self._render_fallback = StyledScrolledText(
            self._render_outer,
            height=30,
            font=("Helvetica", 10),
        )
        self._render_fallback_visible = False

        self._plain_pane  = StyledScrolledText(self._content_frame, height=30,
                                                font=("Helvetica", 10))
        self._html_pane   = StyledScrolledText(self._content_frame, height=30,
                                                font=FONTS["mono_sm"])
        self._source_pane = StyledScrolledText(self._content_frame, height=30,
                                                font=FONTS["mono_sm"])

        self._html_pane.text.tag_configure("tag",    foreground="#1a56db")
        self._html_pane.text.tag_configure("attr",   foreground="#166534")
        self._html_pane.text.tag_configure("string", foreground="#b45309")
        self._html_pane.text.tag_configure("entity", foreground="#7e22ce")

        self._current_mode = None
        self._switch_mode("rendered")

    def _switch_mode(self, mode):
        if mode == self._current_mode:
            return
        self._current_mode = mode
        self.mode.set(mode)
        self._highlight_btn(mode)

        self._render_outer.pack_forget()
        self._plain_pane.pack_forget()
        self._html_pane.pack_forget()
        self._source_pane.pack_forget()
        self._safe_banner.pack_forget()

        if mode == "rendered":
            self._safe_banner.pack(fill="x", padx=20, pady=(8, 0))
            self._render_outer.pack(fill="both", expand=True,
                                    padx=20, pady=10)
            self._show_rendered()
        elif mode == "plain":
            self._plain_pane.pack(fill="both", expand=True, padx=20, pady=10)
        elif mode == "html":
            self._html_pane.pack(fill="both", expand=True, padx=20, pady=10)
        elif mode == "source":
            self._source_pane.pack(fill="both", expand=True, padx=20, pady=10)

    def _highlight_btn(self, active):
        for key, btn in self._mode_btns.items():
            if key == active:
                btn.configure(
                    fg=COLORS["bg"],
                    bg=COLORS["accent"],
                    activeforeground=COLORS["bg"],
                    activebackground=COLORS["accent"],
                )
            else:
                btn.configure(
                    fg=COLORS["text_dim"],
                    bg=COLORS["bg_hover"],
                    activeforeground=COLORS["text"],
                    activebackground=COLORS["bg_hover"],
                )

    def _on_load_remote_clicked(self):
        if not messagebox.askyesno(
            "Load remote content?",
            "This will fetch images/resources from remote servers referenced in "
            "the email. If this is a phishing sample, doing so can alert the "
            "sender that the email was opened.\n\nContinue anyway?",
            icon="warning",
        ):
            return
        self._safe_mode = False
        self._show_rendered()

    def _update_safe_banner(self):
        if self._safe_mode:
            self._safe_label.configure(
                text=f"🛡 Safe Mode — {self._blocked_count} remote resource(s) blocked"
            )
            self._safe_btn.pack(side="right", padx=8, pady=4)
        else:
            self._safe_label.configure(
                text="⚠ Remote content loading enabled for this email"
            )
            self._safe_btn.pack_forget()

    def _show_rendered(self):
        html_src = self._body.get("html", "")
        plain    = self._body.get("plain", "")

        clean_html, blocked = sanitize_html(html_src, allow_remote=not self._safe_mode)
        self._blocked_count = blocked
        self._update_safe_banner()

        self._try_load_webview()

        if self._has_webview and self._webview is not None:
            if self._render_fallback_visible:
                self._render_fallback.pack_forget()
                self._render_fallback_visible = False
            if self._webview_label is not None:
                self._webview_label.pack_forget()

            if clean_html:
                try:
                    self._webview.set_html(clean_html)
                    self._guard_links()
                    return
                except Exception:
                    pass
            if plain:
                try:
                    normalized = plain.replace("\r\n", "\n").replace("\r", "\n")
                    safe = (
                        "<html><body style='font-family:sans-serif;"
                        "padding:16px;white-space:pre-wrap'>"
                        + html.escape(normalized)
                        + "</body></html>"
                    )
                    self._webview.set_html(safe)
                    self._guard_links()
                    return
                except Exception:
                    pass

        if not self._render_fallback_visible:
            self._webview_label = tk.Label(
                self._render_outer,
                text="  ⚠  Install tkhtmlview for live HTML rendering  "
                     "(pip install tkhtmlview)",
                font=("Helvetica", 8),
                fg="#888888",
                bg="#ffffff",
                anchor="w",
            )
            self._webview_label.pack(fill="x")
            self._render_fallback.pack(fill="both", expand=True)
            self._render_fallback_visible = True
            self._render_fallback.text.configure(
                bg="#ffffff", fg="#1a1a2e",
                font=("Georgia", 11),
            )

        if clean_html:
            readable = self._html_to_text(clean_html)
        elif plain:
            readable = plain
        else:
            readable = "[No email body available]"

        self._render_fallback.set_text(readable)

    def load(self, body):
        self._body = body
        self._safe_mode = self.safe_mode_default

        self._plain_pane.set_text(
            body.get("plain") or "[No plain-text body]"
        )

        html_src = body.get("html", "")
        if html_src:
            self._load_html_highlighted(html_src)
        else:
            self._html_pane.set_text("[No HTML body]")

        source_text = body.get("source") or "[No source available]"
        if body.get("source_note"):
            source_text = f"[{body['source_note']}]\n\n{source_text}"
        self._source_pane.set_text(source_text)

        if self._current_mode == "rendered":
            self._show_rendered()

    def _load_html_highlighted(self, src):
        t = self._html_pane.text
        t.configure(state="normal")
        t.delete("1.0", "end")

        pattern = re.compile(
            r'(<[^>]*>)'
            r'|(&\w+;|&#\d+;)'
            r'|([^<&]+)',
            re.DOTALL,
        )
        attr_pat  = re.compile(r'(\s[\w:-]+)(=)(".*?"|\'.*?\')', re.DOTALL)
        tag_name  = re.compile(r'^</?[\w!]+')

        for m in pattern.finditer(src):
            if m.group(1):
                raw = m.group(1)
                nm = tag_name.match(raw)
                nm_end = nm.end() if nm else 1
                t.insert("end", raw[:nm_end], "tag")
                rest = raw[nm_end:]
                last = 0
                for am in attr_pat.finditer(rest):
                    t.insert("end", rest[last:am.start()], "tag")
                    t.insert("end", am.group(1), "attr")
                    t.insert("end", am.group(2), "tag")
                    t.insert("end", am.group(3), "string")
                    last = am.end()
                t.insert("end", rest[last:], "tag")
            elif m.group(2):
                t.insert("end", m.group(2), "entity")
            elif m.group(3):
                t.insert("end", m.group(3))

        t.configure(state="disabled")
