"""Details, Authentication, URLs, Attachments, Transmission, and X-Headers tabs."""

import threading
import tkinter as tk
from tkinter import ttk

from .theme import COLORS, FONTS
from .widgets import StyledScrolledText, InfoCard, StatusBadge


class DetailsTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=COLORS["bg_panel"])
        self._build()

    def _build(self):
        canvas = tk.Canvas(self, bg=COLORS["bg_panel"], highlightthickness=0)
        scrollbar = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.scrollable_frame = tk.Frame(canvas, bg=COLORS["bg_panel"])
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        self.canvas = canvas
        self._labels = {}

        hdr = tk.Frame(self.scrollable_frame, bg=COLORS["bg_panel"])
        hdr.pack(fill="x", padx=20, pady=(20, 8))
        tk.Label(hdr, text="▸ EMAIL DETAILS", font=FONTS["sans_lg"],
                 fg=COLORS["accent"], bg=COLORS["bg_panel"]).pack(side="left")

        card = InfoCard(self.scrollable_frame)
        card.pack(fill="x", padx=20, pady=8)

        rows = [
            ("From (Raw)", "from_raw"),
            ("Display Name", "display_name"),
            ("Sender Address", "sender"),
            ("To", "to"),
            ("Cc", "cc"),
            ("Subject", "subject"),
            ("In Reply To", "in_reply_to"),
            ("Timestamp", "timestamp"),
            ("Reply-To", "reply_to"),
            ("Message-ID", "message_id"),
            ("Return-Path", "return_path"),
            ("Originating IP", "originating_ip"),
            ("rDNS", "rdns"),
        ]
        for label, key in rows:
            lbl_widget = card.add_row(label, "")
            self._labels[key] = lbl_widget

    def load(self, data):
        for key, widget in self._labels.items():
            val = data.get(key, "")
            widget.configure(text=val or "—")
            if key == "originating_ip" and val:
                widget.configure(fg=COLORS["accent2"])
            elif key == "sender":
                widget.configure(fg=COLORS["accent"])


class AuthenticationTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=COLORS["bg_panel"])
        self._build()
        self._widgets = {}

    def _build(self):
        canvas = tk.Canvas(self, bg=COLORS["bg_panel"], highlightthickness=0)
        vsb = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.sf = tk.Frame(canvas, bg=COLORS["bg_panel"])
        self.sf.bind("<Configure>",
                     lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.sf, anchor="nw")
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        hdr = tk.Frame(self.sf, bg=COLORS["bg_panel"])
        hdr.pack(fill="x", padx=20, pady=(20, 8))
        tk.Label(hdr, text="▸ AUTHENTICATION RESULTS", font=FONTS["sans_lg"],
                 fg=COLORS["accent"], bg=COLORS["bg_panel"]).pack(side="left")

        self.spf_frame = tk.Frame(self.sf, bg=COLORS["bg_panel"])
        self.spf_frame.pack(fill="x", padx=20, pady=4)

        self.dkim_frame = tk.Frame(self.sf, bg=COLORS["bg_panel"])
        self.dkim_frame.pack(fill="x", padx=20, pady=4)

        self.dmarc_frame = tk.Frame(self.sf, bg=COLORS["bg_panel"])
        self.dmarc_frame.pack(fill="x", padx=20, pady=4)

    def _make_section(self, parent, title, color):
        frame = tk.Frame(parent, bg=COLORS["bg_card"],
                         highlightbackground=color, highlightthickness=1)
        frame.pack(fill="x", pady=4)
        tk.Label(frame, text=title, font=("Helvetica", 10, "bold"),
                 fg=color, bg=COLORS["bg_card"], anchor="w",
                 padx=12, pady=6).pack(fill="x")
        return frame

    def load(self, data):
        for frame in [self.spf_frame, self.dkim_frame, self.dmarc_frame]:
            for w in frame.winfo_children():
                w.destroy()

        spf_color = COLORS["pass_green"] if data.get("spf_pass") == "PASS" else COLORS["fail_red"]
        spf_sec = self._make_section(self.spf_frame, "SPF", spf_color)
        spf_inner = tk.Frame(spf_sec, bg=COLORS["bg_card"], padx=12, pady=4)
        spf_inner.pack(fill="x")

        def row(parent, label, value, color=None):
            r = tk.Frame(parent, bg=COLORS["bg_card"])
            r.pack(fill="x", pady=2)
            tk.Label(r, text=f"{label}:", font=FONTS["label"], fg=COLORS["text_dim"],
                     bg=COLORS["bg_card"], width=22, anchor="w").pack(side="left")
            if label in ("Result", "DKIM", "DMARC"):
                StatusBadge(r, value).pack(side="left")
            else:
                tk.Label(r, text=value or "—", font=FONTS["value"],
                         fg=color or COLORS["text"], bg=COLORS["bg_card"],
                         anchor="w", wraplength=600, justify="left").pack(side="left")

        row(spf_inner, "Result", data.get("spf_pass", "UNKNOWN"))
        row(spf_inner, "Originating IP", data.get("originating_ip", ""), COLORS["accent2"])
        row(spf_inner, "rDNS", data.get("rdns", ""))
        row(spf_inner, "Return-Path Domain", data.get("return_path_domain", ""))
        row(spf_inner, "SPF Record", data.get("spf_record", ""))

        dkim_color = COLORS["pass_green"] if data.get("dkim_result") == "PASS" else COLORS["fail_red"]
        dkim_sec = self._make_section(self.dkim_frame, "DKIM", dkim_color)
        dkim_inner = tk.Frame(dkim_sec, bg=COLORS["bg_card"], padx=12, pady=4)
        dkim_inner.pack(fill="x")
        row(dkim_inner, "DKIM", data.get("dkim_result", "UNKNOWN"))
        for sig in data.get("dkim_signatures", []):
            row(dkim_inner, "Selector", sig.get("selector", ""))
            row(dkim_inner, "Signing Domain", sig.get("signing_domain", ""))
            row(dkim_inner, "Algorithm", sig.get("algorithm", ""))
            row(dkim_inner, "Verification", sig.get("verification", "NONE"))

        dmarc_color = COLORS["pass_green"] if data.get("dmarc_pass") == "PASS" else COLORS["fail_red"]
        dmarc_sec = self._make_section(self.dmarc_frame, "DMARC", dmarc_color)
        dmarc_inner = tk.Frame(dmarc_sec, bg=COLORS["bg_card"], padx=12, pady=4)
        dmarc_inner.pack(fill="x")
        row(dmarc_inner, "DMARC", data.get("dmarc_pass", "UNKNOWN"))
        row(dmarc_inner, "From Domain", data.get("from_domain", ""))
        row(dmarc_inner, "DMARC Record", data.get("dmarc_record", ""))


class URLsTab(tk.Frame):
    def __init__(self, parent, vt_api, on_rescan=None):
        super().__init__(parent, bg=COLORS["bg_panel"])
        self.vt_api = vt_api
        self.on_rescan = on_rescan
        self._url_data = []
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=COLORS["bg_panel"])
        hdr.pack(fill="x", padx=20, pady=(20, 8))
        tk.Label(hdr, text="▸ URLS FOUND", font=FONTS["sans_lg"],
                 fg=COLORS["accent"], bg=COLORS["bg_panel"]).pack(side="left")
        self.scan_all_btn = tk.Button(
            hdr, text="⚡ SCAN ALL (VirusTotal)", font=("Helvetica", 9, "bold"),
            fg=COLORS["bg"], bg=COLORS["accent"], activebackground=COLORS["accent2"],
            relief="flat", padx=10, pady=4, cursor="hand2",
            command=self._scan_all
        )
        self.scan_all_btn.pack(side="right")

        self.count_label = tk.Label(self, text="No URLs found", font=FONTS["sans"],
                                     fg=COLORS["text_dim"], bg=COLORS["bg_panel"])
        self.count_label.pack(padx=20, anchor="w")

        cols = ("URL", "VirusTotal Result")
        frame = tk.Frame(self, bg=COLORS["bg_panel"])
        frame.pack(fill="both", expand=True, padx=20, pady=8)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("URL.Treeview",
                         background=COLORS["bg_card"],
                         foreground=COLORS["text"],
                         fieldbackground=COLORS["bg_card"],
                         borderwidth=0,
                         rowheight=28,
                         font=FONTS["mono_sm"])
        style.configure("URL.Treeview.Heading",
                         background=COLORS["bg_hover"],
                         foreground=COLORS["accent"],
                         font=("Helvetica", 9, "bold"),
                         relief="flat")
        style.map("URL.Treeview", background=[("selected", COLORS["bg_hover"])])

        self.tree = ttk.Treeview(frame, columns=cols, show="headings",
                                  style="URL.Treeview")
        self.tree.heading("URL", text="URL")
        self.tree.heading("VirusTotal Result", text="VirusTotal Result")
        self.tree.column("URL", width=500)
        self.tree.column("VirusTotal Result", width=300)

        vsb = tk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)

        self.tree.bind("<Button-3>", self._on_right_click)
        self.ctx_menu = tk.Menu(self, tearoff=0, bg=COLORS["bg_card"],
                                 fg=COLORS["text"], activebackground=COLORS["bg_hover"])
        self.ctx_menu.add_command(label="Scan this URL (VirusTotal)", command=self._scan_selected)

    def load(self, urls):
        self._url_data = urls
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.count_label.configure(text=f"{len(urls)} URL(s) found")
        for u in urls:
            self.tree.insert("", "end", values=(u["url"], u.get("vt_result") or "Not scanned"))

    def _set_scanning(self, scanning, progress=""):
        self.scan_all_btn.configure(
            state="disabled" if scanning else "normal",
            text=progress if scanning else "⚡ SCAN ALL (VirusTotal)",
        )

    def _scan_all(self):
        if not self._url_data:
            return

        def run():
            total = len(self._url_data)
            for i, u in enumerate(self._url_data):
                self.after(0, lambda i=i: self._set_scanning(True, f"Scanning {i + 1}/{total}…"))
                result_data = self.vt_api.scan_url(u["url"])
                u["vt_result"] = self.vt_api.parse_url_result(result_data)
                self.after(0, self._refresh)
            self.after(0, lambda: self._set_scanning(False))
            if self.on_rescan:
                self.after(0, self.on_rescan)
        threading.Thread(target=run, daemon=True).start()

    def _scan_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        def run():
            u = self._url_data[idx]
            result_data = self.vt_api.scan_url(u["url"])
            u["vt_result"] = self.vt_api.parse_url_result(result_data)
            self.after(0, self._refresh)
            if self.on_rescan:
                self.after(0, self.on_rescan)
        threading.Thread(target=run, daemon=True).start()

    def _refresh(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for u in self._url_data:
            result = u.get("vt_result") or "Not scanned"
            tag = "malicious" if "MALICIOUS" in str(result) else "clean"
            self.tree.insert("", "end", values=(u["url"], result), tags=(tag,))
        self.tree.tag_configure("malicious", foreground=COLORS["fail_red"])
        self.tree.tag_configure("clean", foreground=COLORS["pass_green"])

    def _on_right_click(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.ctx_menu.post(event.x_root, event.y_root)


class AttachmentsTab(tk.Frame):
    def __init__(self, parent, vt_api, on_rescan=None):
        super().__init__(parent, bg=COLORS["bg_panel"])
        self.vt_api = vt_api
        self.on_rescan = on_rescan
        self._att_data = []
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=COLORS["bg_panel"])
        hdr.pack(fill="x", padx=20, pady=(20, 8))
        tk.Label(hdr, text="▸ ATTACHMENTS", font=FONTS["sans_lg"],
                 fg=COLORS["accent"], bg=COLORS["bg_panel"]).pack(side="left")
        self.scan_btn = tk.Button(
            hdr, text="⚡ SCAN ALL HASHES (VirusTotal)", font=("Helvetica", 9, "bold"),
            fg=COLORS["bg"], bg=COLORS["accent"], activebackground=COLORS["accent2"],
            relief="flat", padx=10, pady=4, cursor="hand2",
            command=self._scan_all
        )
        self.scan_btn.pack(side="right")

        self.count_label = tk.Label(self, text="No attachments", font=FONTS["sans"],
                                     fg=COLORS["text_dim"], bg=COLORS["bg_panel"])
        self.count_label.pack(padx=20, anchor="w")

        note = tk.Label(
            self, text="Hash lookup only — attachment content is never uploaded to VirusTotal.",
            font=FONTS["label"], fg=COLORS["text_dim"], bg=COLORS["bg_panel"],
        )
        note.pack(padx=20, anchor="w")

        frame = tk.Frame(self, bg=COLORS["bg_panel"])
        frame.pack(fill="both", expand=True, padx=20, pady=8)

        cols = ("Filename", "Size", "Type", "SHA256", "VirusTotal")
        style = ttk.Style()
        style.configure("ATT.Treeview",
                         background=COLORS["bg_card"],
                         foreground=COLORS["text"],
                         fieldbackground=COLORS["bg_card"],
                         borderwidth=0,
                         rowheight=30,
                         font=FONTS["mono_sm"])
        style.configure("ATT.Treeview.Heading",
                         background=COLORS["bg_hover"],
                         foreground=COLORS["accent"],
                         font=("Helvetica", 9, "bold"),
                         relief="flat")

        self.tree = ttk.Treeview(frame, columns=cols, show="headings", style="ATT.Treeview")
        for col in cols:
            self.tree.heading(col, text=col)
        self.tree.column("Filename", width=160)
        self.tree.column("Size", width=80)
        self.tree.column("Type", width=120)
        self.tree.column("SHA256", width=200)
        self.tree.column("VirusTotal", width=250)

        vsb = tk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)

        detail_frame = InfoCard(self)
        detail_frame.pack(fill="x", padx=20, pady=8)
        tk.Label(detail_frame, text="SELECT AN ATTACHMENT FOR HASH DETAILS",
                 font=FONTS["label"], fg=COLORS["text_dim"],
                 bg=COLORS["bg_card"]).pack(anchor="w")
        self.md5_lbl = detail_frame.add_row("MD5", "")
        self.sha256_lbl = detail_frame.add_row("SHA256", "")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    def load(self, attachments):
        self._att_data = attachments
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.count_label.configure(text=f"{len(attachments)} attachment(s) found")
        for att in attachments:
            self.tree.insert("", "end", values=(
                att["filename"],
                f"{att['size']} bytes",
                att["content_type"],
                att["sha256"][:32] + "...",
                att.get("vt_result") or "Not scanned",
            ))

    def _on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        att = self._att_data[idx]
        self.md5_lbl.configure(text=att.get("md5", ""))
        self.sha256_lbl.configure(text=att.get("sha256", ""))

    def _set_scanning(self, scanning, progress=""):
        self.scan_btn.configure(
            state="disabled" if scanning else "normal",
            text=progress if scanning else "⚡ SCAN ALL HASHES (VirusTotal)",
        )

    def _scan_all(self):
        if not self._att_data:
            return

        def run():
            total = len(self._att_data)
            for i, att in enumerate(self._att_data):
                self.after(0, lambda i=i: self._set_scanning(True, f"Scanning {i + 1}/{total}…"))
                result_data = self.vt_api.scan_hash(att["sha256"])
                att["vt_result"] = self.vt_api.parse_file_result(result_data)
                self.after(0, self._refresh)
            self.after(0, lambda: self._set_scanning(False))
            if self.on_rescan:
                self.after(0, self.on_rescan)
        threading.Thread(target=run, daemon=True).start()

    def _refresh(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for att in self._att_data:
            result = att.get("vt_result") or "Not scanned"
            tag = "malicious" if "MALICIOUS" in str(result) else "clean"
            self.tree.insert("", "end", values=(
                att["filename"],
                f"{att['size']} bytes",
                att["content_type"],
                att["sha256"][:32] + "...",
                result,
            ), tags=(tag,))
        self.tree.tag_configure("malicious", foreground=COLORS["fail_red"])
        self.tree.tag_configure("clean", foreground=COLORS["pass_green"])


class TransmissionTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=COLORS["bg_panel"])
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=COLORS["bg_panel"])
        hdr.pack(fill="x", padx=20, pady=(20, 8))
        tk.Label(hdr, text="▸ EMAIL TRANSMISSION PATH", font=FONTS["sans_lg"],
                 fg=COLORS["accent"], bg=COLORS["bg_panel"]).pack(side="left")

        canvas = tk.Canvas(self, bg=COLORS["bg_panel"], highlightthickness=0)
        vsb = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.sf = tk.Frame(canvas, bg=COLORS["bg_panel"])
        self.sf.bind("<Configure>",
                     lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.sf, anchor="nw")
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

    def load(self, hops):
        for w in self.sf.winfo_children():
            w.destroy()

        for hop in hops:
            hop_frame = tk.Frame(self.sf, bg=COLORS["bg_card"],
                                  highlightbackground=COLORS["border"],
                                  highlightthickness=1)
            hop_frame.pack(fill="x", padx=20, pady=6)

            header = tk.Frame(hop_frame, bg=COLORS["bg_hover"])
            header.pack(fill="x")

            tk.Label(header, text=f"  HOP {hop['hop']}",
                     font=("Courier New", 10, "bold"),
                     fg=COLORS["accent"], bg=COLORS["bg_hover"],
                     pady=5).pack(side="left")

            if hop.get("timestamp"):
                tk.Label(header, text=hop["timestamp"],
                         font=FONTS["mono_sm"], fg=COLORS["text_dim"],
                         bg=COLORS["bg_hover"], pady=5).pack(side="right", padx=10)

            inner = tk.Frame(hop_frame, bg=COLORS["bg_card"], padx=12, pady=8)
            inner.pack(fill="x")

            if hop.get("from"):
                r = tk.Frame(inner, bg=COLORS["bg_card"])
                r.pack(fill="x", pady=1)
                tk.Label(r, text="FROM:", font=FONTS["label"], fg=COLORS["text_dim"],
                         bg=COLORS["bg_card"], width=8, anchor="w").pack(side="left")
                tk.Label(r, text=hop["from"], font=FONTS["value"],
                         fg=COLORS["text"], bg=COLORS["bg_card"],
                         anchor="w").pack(side="left")

            if hop.get("by"):
                r = tk.Frame(inner, bg=COLORS["bg_card"])
                r.pack(fill="x", pady=1)
                tk.Label(r, text="BY:", font=FONTS["label"], fg=COLORS["text_dim"],
                         bg=COLORS["bg_card"], width=8, anchor="w").pack(side="left")
                tk.Label(r, text=hop["by"], font=FONTS["value"],
                         fg=COLORS["accent3"], bg=COLORS["bg_card"],
                         anchor="w").pack(side="left")

            raw_txt = StyledScrolledText(hop_frame, height=3)
            raw_txt.pack(fill="x", padx=8, pady=(0, 8))
            raw_txt.set_text(hop["raw"])

            if hop["hop"] < len(hops):
                tk.Label(self.sf, text="    ↓", font=("Courier New", 14),
                         fg=COLORS["text_dim"], bg=COLORS["bg_panel"]).pack()


class XHeadersTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=COLORS["bg_panel"])
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=COLORS["bg_panel"])
        hdr.pack(fill="x", padx=20, pady=(20, 8))
        tk.Label(hdr, text="▸ X-HEADERS", font=FONTS["sans_lg"],
                 fg=COLORS["accent"], bg=COLORS["bg_panel"]).pack(side="left")

        canvas = tk.Canvas(self, bg=COLORS["bg_panel"], highlightthickness=0)
        vsb = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.sf = tk.Frame(canvas, bg=COLORS["bg_panel"])
        self.sf.bind("<Configure>",
                     lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.sf, anchor="nw")
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

    def load(self, xheaders):
        for w in self.sf.winfo_children():
            w.destroy()

        if not xheaders:
            tk.Label(self.sf, text="No X-headers found",
                     font=FONTS["sans"], fg=COLORS["text_dim"],
                     bg=COLORS["bg_panel"], pady=20).pack()
            return

        card = InfoCard(self.sf)
        card.pack(fill="x", padx=20, pady=8)
        for key, val in xheaders.items():
            card.add_row(key, val)
