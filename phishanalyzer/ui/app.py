"""Main application window: file handling, notebook of tabs, Settings dialog."""

import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from ..config import ConfigManager
from ..parsing.eml import EmailAnalyzer
from ..parsing.msg_convert import msg_to_eml_bytes, MsgConversionError
from ..virustotal import VirusTotalAPI
from .theme import COLORS, FONTS
from .tabs import (
    DetailsTab, AuthenticationTab, URLsTab, AttachmentsTab,
    TransmissionTab, XHeadersTab,
)
from .email_view_tab import EmailViewTab
from .summary_tab import SummaryTab


class PhishAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PhishAnalyzer ◈ Email Forensics Tool")
        self.geometry("1200x800")
        self.configure(bg=COLORS["bg"])
        self.minsize(900, 600)

        self.config_mgr = ConfigManager()
        self.vt_api_key = self.config_mgr.get("vt_api_key")
        self.safe_mode_default = self.config_mgr.get("safe_mode_default")
        self.vt_rate = self.config_mgr.get("vt_requests_per_minute")
        self.vt_api = VirusTotalAPI(self.vt_api_key, requests_per_minute=self.vt_rate)

        self._setup_styles()
        self._build_ui()
        self._current_file = None
        self._current_analyzer = None
        self._tabs = {}

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Main.TNotebook",
                         background=COLORS["bg"],
                         borderwidth=0,
                         tabmargins=[0, 0, 0, 0])
        style.configure("Main.TNotebook.Tab",
                         background=COLORS["bg_panel"],
                         foreground=COLORS["text_dim"],
                         font=("Helvetica", 9, "bold"),
                         padding=[16, 8],
                         borderwidth=0)
        style.map("Main.TNotebook.Tab",
                  background=[("selected", COLORS["bg_card"]),
                               ("active", COLORS["bg_hover"])],
                  foreground=[("selected", COLORS["accent"]),
                               ("active", COLORS["text"])])

    def _build_ui(self):
        topbar = tk.Frame(self, bg=COLORS["bg_panel"], height=56)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)

        logo_frame = tk.Frame(topbar, bg=COLORS["bg_panel"])
        logo_frame.pack(side="left", padx=20, pady=8)
        tk.Label(logo_frame, text="⬡", font=("Helvetica", 20),
                 fg=COLORS["accent"], bg=COLORS["bg_panel"]).pack(side="left")
        tk.Label(logo_frame, text=" PHISH", font=("Helvetica", 14, "bold"),
                 fg=COLORS["text_bright"], bg=COLORS["bg_panel"]).pack(side="left")
        tk.Label(logo_frame, text="ANALYZER", font=("Helvetica", 14, "bold"),
                 fg=COLORS["accent"], bg=COLORS["bg_panel"]).pack(side="left")

        ctrl_frame = tk.Frame(topbar, bg=COLORS["bg_panel"])
        ctrl_frame.pack(side="right", padx=16, pady=8)

        self.settings_btn = tk.Button(
            ctrl_frame, text="⚙ Settings", font=("Helvetica", 9),
            fg=COLORS["text_dim"], bg=COLORS["bg_panel"],
            activeforeground=COLORS["text"], activebackground=COLORS["bg_hover"],
            relief="flat", padx=10, pady=4, cursor="hand2",
            command=self._open_settings,
        )
        self.settings_btn.pack(side="right", padx=4)

        self.open_btn = tk.Button(
            ctrl_frame, text="📂 Open Email File",
            font=("Helvetica", 9, "bold"),
            fg=COLORS["bg"], bg=COLORS["accent"],
            activeforeground=COLORS["bg"], activebackground=COLORS["accent2"],
            relief="flat", padx=14, pady=6, cursor="hand2",
            command=self._open_file,
        )
        self.open_btn.pack(side="right", padx=4)

        self.status_bar = tk.Frame(self, bg=COLORS["bg_panel"], height=28)
        self.status_bar.pack(fill="x", side="bottom")
        self.status_bar.pack_propagate(False)
        self.status_label = tk.Label(
            self.status_bar, text="  Ready — open an .eml or .msg file to begin analysis",
            font=FONTS["label"], fg=COLORS["text_dim"], bg=COLORS["bg_panel"], anchor="w"
        )
        self.status_label.pack(side="left", padx=8)

        self.vt_status = tk.Label(
            self.status_bar,
            text="",
            font=FONTS["label"],
            bg=COLORS["bg_panel"], anchor="e"
        )
        self.vt_status.pack(side="right", padx=12)
        self._refresh_vt_status()

        self.main_frame = tk.Frame(self, bg=COLORS["bg"])
        self.main_frame.pack(fill="both", expand=True)
        self._show_drop_zone()

    def _refresh_vt_status(self):
        self.vt_status.configure(
            text=f"VT API: {'Configured ✓' if self.vt_api_key else 'Not Set — go to Settings'}",
            fg=COLORS["pass_green"] if self.vt_api_key else COLORS["warn_yellow"],
        )

    def _show_drop_zone(self):
        for w in self.main_frame.winfo_children():
            w.destroy()

        drop = tk.Frame(self.main_frame, bg=COLORS["bg"])
        drop.place(relx=0.5, rely=0.5, anchor="center")

        border = tk.Frame(drop, bg=COLORS["bg"],
                           highlightbackground=COLORS["border_accent"],
                           highlightthickness=2)
        border.pack(padx=40, pady=40)

        inner = tk.Frame(border, bg=COLORS["bg"], padx=60, pady=50)
        inner.pack()

        tk.Label(inner, text="⬡", font=("Helvetica", 48),
                 fg=COLORS["border"], bg=COLORS["bg"]).pack()
        tk.Label(inner, text="DROP EMAIL FILE HERE", font=("Helvetica", 16, "bold"),
                 fg=COLORS["text_dim"], bg=COLORS["bg"]).pack(pady=(8, 4))
        tk.Label(inner, text="or click to browse", font=FONTS["sans"],
                 fg=COLORS["text_dim"], bg=COLORS["bg"]).pack()
        tk.Label(inner, text=".eml · .msg · .txt",
                 font=FONTS["label"], fg=COLORS["text_dim"],
                 bg=COLORS["bg"]).pack(pady=(4, 0))

        btn = tk.Button(
            inner, text="Browse File",
            font=("Helvetica", 10, "bold"),
            fg=COLORS["bg"], bg=COLORS["accent"],
            activeforeground=COLORS["bg"], activebackground=COLORS["accent2"],
            relief="flat", padx=20, pady=8, cursor="hand2",
            command=self._open_file,
        )
        btn.pack(pady=(20, 0))

    def _show_notebook(self, analyzer):
        for w in self.main_frame.winfo_children():
            w.destroy()

        nb = ttk.Notebook(self.main_frame, style="Main.TNotebook")
        nb.pack(fill="both", expand=True)

        summary_tab = SummaryTab(nb)
        urls_tab = URLsTab(nb, self.vt_api, on_rescan=lambda: self._refresh_summary(analyzer))
        attachments_tab = AttachmentsTab(nb, self.vt_api, on_rescan=lambda: self._refresh_summary(analyzer))

        tabs = [
            ("Summary", summary_tab),
            ("Details", DetailsTab(nb)),
            ("Authentication", AuthenticationTab(nb)),
            ("URLs", urls_tab),
            ("Attachments", attachments_tab),
            ("Transmission", TransmissionTab(nb)),
            ("X-Headers", XHeadersTab(nb)),
            ("Email View", EmailViewTab(nb, safe_mode_default=self.safe_mode_default)),
        ]

        for title, tab in tabs:
            nb.add(tab, text=f"  {title}  ")

        self._tabs = dict(tabs)
        self._tabs["Summary"].load(analyzer.results)
        self._tabs["Details"].load(analyzer.results["details"])
        self._tabs["Authentication"].load(analyzer.results["authentication"])
        self._tabs["URLs"].load(analyzer.results["urls"])
        self._tabs["Attachments"].load(analyzer.results["attachments"])
        self._tabs["Transmission"].load(analyzer.results["transmission"])
        self._tabs["X-Headers"].load(analyzer.results["xheaders"])
        self._tabs["Email View"].load(analyzer.results["body"])

    def _refresh_summary(self, analyzer):
        if "Summary" in self._tabs:
            self._tabs["Summary"].load(analyzer.results)

    def _open_file(self):
        path = filedialog.askopenfilename(
            title="Open Email File",
            filetypes=[
                ("Email files", "*.eml *.msg *.txt"),
                ("All files", "*.*"),
            ]
        )
        if path:
            self._analyze_file(path)

    def _analyze_file(self, path):
        self._set_status(f"Analyzing: {os.path.basename(path)}...")
        self.update_idletasks()

        def run():
            try:
                if path.lower().endswith(".msg"):
                    raw, reconstructed = msg_to_eml_bytes(path)
                    note = (
                        "Reconstructed from .msg (no original transport headers found — "
                        "Authentication/Transmission data may be incomplete)"
                        if reconstructed else
                        "Reconstructed from .msg using original transport headers"
                    )
                    analyzer = EmailAnalyzer(raw, source_note=note)
                else:
                    with open(path, "rb") as f:
                        raw = f.read()
                    analyzer = EmailAnalyzer(raw)
                self.after(0, lambda: self._on_analysis_done(analyzer, path))
            except MsgConversionError as e:
                self.after(0, lambda: messagebox.showerror("Missing Dependency", str(e)))
                self.after(0, lambda: self._set_status("Error during analysis"))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror(
                    "Analysis Error", f"Failed to analyze file:\n{e}"
                ))
                self.after(0, lambda: self._set_status("Error during analysis"))

        threading.Thread(target=run, daemon=True).start()

    def _on_analysis_done(self, analyzer, path):
        self._current_file = path
        self._current_analyzer = analyzer
        self._show_notebook(analyzer)
        fname = os.path.basename(path)
        n_urls = len(analyzer.results["urls"])
        n_att = len(analyzer.results["attachments"])
        self._set_status(
            f"✓ Analyzed: {fname}  |  {n_urls} URL(s)  |  {n_att} attachment(s)"
        )
        self.title(f"PhishAnalyzer ◈ {fname}")

    def _set_status(self, text):
        self.status_label.configure(text=f"  {text}")

    def _open_settings(self):
        dlg = tk.Toplevel(self)
        dlg.title("Settings")
        dlg.geometry("520x420")
        dlg.configure(bg=COLORS["bg_card"])
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.grab_set()

        tk.Label(dlg, text="SETTINGS", font=FONTS["sans_lg"],
                 fg=COLORS["accent"], bg=COLORS["bg_card"]).pack(padx=20, pady=(20, 4), anchor="w")

        sep = tk.Frame(dlg, bg=COLORS["border"], height=1)
        sep.pack(fill="x", padx=20, pady=8)

        tk.Label(dlg, text="VirusTotal API Key", font=FONTS["label"],
                 fg=COLORS["text_dim"], bg=COLORS["bg_card"]).pack(padx=20, pady=(8, 2), anchor="w")
        tk.Label(dlg, text="Get your free key at: https://www.virustotal.com/gui/my-apikey",
                 font=FONTS["label"], fg=COLORS["text_dim"],
                 bg=COLORS["bg_card"]).pack(padx=20, anchor="w")

        api_frame = tk.Frame(dlg, bg=COLORS["bg_card"])
        api_frame.pack(fill="x", padx=20, pady=4)
        api_entry = tk.Entry(
            api_frame, font=FONTS["mono_sm"],
            fg=COLORS["text"], bg=COLORS["bg"],
            insertbackground=COLORS["accent"],
            relief="flat", show="•", width=50,
        )
        api_entry.pack(fill="x", ipady=6, padx=2)
        if self.vt_api_key:
            api_entry.insert(0, self.vt_api_key)

        def show_hide():
            api_entry.configure(show="" if api_entry.cget("show") else "•")
        tk.Button(api_frame, text="Show/Hide", font=FONTS["label"],
                  fg=COLORS["text_dim"], bg=COLORS["bg_hover"],
                  relief="flat", command=show_hide, cursor="hand2").pack(anchor="e", pady=2)

        tk.Label(dlg, text="VT requests per minute (free tier = 4)", font=FONTS["label"],
                 fg=COLORS["text_dim"], bg=COLORS["bg_card"]).pack(padx=20, pady=(12, 2), anchor="w")
        rate_var = tk.StringVar(value=str(self.vt_rate))
        rate_spin = tk.Spinbox(
            dlg, from_=1, to=60, textvariable=rate_var, width=6,
            font=FONTS["mono_sm"], bg=COLORS["bg"], fg=COLORS["text"],
            relief="flat", insertbackground=COLORS["accent"],
        )
        rate_spin.pack(padx=20, anchor="w")

        sep2 = tk.Frame(dlg, bg=COLORS["border"], height=1)
        sep2.pack(fill="x", padx=20, pady=12)

        safe_mode_var = tk.BooleanVar(value=self.safe_mode_default)
        tk.Checkbutton(
            dlg, text="Block remote content by default in the Rendered email view",
            variable=safe_mode_var, font=FONTS["sans_sm"],
            fg=COLORS["text"], bg=COLORS["bg_card"], selectcolor=COLORS["bg"],
            activebackground=COLORS["bg_card"], activeforeground=COLORS["text"],
        ).pack(padx=20, pady=(0, 4), anchor="w")
        tk.Label(
            dlg,
            text="Recommended: prevents tracking pixels / remote images from\n"
                 "alerting a sender that a phishing sample was opened.",
            font=FONTS["label"], fg=COLORS["text_dim"], bg=COLORS["bg_card"],
            justify="left",
        ).pack(padx=20, anchor="w")

        def save():
            self.vt_api_key = api_entry.get().strip()
            try:
                rate = max(1, int(rate_var.get()))
            except ValueError:
                rate = self.vt_rate
            self.vt_rate = rate
            self.safe_mode_default = bool(safe_mode_var.get())

            self.vt_api.set_api_key(self.vt_api_key)
            self.vt_api.set_rate(self.vt_rate)
            self.config_mgr.save(
                vt_api_key=self.vt_api_key,
                vt_requests_per_minute=self.vt_rate,
                safe_mode_default=self.safe_mode_default,
            )
            self._refresh_vt_status()
            dlg.destroy()

        btn_frame = tk.Frame(dlg, bg=COLORS["bg_card"])
        btn_frame.pack(fill="x", padx=20, pady=16, side="bottom")
        tk.Button(btn_frame, text="Cancel", font=("Helvetica", 9),
                  fg=COLORS["text_dim"], bg=COLORS["bg_hover"],
                  relief="flat", padx=12, pady=6, cursor="hand2",
                  command=dlg.destroy).pack(side="right", padx=4)
        tk.Button(btn_frame, text="Save", font=("Helvetica", 9, "bold"),
                  fg=COLORS["bg"], bg=COLORS["accent"],
                  relief="flat", padx=16, pady=6, cursor="hand2",
                  command=save).pack(side="right", padx=4)


def main():
    app = PhishAnalyzerApp()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    app.mainloop()
