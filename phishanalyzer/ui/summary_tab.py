"""At-a-glance triage summary: heuristic risk flags + IOC export."""

import tkinter as tk
from tkinter import filedialog, messagebox

from .. import scoring
from ..ioc_export import collect_iocs, export_csv, export_json
from .theme import COLORS, FONTS
from .widgets import InfoCard, StatusBadge


class SummaryTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=COLORS["bg_panel"])
        self._results = None
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=COLORS["bg_panel"])
        hdr.pack(fill="x", padx=20, pady=(20, 8))
        tk.Label(hdr, text="▸ TRIAGE SUMMARY", font=FONTS["sans_lg"],
                 fg=COLORS["accent"], bg=COLORS["bg_panel"]).pack(side="left")
        self.export_btn = tk.Button(
            hdr, text="⬇ Export IOCs…", font=("Helvetica", 9, "bold"),
            fg=COLORS["bg"], bg=COLORS["accent"], activebackground=COLORS["accent2"],
            relief="flat", padx=10, pady=4, cursor="hand2",
            command=self._export,
        )
        self.export_btn.pack(side="right")

        self.verdict_frame = tk.Frame(self, bg=COLORS["bg_card"],
                                       highlightbackground=COLORS["border"],
                                       highlightthickness=1)
        self.verdict_frame.pack(fill="x", padx=20, pady=8)
        inner = tk.Frame(self.verdict_frame, bg=COLORS["bg_card"], padx=14, pady=10)
        inner.pack(fill="x")
        tk.Label(inner, text="OVERALL TRIAGE READ", font=FONTS["label"],
                 fg=COLORS["text_dim"], bg=COLORS["bg_card"]).pack(anchor="w")
        self.verdict_row = tk.Frame(inner, bg=COLORS["bg_card"])
        self.verdict_row.pack(anchor="w", pady=(4, 0))

        tk.Label(
            self,
            text="Heuristic flags for a human analyst to weigh — not an automated verdict.",
            font=FONTS["label"], fg=COLORS["text_dim"], bg=COLORS["bg_panel"],
        ).pack(padx=20, anchor="w", pady=(0, 4))

        canvas = tk.Canvas(self, bg=COLORS["bg_panel"], highlightthickness=0)
        vsb = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.sf = tk.Frame(canvas, bg=COLORS["bg_panel"])
        self.sf.bind("<Configure>",
                     lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.sf, anchor="nw")
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

    def load(self, results):
        self._results = results
        flags = scoring.evaluate(results)
        verdict = scoring.overall_verdict(flags)

        for w in self.verdict_row.winfo_children():
            w.destroy()
        StatusBadge(self.verdict_row, verdict).pack(side="left")
        tk.Label(self.verdict_row, text=f"  {len(flags)} flag(s) raised",
                 font=FONTS["value"], fg=COLORS["text"],
                 bg=COLORS["bg_card"]).pack(side="left")

        for w in self.sf.winfo_children():
            w.destroy()

        if not flags:
            tk.Label(self.sf, text="No heuristic flags raised on the parsed data.",
                     font=FONTS["sans"], fg=COLORS["text_dim"],
                     bg=COLORS["bg_panel"], pady=16).pack(padx=20, anchor="w")
            return

        for flag in flags:
            row = tk.Frame(self.sf, bg=COLORS["bg_card"],
                            highlightbackground=COLORS["border"], highlightthickness=1)
            row.pack(fill="x", padx=20, pady=4)
            top = tk.Frame(row, bg=COLORS["bg_card"], padx=12, pady=8)
            top.pack(fill="x")
            StatusBadge(top, flag.severity).pack(side="left")
            tk.Label(top, text=f"  {flag.label}", font=("Helvetica", 10, "bold"),
                     fg=COLORS["text"], bg=COLORS["bg_card"]).pack(side="left")
            if flag.detail:
                tk.Label(row, text=flag.detail, font=FONTS["value"],
                         fg=COLORS["text_dim"], bg=COLORS["bg_card"],
                         anchor="w", wraplength=800, justify="left",
                         padx=12).pack(fill="x", pady=(0, 8))

    def _export(self):
        if not self._results:
            return
        iocs = collect_iocs(self._results)
        if not iocs:
            messagebox.showinfo("Export IOCs", "No indicators found to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export IOCs",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")],
        )
        if not path:
            return
        try:
            if path.lower().endswith(".json"):
                export_json(path, iocs)
            else:
                export_csv(path, iocs)
            messagebox.showinfo("Export IOCs", f"Exported {len(iocs)} indicator(s) to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export IOCs", f"Failed to export:\n{e}")
