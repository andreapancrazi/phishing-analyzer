"""Reusable styled tkinter widgets shared across tabs."""

import tkinter as tk
from tkinter import ttk

from .theme import COLORS, FONTS


class StyledScrolledText(tk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=COLORS["bg_card"])
        height = kwargs.pop("height", 20)
        font = kwargs.pop("font", FONTS["mono"])

        self.text = tk.Text(
            self,
            bg=COLORS["bg_card"],
            fg=COLORS["text"],
            insertbackground=COLORS["accent"],
            selectbackground=COLORS["bg_hover"],
            relief="flat",
            borderwidth=0,
            font=font,
            height=height,
            wrap=tk.WORD,
            **kwargs,
        )
        self.vsb = tk.Scrollbar(self, orient="vertical", command=self.text.yview,
                                 bg=COLORS["bg"], troughcolor=COLORS["bg_panel"],
                                 activebackground=COLORS["accent"])
        self.text.configure(yscrollcommand=self.vsb.set)
        self.vsb.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)

    def set_text(self, content):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", content)
        self.text.configure(state="disabled")

    def clear(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")


class InfoCard(tk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(
            parent,
            bg=COLORS["bg_card"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            padx=16,
            pady=12,
            **kwargs
        )

    def add_row(self, label, value, value_color=None):
        row = tk.Frame(self, bg=COLORS["bg_card"])
        row.pack(fill="x", pady=3)

        lbl = tk.Label(
            row,
            text=f"{label}:",
            font=FONTS["label"],
            fg=COLORS["text_dim"],
            bg=COLORS["bg_card"],
            width=20,
            anchor="w",
        )
        lbl.pack(side="left")

        val = tk.Label(
            row,
            text=value or "—",
            font=FONTS["value"],
            fg=value_color or COLORS["text"],
            bg=COLORS["bg_card"],
            anchor="w",
            wraplength=600,
            justify="left",
        )
        val.pack(side="left", fill="x", expand=True)
        return val


class StatusBadge(tk.Label):
    def __init__(self, parent, status, **kwargs):
        color, bg = self._get_colors(status)
        super().__init__(
            parent,
            text=f"  {status}  ",
            font=("Helvetica", 9, "bold"),
            fg=color,
            bg=bg,
            relief="flat",
            padx=6,
            pady=3,
            **kwargs,
        )

    def _get_colors(self, status):
        s = status.upper() if status else ""
        if s in ("PASS", "CLEAN", "LOW"):
            return COLORS["bg"], COLORS["pass_green"]
        elif s in ("FAIL", "MALICIOUS", "HIGH"):
            return COLORS["text_bright"], COLORS["fail_red"]
        elif s in ("SOFTFAIL", "SUSPICIOUS", "WARN", "MEDIUM"):
            return COLORS["bg"], COLORS["warn_yellow"]
        elif s in ("NONE", "NEUTRAL", "UNKNOWN"):
            return COLORS["text"], COLORS["bg_hover"]
        else:
            return COLORS["text"], COLORS["bg_hover"]


class SectionHeader(tk.Label):
    def __init__(self, parent, text, **kwargs):
        super().__init__(
            parent,
            text=text.upper(),
            font=("Courier New", 9, "bold"),
            fg=COLORS["accent"],
            bg=COLORS["bg_panel"],
            anchor="w",
            pady=4,
            **kwargs,
        )
