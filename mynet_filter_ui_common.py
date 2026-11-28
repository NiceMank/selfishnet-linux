#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MyNet Filter UI Common — composants UX modernes partagés entre Linux et Windows.

Contient :
  * palette sombre moderne (cartes élevées, bordures subtiles, états sémantiques) ;
  * fonctions pures de tri, filtrage et export CSV/JSON (testables sans serveur X) ;
  * BandwidthSparkline : graphique temps réel du débit réseau (Canvas Tkinter) ;
  * KpiBar : bandeau de 4 cartes d'indicateurs clés (Appareils, Trafic, Restreints, Protégés).
"""

import csv
import json
from collections import deque

from mynet_filter_core import human_rate_short, sort_key_ip

# Palette sombre moderne (Slate / GitHub Dark Refined)
THEME = {
    "bg": "#0d1117",
    "surface": "#161b22",
    "surface_alt": "#1c2128",
    "border": "#30363d",
    "fg": "#e6edf3",
    "muted": "#8b949e",
    "accent": "#2f81f7",
    "accent_soft": "#1f3a5f",
    "green": "#3fb950",
    "yellow": "#d29922",
    "red": "#f85149",
    "purple": "#a371f7",
}

PRESET_RATES = [
    ("Éco 150k", 150),
    ("Web 1M", 1000),
    ("Vidéo 2.5M", 2500),
]
FOCUS_MODE_RATE_KBIT = 250


# ------------------------------------------------------------------ Logique pure (testable headless)
def filter_devices(devices, targets, query="", mode_filter="all"):
    """Filtre la liste des appareils selon un mode ('all'|'active'|'restricted'|'safe') et une recherche."""
    q = (query or "").strip().lower()
    out = []
    for d in devices:
        ip = d.get("ip", "")
        t = targets.get(ip)
        is_safe = bool(d.get("is_safe", False))
        kbit = float(d.get("kbit", 0.0) or 0.0)

        if mode_filter == "active" and kbit < 1.0:
            continue
        if mode_filter == "restricted" and not t:
            continue
        if mode_filter == "safe" and not is_safe:
            continue

        if q:
            state_txt = ""
            if t:
                state_txt = "bloqué pause" if t.get("mode") == "pause" else f"limité {t.get('rate', '')}"
            elif is_safe:
                state_txt = "protégé safe"
            else:
                state_txt = "normal"
            haystack = " ".join([
                ip,
                str(d.get("mac", "")),
                str(d.get("vendor", "")),
                str(d.get("alias", "")),
                state_txt,
            ]).lower()
            if q not in haystack:
                continue
        out.append(d)
    return out


def sort_devices(devices, targets, sort_col="default", reverse=False):
    """Trie les appareils selon la colonne choisie tout en gérant les types numériques/IP."""
    if sort_col == "default":
        return list(devices)

    def key_fn(d):
        ip = d.get("ip", "")
        if sort_col == "ip":
            return sort_key_ip(ip)
        if sort_col == "mac":
            return str(d.get("mac", "")).lower()
        if sort_col == "vendor":
            return (d.get("alias") or d.get("vendor") or "").lower()
        if sort_col == "rate":
            return float(d.get("kbit", 0.0) or 0.0)
        if sort_col == "pkts":
            return int(d.get("pkts", d.get("packets", 0)) or 0)
        if sort_col == "age":
            return float(d.get("age", 0.0) or 0.0)
        if sort_col == "safe":
            return 1 if d.get("is_safe") else 0
        if sort_col == "state":
            t = targets.get(ip)
            if not t:
                return 0 if not d.get("is_safe") else 1
            return 3 if t.get("mode") == "pause" else 2
        return sort_key_ip(ip)

    return sorted(devices, key=key_fn, reverse=reverse)


def compute_kpis(devices, targets, total_kbit=0.0):
    """Calcule les 4 indicateurs synthétiques du tableau de bord."""
    total = len(devices)
    restricted = len(targets)
    paused = sum(1 for t in targets.values() if t.get("mode") == "pause")
    limited = sum(1 for t in targets.values() if t.get("mode") == "limit")
    safe = sum(1 for d in devices if d.get("is_safe"))
    return {
        "total_devices": total,
        "total_kbit": float(total_kbit or 0.0),
        "restricted": restricted,
        "paused": paused,
        "limited": limited,
        "safe": safe,
    }


def export_devices_file(devices, targets, filepath):
    """Exporte l'état des appareils en CSV ou JSON selon l'extension du fichier."""
    rows = []
    for d in devices:
        ip = d.get("ip", "")
        t = targets.get(ip)
        mode = t.get("mode") if t else ("safe" if d.get("is_safe") else "normal")
        rows.append({
            "ip": ip,
            "mac": d.get("mac", ""),
            "alias": d.get("alias", ""),
            "vendor": d.get("vendor", ""),
            "is_safe": bool(d.get("is_safe", False)),
            "mode": mode,
            "limit_kbit": t.get("rate") if t and t.get("mode") == "limit" else "",
            "kbit": round(float(d.get("kbit", 0.0) or 0.0), 1),
            "up_kbit": round(float(d.get("up_kbit", 0.0) or 0.0), 1),
            "down_kbit": round(float(d.get("down_kbit", 0.0) or 0.0), 1),
            "packets": int(d.get("pkts", d.get("packets", 0)) or 0),
        })

    if filepath.lower().endswith(".json"):
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, ensure_ascii=False)
    else:
        fieldnames = [
            "ip", "mac", "alias", "vendor", "is_safe", "mode",
            "limit_kbit", "kbit", "up_kbit", "down_kbit", "packets",
        ]
        with open(filepath, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
    return len(rows)


# ------------------------------------------------------------------ Widgets Tkinter
def apply_modern_ttk_styles(root):
    """Configure un style ttk sombre cohérent et lisible."""
    from tkinter import ttk
    import tkinter as tk

    st = ttk.Style(root)
    try:
        st.theme_use("clam")
    except tk.TclError:
        pass

    st.configure(
        ".",
        background=THEME["bg"],
        foreground=THEME["fg"],
        fieldbackground=THEME["surface"],
        bordercolor=THEME["border"],
        lightcolor=THEME["surface"],
        darkcolor=THEME["surface"],
    )
    st.configure(
        "TButton",
        background=THEME["surface_alt"],
        foreground=THEME["fg"],
        borderwidth=1,
        focusthickness=0,
        padding=(10, 6),
    )
    st.map("TButton", background=[("active", "#262c36"), ("pressed", "#2d333b")])
    st.configure("Accent.TButton", background=THEME["accent"], foreground="#ffffff", borderwidth=0)
    st.map("Accent.TButton", background=[("active", "#388bfd")])
    st.configure("Danger.TButton", foreground=THEME["red"])
    st.configure("Warn.TButton", foreground=THEME["yellow"])
    st.configure("Ok.TButton", foreground=THEME["green"])
    st.configure("Pill.TButton", background=THEME["surface"], foreground=THEME["muted"], padding=(9, 4))
    st.configure("PillActive.TButton", background=THEME["accent_soft"], foreground=THEME["fg"], padding=(9, 4))

    st.configure(
        "Treeview",
        background=THEME["surface"],
        fieldbackground=THEME["surface"],
        foreground=THEME["fg"],
        rowheight=28,
        borderwidth=0,
    )
    st.configure(
        "Treeview.Heading",
        background=THEME["surface_alt"],
        foreground=THEME["muted"],
        borderwidth=0,
        padding=(8, 7),
    )
    st.map("Treeview.Heading", background=[("active", "#262c36")])
    st.map(
        "Treeview",
        background=[("selected", THEME["accent_soft"])],
        foreground=[("selected", THEME["fg"])],
    )
    st.configure(
        "TSpinbox",
        fieldbackground=THEME["surface"],
        foreground=THEME["fg"],
        background=THEME["surface_alt"],
        arrowcolor=THEME["fg"],
        borderwidth=1,
    )


def create_kpi_bar(parent):
    """Crée un bandeau de 4 cartes KPI et retourne (frame, dict_de_labels)."""
    import tkinter as tk

    bar = tk.Frame(parent, bg=THEME["bg"])
    cards = {}
    specs = [
        ("total_devices", "Appareils détectés", THEME["fg"]),
        ("total_kbit", "Débit réseau mesuré", THEME["accent"]),
        ("restricted", "Restreints (Pause / Limite)", THEME["yellow"]),
        ("safe", "Protégés (Safe Mode)", THEME["green"]),
    ]
    for idx, (key, title, color) in enumerate(specs):
        card = tk.Frame(
            bar,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
            padx=14,
            pady=8,
        )
        card.grid(row=0, column=idx, sticky="nsew", padx=(0 if idx == 0 else 8, 0))
        bar.grid_columnconfigure(idx, weight=1)
        tk.Label(card, text=title, font=("TkDefaultFont", 8), bg=THEME["surface"], fg=THEME["muted"]).pack(anchor="w")
        val_lbl = tk.Label(card, text="—", font=("TkDefaultFont", 14, "bold"), bg=THEME["surface"], fg=color)
        val_lbl.pack(anchor="w", pady=(2, 0))
        sub_lbl = tk.Label(card, text="", font=("TkDefaultFont", 8), bg=THEME["surface"], fg=THEME["muted"])
        sub_lbl.pack(anchor="w")
        cards[key] = (val_lbl, sub_lbl)
    return bar, cards


def update_kpi_bar(cards, kpis):
    cards["total_devices"][0].configure(text=str(kpis["total_devices"]))
    cards["total_devices"][1].configure(text="sur le sous-réseau local")

    cards["total_kbit"][0].configure(text=human_rate_short(kpis["total_kbit"]))
    cards["total_kbit"][1].configure(text="fenêtre glissante 3 s")

    cards["restricted"][0].configure(
        text=str(kpis["restricted"]),
        fg=THEME["red"] if kpis["paused"] > 0 else (THEME["yellow"] if kpis["limited"] > 0 else THEME["muted"]),
    )
    cards["restricted"][1].configure(text=f"{kpis['paused']} pause · {kpis['limited']} limité")

    cards["safe"][0].configure(text=str(kpis["safe"]))
    cards["safe"][1].configure(text="immunisés contre les actions")


class BandwidthSparkline:
    """Mini-graphique temps réel du débit total (60 échantillons) dessiné sur Canvas Tk."""

    def __init__(self, parent, max_points=60, height=58):
        import tkinter as tk

        self.max_points = max_points
        self.samples = deque([0.0] * max_points, maxlen=max_points)
        self.frame = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
            padx=10,
            pady=6,
        )
        hdr = tk.Frame(self.frame, bg=THEME["surface"])
        hdr.pack(fill="x")
        tk.Label(hdr, text="Activité réseau en temps réel", font=("TkDefaultFont", 8, "bold"),
                 bg=THEME["surface"], fg=THEME["muted"]).pack(side="left")
        self.lbl_peak = tk.Label(hdr, text="Pic : 0 kb/s", font=("TkDefaultFont", 8),
                                 bg=THEME["surface"], fg=THEME["accent"])
        self.lbl_peak.pack(side="right")

        self.canvas = tk.Canvas(
            self.frame,
            height=height,
            bg=THEME["bg"],
            highlightthickness=0,
        )
        self.canvas.pack(fill="x", expand=True, pady=(4, 0))
        self.canvas.bind("<Configure>", lambda _e: self.redraw())

    def push(self, kbit):
        self.samples.append(max(0.0, float(kbit or 0.0)))
        self.redraw()

    def redraw(self):
        c = self.canvas
        w = max(100, c.winfo_width())
        h = max(36, c.winfo_height())
        c.delete("all")

        peak = max(self.samples) if self.samples else 0.0
        scale = max(100.0, peak * 1.15)
        self.lbl_peak.configure(text=f"Pic : {human_rate_short(peak)}")

        # Lignes horizontales de repère
        for frac in (0.25, 0.5, 0.75):
            y = int(h * frac)
            c.create_line(0, y, w, y, fill="#21262d", dash=(2, 4))

        pts = list(self.samples)
        n = len(pts)
        if n < 2:
            return
        step = w / float(n - 1)
        coords = []
        for i, val in enumerate(pts):
            x = i * step
            y = h - 3 - (val / scale) * (h - 8)
            coords.extend((x, y))

        # Aire remplie subtile
        poly = [0, h, *coords, w, h]
        c.create_polygon(poly, fill="#162a45", outline="")
        c.create_line(*coords, fill=THEME["accent"], width=2, smooth=True)
