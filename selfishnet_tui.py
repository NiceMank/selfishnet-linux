#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SelfishNet-Linux — Interface graphique Tkinter (UX moderne v1.1).

Architecture client-serveur :
- Le démon root (service systemd ou « sudo selfishnet daemon ») gère le réseau local.
- L'interface s'exécute avec les privilèges utilisateur normaux via /run/selfishnet.sock.
"""

import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

_HERE = os.path.dirname(os.path.realpath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from selfishnet_core import (
    VERSION,
    human_rate_short,
    ipc_request,
    is_valid_mac,
    resource_path,
)
from selfishnet_ui_common import (
    FOCUS_MODE_RATE_KBIT,
    PRESET_RATES,
    THEME,
    BandwidthSparkline,
    apply_modern_ttk_styles,
    compute_kpis,
    create_kpi_bar,
    export_devices_file,
    filter_devices,
    sort_devices,
    update_kpi_bar,
)

SOCK_FILE = "/run/selfishnet.sock"
REFRESH_MS = 1500
MAX_LOG_LINES = 500


def get_daemon_bin():
    candidates = [
        shutil.which("selfishnet"),
        "/usr/local/bin/selfishnet",
        "/usr/local/sbin/selfishnet",
        os.path.join(_HERE, "selfishnet"),
        os.path.join(_HERE, "selfishnet.py"),
    ]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return "selfishnet"


def ipc(payload, timeout=12):
    return ipc_request(SOCK_FILE, payload, timeout=timeout)


def human_rate(kbit):
    return human_rate_short(kbit)


class App:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.devices = []
        self.targets = {}
        self.safe_targets = set()
        self.search_var = tk.StringVar()
        self.mode_filter = "all"
        self.sort_col = "default"
        self.sort_rev = False
        self.my_ip = None
        self.gw_ip = None
        self.daemon_running = False
        self._refreshing = False
        self._shown_errors = []

        root.title(f"MyNet Filter Linux v{VERSION} — Contrôle de la bande passante")
        root.configure(bg=THEME["bg"])
        root.geometry("1240x800")
        root.minsize(1020, 640)

        for icon_path in [
            resource_path(os.path.join("assets", "selfishnet.png")),
            os.path.expanduser("~/.local/share/icons/hicolor/256x256/apps/selfishnet.png"),
            "/usr/share/icons/hicolor/256x256/apps/selfishnet.png",
        ]:
            if icon_path and os.path.isfile(icon_path):
                try:
                    self._icon = tk.PhotoImage(file=icon_path)
                    root.iconphoto(True, self._icon)
                    break
                except Exception:
                    pass

        apply_modern_ttk_styles(root)
        self._build()

        root.bind("<Control-a>", self._on_ctrl_a)
        root.bind("<Control-A>", self._on_ctrl_a)
        root.bind("<Control-d>", lambda _e: (self.select_none(), "break")[1])
        root.bind("<F5>", lambda _e: (self.rescan(), "break")[1])
        root.bind("<Control-r>", lambda _e: (self.rescan(), "break")[1])
        root.bind("<Control-R>", lambda _e: (self.rescan(), "break")[1])

        self.root.after(100, self.refresh_async)
        self.root.after(250, self.tick)

    def _on_ctrl_a(self, _event=None):
        focused = self.root.focus_get()
        if isinstance(focused, (tk.Entry, ttk.Entry, ttk.Spinbox, tk.Text)):
            return None
        self.select_all()
        return "break"

    def _build(self):
        # 1) En-tête
        head = tk.Frame(self.root, bg=THEME["bg"])
        head.pack(fill="x", padx=18, pady=(14, 4))
        tk.Label(head, text="MyNet Filter", font=("TkDefaultFont", 17, "bold"),
                 bg=THEME["bg"], fg=THEME["fg"]).pack(side="left")
        tk.Label(head, text=f"  Linux v{VERSION}", font=("TkDefaultFont", 10),
                 bg=THEME["bg"], fg=THEME["muted"]).pack(side="left", pady=(4, 0))

        self.btn_daemon = ttk.Button(head, text="Démarrer le service", command=self.toggle_daemon)
        self.btn_daemon.pack(side="right", padx=(8, 0))
        self.btn_fix_perms = ttk.Button(head, text="Corriger permissions", style="Warn.TButton",
                                        command=self.fix_socket_permissions)
        ttk.Button(head, text="Exporter", command=self.export_data).pack(side="right", padx=(8, 0))
        self.btn_rescan = ttk.Button(head, text="Rafraîchir (F5)", style="Ok.TButton", command=self.rescan)
        self.btn_rescan.pack(side="right", padx=(8, 0))

        self.lbl_net = tk.Label(
            self.root, text="Connexion au service en cours...",
            font=("TkDefaultFont", 9), bg=THEME["bg"], fg=THEME["muted"], anchor="w",
        )
        self.lbl_net.pack(fill="x", padx=18)

        # 2) Cartes KPI + Graphique temps réel
        kpi_bar, self.kpi_cards = create_kpi_bar(self.root)
        kpi_bar.pack(fill="x", padx=18, pady=(8, 6))

        self.sparkline = BandwidthSparkline(self.root, max_points=60, height=52)
        self.sparkline.frame.pack(fill="x", padx=18, pady=(0, 8))

        # 3) Barre de filtres + recherche
        s_bar = tk.Frame(self.root, bg=THEME["bg"])
        s_bar.pack(fill="x", padx=18, pady=(0, 6))
        self.filter_buttons = {}
        for key, label in (("all", "Tous"), ("active", "Actifs"), ("restricted", "Restreints"), ("safe", "Protégés")):
            btn = ttk.Button(
                s_bar,
                text=label,
                style="PillActive.TButton" if key == "all" else "Pill.TButton",
                command=lambda k=key: self.set_filter(k),
            )
            btn.pack(side="left", padx=(0, 4))
            self.filter_buttons[key] = btn

        tk.Label(s_bar, text="Rechercher :", font=("TkDefaultFont", 9),
                 bg=THEME["bg"], fg=THEME["muted"]).pack(side="left", padx=(14, 4))
        self.search_entry = tk.Entry(
            s_bar, textvariable=self.search_var, bg=THEME["surface"], fg=THEME["fg"],
            insertbackground=THEME["fg"], bd=0, highlightthickness=1,
            highlightbackground=THEME["border"], font=("TkDefaultFont", 10),
        )
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 6), ipady=4)
        self.search_var.trace_add("write", lambda *_: self.render_rows())
        ttk.Button(s_bar, text="Effacer", command=lambda: self.search_var.set("")).pack(side="right")

        # 4) Tableau des appareils (triable + menu contextuel clic droit)
        wrap = tk.Frame(
            self.root, bg=THEME["surface"],
            highlightthickness=1, highlightbackground=THEME["border"],
        )
        wrap.pack(fill="both", expand=True, padx=18, pady=(0, 8))
        cols = ("idx", "safe", "ip", "mac", "vendor", "rate", "pkts", "age", "state")
        self.col_titles = {
            "idx": "N°", "safe": "Protection", "ip": "Adresse IP", "mac": "Adresse MAC",
            "vendor": "Nom / Fabricant", "rate": "Débit (↑ / ↓)", "pkts": "Paquets",
            "age": "Dernière vue", "state": "Statut",
        }
        widths = {
            "idx": 40, "safe": 85, "ip": 130, "mac": 145,
            "vendor": 210, "rate": 145, "pkts": 75, "age": 85, "state": 175,
        }
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="extended")
        for c in cols:
            if c == "idx":
                self.tree.heading(c, text=self.col_titles[c])
            else:
                self.tree.heading(c, text=self.col_titles[c], command=lambda col=c: self.toggle_sort(col))
            self.tree.column(c, width=widths[c],
                             anchor="center" if c in ("idx", "safe", "rate", "pkts", "age") else "w")
        self.tree.tag_configure("safe", foreground=THEME["green"])
        self.tree.tag_configure("pause", foreground=THEME["red"])
        self.tree.tag_configure("limit", foreground=THEME["yellow"])
        self.tree.tag_configure("free", foreground=THEME["fg"])

        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # Menu contextuel clic droit
        self.ctx_menu = tk.Menu(self.root, tearoff=0, bg=THEME["surface_alt"], fg=THEME["fg"],
                                activebackground=THEME["accent_soft"], activeforeground=THEME["fg"])
        self.ctx_menu.add_command(label="Mettre en pause", command=lambda: self.act("pause"))
        self.ctx_menu.add_command(label="Limiter au débit configuré", command=lambda: self.act("limit"))
        self.ctx_menu.add_command(label="Libérer", command=lambda: self.act("free"))
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="Protéger (Safe Mode)", command=self.safe_add)
        self.ctx_menu.add_command(label="Retirer du Safe Mode", command=self.safe_remove)
        self.ctx_menu.add_command(label="Renommer l'appareil...", command=self.rename_selected)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="Copier l'adresse IP", command=lambda: self.copy_selected(2))
        self.ctx_menu.add_command(label="Copier l'adresse MAC", command=lambda: self.copy_selected(3))
        self.tree.bind("<Button-3>", self._show_context_menu)

        # 5) Barre d'actions 1 : Contrôle individuel + Presets rapides
        bar = tk.Frame(self.root, bg=THEME["bg"])
        bar.pack(fill="x", padx=18)
        ttk.Button(bar, text="Mettre en pause", style="Danger.TButton",
                   command=lambda: self.act("pause")).pack(side="left", padx=(0, 6))
        tk.Label(bar, text="Limite :", bg=THEME["bg"], fg=THEME["muted"]).pack(side="left", padx=(4, 4))
        self.spin = ttk.Spinbox(bar, from_=16, to=100000, increment=50, width=7)
        self.spin.set(500)
        self.spin.pack(side="left")
        tk.Label(bar, text="kb/s", bg=THEME["bg"], fg=THEME["muted"]).pack(side="left", padx=(3, 6))
        ttk.Button(bar, text="Limiter", style="Warn.TButton",
                   command=lambda: self.act("limit")).pack(side="left", padx=3)

        for label, rate_val in PRESET_RATES:
            ttk.Button(bar, text=label, style="Pill.TButton",
                       command=lambda r=rate_val: self.apply_preset(r)).pack(side="left", padx=2)

        tk.Label(bar, text="Durée :", bg=THEME["bg"], fg=THEME["muted"]).pack(side="left", padx=(10, 4))
        self.spin_min = ttk.Spinbox(bar, from_=0, to=1440, increment=5, width=5)
        self.spin_min.set(0)
        self.spin_min.pack(side="left")
        tk.Label(bar, text="min", bg=THEME["bg"], fg=THEME["muted"]).pack(side="left", padx=(3, 8))
        ttk.Button(bar, text="Libérer", style="Ok.TButton",
                   command=lambda: self.act("free")).pack(side="left", padx=3)
        ttk.Button(bar, text="Renommer", command=self.rename_selected).pack(side="right")

        # 6) Barre d'actions 2 : Actions groupées, Mode Focus & Safe Mode
        bar2 = tk.Frame(self.root, bg=THEME["bg"])
        bar2.pack(fill="x", padx=18, pady=(8, 0))
        ttk.Button(bar2, text="Tout sélectionner", command=self.select_all).pack(side="left")
        ttk.Button(bar2, text="Désélectionner", command=self.select_none).pack(side="left", padx=5)
        ttk.Button(bar2, text=f"Mode Focus ({FOCUS_MODE_RATE_KBIT}k)", style="Accent.TButton",
                   command=self.focus_mode).pack(side="left", padx=(8, 4))
        ttk.Button(bar2, text="Bloquer tout", style="Danger.TButton",
                   command=self.block_all).pack(side="left", padx=4)
        ttk.Button(bar2, text="Limiter tout", style="Warn.TButton",
                   command=lambda: self.act("limit_all")).pack(side="left", padx=4)
        ttk.Button(bar2, text="Libérer tout", style="Ok.TButton",
                   command=lambda: self.act("free_all")).pack(side="left", padx=4)
        ttk.Button(bar2, text="Protéger (Safe)", style="Ok.TButton",
                   command=self.safe_add).pack(side="right", padx=(4, 0))
        ttk.Button(bar2, text="Retirer Safe", command=self.safe_remove).pack(side="right")

        # 7) Journal d'activité
        self.log = tk.Text(
            self.root, height=5, bg=THEME["surface"], fg=THEME["muted"], bd=0,
            highlightthickness=1, highlightbackground=THEME["border"],
            font=("TkFixedFont", 9), wrap="word", state="disabled",
        )
        self.log.pack(fill="x", padx=18, pady=(8, 4))
        tk.Label(
            self.root,
            text="Raccourcis : F5 / Ctrl+R Rafraîchir · Ctrl+A Tout sélectionner · Ctrl+D Désélectionner · Clic droit Menu rapide",
            bg=THEME["bg"], fg=THEME["muted"], font=("TkDefaultFont", 8),
        ).pack(anchor="w", padx=18, pady=(0, 10))

    def _show_context_menu(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            if row not in self.tree.selection():
                self.tree.selection_set(row)
            self.ctx_menu.tk_popup(event.x_root, event.y_root)

    def copy_selected(self, col_idx):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        if vals and len(vals) > col_idx:
            val = str(vals[col_idx])
            self.root.clipboard_clear()
            self.root.clipboard_append(val)
            self.say(f"[Presse-papiers] Copié : {val}")

    def set_filter(self, key):
        self.mode_filter = key
        for k, btn in self.filter_buttons.items():
            btn.configure(style="PillActive.TButton" if k == key else "Pill.TButton")
        self.render_rows()

    def toggle_sort(self, col):
        if self.sort_col == col:
            self.sort_rev = not self.sort_rev
        else:
            self.sort_col = col
            self.sort_rev = col in ("rate", "pkts")
        for c, title in self.col_titles.items():
            if c == self.sort_col:
                arrow = " ▼" if self.sort_rev else " ▲"
                self.tree.heading(c, text=title + arrow)
            else:
                self.tree.heading(c, text=title)
        self.render_rows()

    def apply_preset(self, rate_kbit):
        self.spin.set(rate_kbit)
        if self.selection():
            self.act("limit")
        else:
            self.say(f"Preset {rate_kbit} kb/s prêt — sélectionnez un appareil puis cliquez sur Limiter.")

    def focus_mode(self):
        self.spin.set(FOCUS_MODE_RATE_KBIT)
        dur = self._duration_sec()
        self._run_async(
            lambda: ipc({"cmd": "set", "targets": "local", "mode": "limit",
                         "rate": FOCUS_MODE_RATE_KBIT, "duration": dur}, timeout=15),
            lambda res: self._report_ipc_result("Mode Focus", res),
        )

    def export_data(self):
        if not self.devices:
            self.say("Aucun appareil à exporter.")
            return
        path = filedialog.asksaveasfilename(
            title="Exporter la liste des appareils",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")],
            parent=self.root,
        )
        if not path:
            return
        try:
            count = export_devices_file(self.devices, self.targets, path)
            self.say(f"[Export] {count} appareil(s) exporté(s) vers {path}")
        except Exception as exc:
            messagebox.showerror("Export", str(exc))

    def say(self, msg):
        self.log.configure(state="normal")
        self.log.insert("end", f"{time.strftime('%H:%M:%S')}  {msg}\n")
        lines = int(self.log.index("end-1c").split(".")[0])
        if lines > MAX_LOG_LINES:
            self.log.delete("1.0", f"{lines - MAX_LOG_LINES}.0")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _run_async(self, fn, on_done=None):
        def worker():
            try:
                res = fn()
            except Exception as exc:
                res = {"error": str(exc)}
            self.q.put(("callback", on_done, res))
        threading.Thread(target=worker, daemon=True).start()

    def _duration_sec(self):
        try:
            mins = int(float(str(self.spin_min.get()).replace(",", ".")))
            return max(0, mins * 60) or None
        except ValueError:
            return None

    def selection(self):
        out = []
        for item in self.tree.selection():
            vals = self.tree.item(item, "values")
            if vals and len(vals) > 2:
                out.append(str(vals[2]))
        return out

    def select_all(self):
        self.tree.selection_set(self.tree.get_children())
        self.say(f"{len(self.tree.selection())} appareil(s) sélectionné(s).")

    def select_none(self):
        self.tree.selection_remove(self.tree.get_children())
        self.say("Sélection effacée.")

    def _report_ipc_result(self, prefix, res):
        err = res.get("error")
        if err == "daemon_absent":
            self.say("Le service n'est pas lancé. Cliquez sur « Démarrer le service ».")
            return
        if err == "permission_denied":
            self.say("Permission refusée sur /run/selfishnet.sock (vérifiez le groupe 'selfishnet').")
            return
        if err == "timeout":
            self.say("L'action a été transmise au service d'arrière-plan.")
            self.refresh_async()
            return
        msg = res.get("message") or err or "OK"
        self.say(f"[{prefix}] {msg}")
        self.refresh_async()

    def safe_add(self):
        ips = self.selection()
        if not ips:
            self.say("Sélectionnez d'abord un ou plusieurs appareils à protéger.")
            return
        self._run_async(
            lambda: {"batch": [ipc({"cmd": "safe_add", "target": ip}, timeout=12) for ip in ips]},
            lambda res: [self._report_ipc_result("Safe Mode", item) for item in res.get("batch", [])],
        )

    def safe_remove(self):
        ips = self.selection()
        if not ips:
            self.say("Sélectionnez d'abord un ou plusieurs appareils pour retirer la protection.")
            return
        self._run_async(
            lambda: {"batch": [ipc({"cmd": "safe_remove", "target": ip}, timeout=12) for ip in ips]},
            lambda res: [self._report_ipc_result("Safe Mode", item) for item in res.get("batch", [])],
        )

    def rename_selected(self):
        ips = self.selection()
        if len(ips) != 1:
            self.say("Sélectionnez exactement un appareil à renommer.")
            return
        ip = ips[0]
        dev = next((d for d in self.devices if d["ip"] == ip), {})
        target_key = dev.get("mac") if is_valid_mac(dev.get("mac")) else ip
        name = simpledialog.askstring(
            "Renommer l'appareil",
            f"Nom personnalisé pour {ip} ({target_key}) :\n(laisser vide pour effacer)",
            initialvalue=dev.get("alias", ""),
            parent=self.root,
        )
        if name is None:
            return
        self._run_async(
            lambda: ipc({"cmd": "alias_set", "target": target_key, "name": name}, timeout=10),
            lambda res: self._report_ipc_result("Alias", res),
        )

    def block_all(self):
        non_safe = [
            d for d in self.devices
            if d["ip"] not in (self.my_ip, self.gw_ip) and not d.get("is_safe")
        ]
        if not messagebox.askyesno(
            "Bloquer les appareils non protégés ?",
            f"Mettre en pause {len(non_safe)} appareil(s) non protégé(s) ?\n\n"
            "• Votre machine, la box et les appareils en Safe Mode restent protégés.",
        ):
            return
        dur = self._duration_sec()
        self._run_async(
            lambda: ipc({"cmd": "set", "targets": "local", "mode": "pause", "duration": dur}, timeout=15),
            lambda res: self._report_ipc_result("Action", res),
        )

    def act(self, action):
        ips = self.selection()
        try:
            rate = int(float(str(self.spin.get()).replace(",", ".")))
        except ValueError:
            rate = 500
        dur = self._duration_sec()

        if action in ("pause", "limit", "free") and not ips:
            self.say("Sélectionnez d'abord un ou plusieurs appareils dans la liste.")
            return
        if action == "free_all":
            self._run_async(
                lambda: ipc({"cmd": "free_all"}, timeout=15),
                lambda res: self._report_ipc_result("Action", res),
            )
            return
        targets = "local" if action in ("pause_all", "limit_all") else ",".join(ips)
        mode = {"pause": "pause", "limit": "limit", "free": "free",
                "pause_all": "pause", "limit_all": "limit"}[action]
        payload = {"cmd": "set", "targets": targets, "mode": mode, "rate": rate}
        if mode != "free" and dur:
            payload["duration"] = dur
        self._run_async(
            lambda: ipc(payload, timeout=15),
            lambda res: self._report_ipc_result("Action", res),
        )

    def rescan(self):
        self.say("[Réseau] Balayage actif du réseau en cours...")

        def done(res):
            if res.get("error"):
                self._report_ipc_result("Réseau", res)
                return
            self.root.after(800, self.refresh_async)
            self.root.after(2000, self.refresh_async)

        self._run_async(lambda: ipc({"cmd": "rescan"}, timeout=8), done)

    def refresh_async(self):
        if self._refreshing:
            return
        self._refreshing = True
        threading.Thread(target=self._refresh, daemon=True).start()

    def _refresh(self):
        try:
            st = ipc({"cmd": "status"}, timeout=3)
            self.q.put(("status", st))
        finally:
            self._refreshing = False

    def tick(self):
        try:
            while True:
                item = self.q.get_nowait()
                if item[0] == "status":
                    self.apply_status(item[1])
                elif item[0] == "callback":
                    _, cb, res = item
                    if cb:
                        cb(res)
        except queue.Empty:
            pass
        self.refresh_async()
        self.root.after(REFRESH_MS, self.tick)

    def apply_status(self, st):
        err = st.get("error")
        if err == "daemon_absent":
            self.daemon_running = False
            self.btn_fix_perms.pack_forget()
            self.btn_daemon.configure(text="Démarrer le service")
            self.lbl_net.configure(text="Service arrêté — cliquez sur « Démarrer le service »", fg=THEME["red"])
            return
        if err == "permission_denied":
            self.daemon_running = True
            if not self.btn_fix_perms.winfo_ismapped():
                self.btn_fix_perms.pack(side="right", padx=(8, 0))
            self.lbl_net.configure(
                text="Accès refusé au socket (/run/selfishnet.sock) — cliquez sur « Corriger permissions »",
                fg=THEME["red"],
            )
            return
        if err:
            self.lbl_net.configure(text=f"Erreur : {err}", fg=THEME["red"])
            return

        self.btn_fix_perms.pack_forget()
        self.daemon_running = True
        self.btn_daemon.configure(text="Arrêter le service")
        self.devices = st.get("devices", [])
        self.targets = {t["ip"]: t for t in st.get("targets", [])}
        self.safe_targets = set(st.get("safe", []))
        self.my_ip = st.get("my_ip")
        self.gw_ip = st.get("gateway")

        total_kbit = st.get("total_kbit", 0.0)
        kpis = compute_kpis(self.devices, self.targets, total_kbit)
        update_kpi_bar(self.kpi_cards, kpis)
        self.sparkline.push(total_kbit)

        ipv6_note = "   ·   ⚠ IPv6 actif" if st.get("ipv6_active") else ""
        self.lbl_net.configure(
            text=f"Interface {st.get('iface')}   ·   Mon PC : {self.my_ip}   ·   Box : {self.gw_ip}{ipv6_note}",
            fg=THEME["yellow"] if st.get("ipv6_active") else THEME["muted"],
        )
        self.render_rows()
        for e in st.get("errors", [])[-2:]:
            if e and e not in self._shown_errors:
                self._shown_errors.append(e)
                if len(self._shown_errors) > 50:
                    self._shown_errors = self._shown_errors[-25:]
                self.say(f"[Alerte] {e}")

    def render_rows(self):
        sel_ips = set(self.selection())
        visible = filter_devices(self.devices, self.targets, self.search_var.get(), self.mode_filter)
        visible = sort_devices(visible, self.targets, self.sort_col, self.sort_rev)

        idx = 1
        current_iids = set()
        for d in visible:
            ip = d["ip"]
            mac = d.get("mac", "?")
            alias = d.get("alias", "")
            vendor = d.get("vendor", "")
            if alias:
                display_name = f"{alias} ({vendor})" if vendor else alias
            elif ip == self.my_ip:
                display_name = "Votre machine (Ce PC)"
            elif ip == self.gw_ip:
                display_name = f"{vendor} (Box / Passerelle)" if vendor else "Box / Passerelle"
            else:
                display_name = vendor or "—"

            t = self.targets.get(ip)
            is_safe = bool(d.get("is_safe"))
            safe_str = "Protégé" if is_safe else "—"

            if not t:
                state, tag = ("Protégé", "safe") if is_safe else ("Normal", "free")
            elif t["mode"] == "pause":
                state, tag = "Bloqué (Pause)", "pause"
            else:
                state, tag = f"Limité ({human_rate(t.get('rate'))})", "limit"
            if t and t.get("remaining_sec") is not None:
                rem = t["remaining_sec"]
                rem_s = f"{rem // 60}m{rem % 60:02d}s" if rem >= 60 else f"{rem}s"
                state += f" [{rem_s}]"

            age = d.get("age", 0)
            age_s = f"{age:.0f} s" if age < 120 else f"{age / 60:.0f} min"
            up_s = human_rate(d.get("up_kbit", 0))
            down_s = human_rate(d.get("down_kbit", 0))
            rate_str = f"↑{up_s} / ↓{down_s}" if (d.get("up_kbit") or d.get("down_kbit")) else human_rate(d.get("kbit", 0))

            row_id = f"ip_{ip.replace('.', '_')}"
            vals = (idx, safe_str, ip, mac, display_name, rate_str, d.get("pkts", 0), age_s, state)

            if self.tree.exists(row_id):
                self.tree.item(row_id, values=vals, tags=(tag,))
                self.tree.move(row_id, "", idx - 1)
            else:
                self.tree.insert("", idx - 1, iid=row_id, values=vals, tags=(tag,))

            if ip in sel_ips and row_id not in self.tree.selection():
                self.tree.selection_add(row_id)

            current_iids.add(row_id)
            idx += 1

        for child in list(self.tree.get_children()):
            if child not in current_iids:
                self.tree.delete(child)

    def fix_socket_permissions(self):
        import getpass
        user = getpass.getuser()
        if not shutil.which("pkexec"):
            self.say(f"Exécutez en terminal : sudo usermod -aG selfishnet {user} && sudo setfacl -m u:{user}:rw {SOCK_FILE}")
            return

        def job():
            script = (
                f"groupadd -rf selfishnet && "
                f"usermod -aG selfishnet {user} && "
                f"(setfacl -m u:{user}:rw {SOCK_FILE} 2>/dev/null || chgrp selfishnet {SOCK_FILE})"
            )
            p = subprocess.run(["pkexec", "sh", "-c", script], capture_output=True, text=True, check=False)
            if p.returncode != 0:
                return {"error": (p.stderr or p.stdout or "Authentification annulée").strip()}
            return {"message": f"Permissions corrigées pour {user}."}

        self._run_async(job, lambda res: (
            self._report_ipc_result("Permissions", res),
            self.root.after(400, self.refresh_async),
        ))

    def toggle_daemon(self):
        if self.daemon_running:
            self._run_async(
                lambda: ipc({"cmd": "quit"}, timeout=10),
                lambda res: self._report_ipc_result("Service", res),
            )
            return

        def launch():
            if ipc({"cmd": "ping"}, timeout=2).get("ok"):
                return {"message": "Le service tourne déjà."}
            daemon_bin = get_daemon_bin()
            has_systemd = False
            if shutil.which("systemctl"):
                p = subprocess.run(
                    ["systemctl", "list-unit-files", "selfishnet.service"],
                    capture_output=True, text=True, check=False,
                )
                has_systemd = (p.returncode == 0 and "selfishnet.service" in p.stdout)
            if has_systemd and os.geteuid() != 0 and shutil.which("pkexec"):
                subprocess.Popen(
                    ["pkexec", "systemctl", "start", "selfishnet"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            else:
                cmd = ([shutil.which("pkexec"), daemon_bin, "daemon"]
                       if (os.geteuid() != 0 and shutil.which("pkexec"))
                       else [daemon_bin, "daemon"])
                subprocess.Popen(
                    cmd, cwd=_HERE,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            return {"message": "Démarrage du service en cours (authentification demandée)..."}

        self._run_async(launch, lambda res: (
            self._report_ipc_result("Service", res),
            self.root.after(2500, self.refresh_async),
        ))


def main():
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        sys.exit(f"Impossible d'ouvrir une fenêtre graphique ({exc}).\n"
                 "Utilisez plutôt la console : sudo selfishnet watch")
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
