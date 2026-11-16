#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SelfishNet-Linux — Interface graphique Tkinter.

Architecture client-serveur :
- Le démon root (service systemd ou « sudo selfishnet daemon ») gère l'ARP spoofing et la mesure de bande passante.
- L'interface s'exécute avec les privilèges utilisateur normaux en communiquant via /run/selfishnet.sock.
"""

import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

HERE = os.path.dirname(os.path.abspath(__file__))
SOCK_FILE = "/run/selfishnet.sock"

def get_daemon_bin():
    candidates = [
        shutil.which("selfishnet"),
        "/usr/local/bin/selfishnet",
        "/usr/local/sbin/selfishnet",
        os.path.join(HERE, "selfishnet"),
        os.path.join(HERE, "selfishnet.py"),
    ]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return "selfishnet"

REFRESH_MS = 1500

C_BG = "#161b22"
C_PANEL = "#0d1117"
C_FG = "#e6edf3"
C_DIM = "#8b949e"
C_ACCENT = "#2f81f7"
C_RED = "#f85149"
C_YELLOW = "#d29922"
C_GREEN = "#3fb950"


def ipc(payload, timeout=12):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(SOCK_FILE)
        s.sendall((json.dumps(payload) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        return json.loads(buf.decode() or "{}")
    except (FileNotFoundError, ConnectionRefusedError):
        return {"error": "daemon_absent"}
    except socket.timeout:
        return {"error": "timeout"}
    except Exception as exc:
        return {"error": str(exc)}


def human_rate(kbit):
    if kbit is None:
        return "—"
    if kbit >= 1000:
        return f"{kbit/1000:.1f} Mb/s"
    return f"{kbit:.0f} kb/s"


class App:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.devices = []
        self.targets = {}
        self.safe_targets = set()
        self.search_var = tk.StringVar()
        self.my_ip = None
        self.gw_ip = None
        self._refreshing = False
        self._shown = []

        root.title("SelfishNet Linux - Contrôle de la bande passante")
        root.configure(bg=C_BG)
        root.geometry("1100x680")
        root.minsize(960, 540)

        for icon_path in [
            os.path.join(HERE, "assets", "selfishnet.png"),
            os.path.expanduser("~/.local/share/icons/hicolor/256x256/apps/selfishnet.png"),
            "/usr/share/icons/hicolor/256x256/apps/selfishnet.png"
        ]:
            if os.path.isfile(icon_path):
                try:
                    self._icon = tk.PhotoImage(file=icon_path)
                    root.iconphoto(True, self._icon)
                    break
                except Exception:
                    pass

        self._styles()
        self._build()

        root.bind("<Control-a>", lambda e: (self.select_all(), "break")[1])
        root.bind("<Control-A>", lambda e: (self.select_all(), "break")[1])
        root.bind("<Control-d>", lambda e: (self.select_none(), "break")[1])
        root.bind("<F5>", lambda e: (self.rescan(), "break")[1])
        root.bind("<Control-r>", lambda e: (self.rescan(), "break")[1])
        root.bind("<Control-R>", lambda e: (self.rescan(), "break")[1])

        self.root.after(100, self.refresh_async)
        self.root.after(300, self.tick)

    # ------------------------------------------------------------- styles & layout
    def _styles(self):
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=C_BG, foreground=C_FG, fieldbackground=C_PANEL,
                     bordercolor=C_PANEL, lightcolor=C_PANEL, darkcolor=C_PANEL)
        st.configure("TButton", background=C_PANEL, foreground=C_FG,
                     borderwidth=0, focusthickness=0, padding=(12, 7))
        st.map("TButton", background=[("active", "#21262d")])
        st.configure("Danger.TButton", foreground=C_RED)
        st.configure("Warn.TButton", foreground=C_YELLOW)
        st.configure("Ok.TButton", foreground=C_GREEN)
        st.configure("Treeview", background=C_PANEL, fieldbackground=C_PANEL,
                     foreground=C_FG, rowheight=26, borderwidth=0)
        st.configure("Treeview.Heading", background="#21262d", foreground=C_DIM,
                     borderwidth=0, padding=(6, 6))
        st.map("Treeview", background=[("selected", "#1f6feb40")],
               foreground=[("selected", C_FG)])
        st.configure("TSpinbox", fieldbackground=C_PANEL, foreground=C_FG,
                     background=C_PANEL, arrowcolor=C_FG, borderwidth=0)

    def _build(self):
        head = tk.Frame(self.root, bg=C_BG)
        head.pack(fill="x", padx=18, pady=(16, 4))
        tk.Label(head, text="SelfishNet", font=("TkDefaultFont", 17, "bold"),
                 bg=C_BG, fg=C_FG).pack(side="left")
        tk.Label(head, text="  Linux", font=("TkDefaultFont", 11),
                 bg=C_BG, fg=C_DIM).pack(side="left")
        self.btn_daemon = ttk.Button(head, text="Démarrer le service",
                                     command=self.start_daemon)
        self.btn_daemon.pack(side="right", padx=(8, 0))
        self.btn_rescan = ttk.Button(head, text="Rafraîchir (F5)", style="Ok.TButton",
                                     command=self.rescan)
        self.btn_rescan.pack(side="right", padx=(12, 0))
        self.lbl_total = tk.Label(head, text="", font=("TkDefaultFont", 11),
                                  bg=C_BG, fg=C_ACCENT)
        self.lbl_total.pack(side="right")

        self.lbl_net = tk.Label(self.root, text="Connexion au service en cours...",
                                font=("TkDefaultFont", 10), bg=C_BG, fg=C_DIM, anchor="w")
        self.lbl_net.pack(fill="x", padx=18)

        # Barre de recherche
        s_bar = tk.Frame(self.root, bg=C_BG)
        s_bar.pack(fill="x", padx=18, pady=(8, 2))
        tk.Label(s_bar, text="Rechercher :", font=("TkDefaultFont", 10), bg=C_BG, fg=C_FG).pack(side="left")
        self.search_entry = tk.Entry(s_bar, textvariable=self.search_var, bg=C_PANEL, fg=C_FG,
                                     insertbackground=C_FG, bd=0, highlightthickness=1,
                                     highlightbackground="#30363d", font=("TkDefaultFont", 10))
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(8, 8), ipady=4)
        self.search_var.trace_add("write", lambda *_: self.render_rows())
        ttk.Button(s_bar, text="Effacer", command=lambda: self.search_var.set("")).pack(side="right")

        # Tableau des périphériques
        wrap = tk.Frame(self.root, bg=C_BG)
        wrap.pack(fill="both", expand=True, padx=18, pady=8)
        cols = ("idx", "safe", "ip", "mac", "vendor", "rate", "pkts", "age", "state")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="extended")
        titles = {
            "idx": "N°", "safe": "Protection", "ip": "Adresse IP", "mac": "Adresse MAC",
            "vendor": "Fabricant / Nom", "rate": "Débit", "pkts": "Paquets",
            "age": "Dernière vue", "state": "Statut"
        }
        widths = {
            "idx": 40, "safe": 90, "ip": 135, "mac": 150,
            "vendor": 180, "rate": 95, "pkts": 75, "age": 85, "state": 160
        }
        for c in cols:
            self.tree.heading(c, text=titles[c])
            self.tree.column(c, width=widths[c],
                             anchor="center" if c in ("idx", "safe", "rate", "pkts", "age") else "w")
        self.tree.tag_configure("safe", foreground=C_GREEN)
        self.tree.tag_configure("pause", foreground=C_RED)
        self.tree.tag_configure("limit", foreground=C_YELLOW)
        self.tree.tag_configure("free", foreground=C_FG)

        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # Barre d'actions 1 : Blocage / Limite / Libération
        bar = tk.Frame(self.root, bg=C_BG)
        bar.pack(fill="x", padx=18)
        self.btn_pause = ttk.Button(bar, text="Mettre en pause", style="Danger.TButton",
                                     command=lambda: self.act("pause"))
        self.btn_pause.pack(side="left", padx=(0, 8))
        tk.Label(bar, text="Limite :", bg=C_BG, fg=C_DIM).pack(side="left", padx=(8, 4))
        self.spin = ttk.Spinbox(bar, from_=32, to=100000, increment=50, width=7)
        self.spin.set(500)
        self.spin.pack(side="left")
        tk.Label(bar, text="kb/s", bg=C_BG, fg=C_DIM).pack(side="left", padx=(4, 8))
        ttk.Button(bar, text="Limiter", style="Warn.TButton",
                   command=lambda: self.act("limit")).pack(side="left", padx=4)
        ttk.Button(bar, text="Libérer", style="Ok.TButton",
                   command=lambda: self.act("free")).pack(side="left", padx=4)

        # Barre d'actions 2 : Sélections groupées / Safe Mode
        bar2 = tk.Frame(self.root, bg=C_BG)
        bar2.pack(fill="x", padx=18, pady=(8, 0))
        ttk.Button(bar2, text="Tout sélectionner", command=self.select_all).pack(side="left")
        ttk.Button(bar2, text="Tout désélectionner", command=self.select_none).pack(side="left", padx=6)
        ttk.Button(bar2, text="Bloquer tout", style="Danger.TButton",
                   command=self.block_all).pack(side="left", padx=(8, 0))
        ttk.Button(bar2, text="Limiter tout", command=lambda: self.act("limit_all")).pack(side="left", padx=4)
        ttk.Button(bar2, text="Libérer tout", command=lambda: self.act("free_all")).pack(side="left")
        ttk.Button(bar2, text="Protéger (Safe Mode)", style="Ok.TButton",
                   command=self.safe_add).pack(side="left", padx=(12, 4))
        ttk.Button(bar2, text="Retirer protection",
                   command=self.safe_remove).pack(side="left", padx=4)
        ttk.Button(bar2, text="Rafraîchir", command=self.rescan).pack(side="left", padx=6)

        # Journal d'activité
        self.log = tk.Text(self.root, height=6, bg=C_PANEL, fg=C_DIM, bd=0,
                           font=("TkFixedFont", 9), wrap="word")
        self.log.pack(fill="x", padx=18, pady=(10, 4))
        tk.Label(self.root, text="Raccourcis : F5 / Ctrl+R Rafraîchir · Ctrl+A Tout sélectionner · "
                                 "Ctrl+D Désélectionner · Ctrl+clic Sélection multiple",
                 bg=C_BG, fg=C_ACCENT, font=("TkDefaultFont", 9)).pack(anchor="w", padx=18)
        tk.Label(self.root, text="À n'utiliser que sur votre réseau / vos appareils.",
                 bg=C_BG, fg=C_DIM, font=("TkDefaultFont", 9)).pack(anchor="w", padx=18, pady=(0, 12))

    def say(self, msg):
        self.log.insert("end", f"{time.strftime('%H:%M:%S')}  {msg}\n")
        self.log.see("end")

    # ------------------------------------------------------------- sélection & actions
    def selection(self):
        out = []
        for item in self.tree.selection():
            vals = self.tree.item(item, "values")
            if vals and len(vals) > 2:
                out.append(str(vals[2]))  # Colonne IP (indice 2)
        return out

    def select_all(self):
        self.tree.selection_set(self.tree.get_children())
        n = len(self.tree.selection())
        self.say(f"{n} appareil(s) sélectionné(s) — choisissez une action (Mettre en pause, Limiter, Protéger).")

    def select_none(self):
        self.tree.selection_remove(self.tree.get_children())
        self.say("Sélection effacée.")

    def safe_add(self):
        ips = self.selection()
        if not ips:
            self.say("Sélectionnez d'abord un ou plusieurs appareils à placer en Safe Mode.")
            return
        for ip in ips:
            res = ipc({"cmd": "safe_add", "target": ip})
            msg = res.get("message") or res.get("error", "Erreur")
            self.say(f"[Safe Mode] {msg}")
        self.refresh_async()

    def safe_remove(self):
        ips = self.selection()
        if not ips:
            self.say("Sélectionnez d'abord un ou plusieurs appareils pour retirer la protection.")
            return
        for ip in ips:
            res = ipc({"cmd": "safe_remove", "target": ip})
            msg = res.get("message") or res.get("error", "Erreur")
            self.say(f"[Safe Mode] {msg}")
        self.refresh_async()

    def block_all(self):
        non_safe = [d for d in self.devices
                    if d["ip"] not in (self.my_ip, self.gw_ip)
                    and d["ip"] not in self.safe_targets
                    and d.get("mac") not in self.safe_targets]
        n = len(non_safe)
        if not messagebox.askyesno(
                "Bloquer les appareils non protégés ?",
                f"Bloquer l'accès réseau de {n} appareil(s) non protégé(s) ?\n\n"
                "• Votre propre machine et la box sont protégées d'office.\n"
                "• Les appareils configurés en Safe Mode sont protégés et ne seront pas coupés.\n\n"
                "Confirmer le blocage ?"):
            return
        res = ipc({"cmd": "set", "targets": "local", "mode": "pause"}, timeout=15)
        if res.get("error") == "daemon_absent":
            self.say("Le service n'est pas lancé. Cliquez sur « Démarrer le service ».")
            return
        if res.get("error") == "timeout":
            self.say("L'action a été transmise au service d'arrière-plan (application en cours).")
            self.refresh_async()
            return
        msg = res.get("message") or res.get("error", "Erreur")
        self.say(f"[Action] {msg}")
        self.refresh_async()

    def act(self, action):
        ips = self.selection()
        rate = None
        try:
            rate = int(float(str(self.spin.get()).replace(",", ".")))
        except ValueError:
            rate = 500
        if action in ("pause", "limit", "free") and not ips:
            self.say("Sélectionnez d'abord un ou plusieurs appareils dans la liste.")
            return
        if action == "pause_all":
            targets = "local"
        elif action == "limit_all":
            targets = "local"
        elif action == "free_all":
            res = ipc({"cmd": "free_all"}, timeout=15)
            self.say(f"[Action] {res.get('message', res.get('error', '?'))}")
            self.refresh_async()
            return
        else:
            targets = ",".join(ips)
        mode = {"pause": "pause", "limit": "limit", "free": "free",
                "pause_all": "pause", "limit_all": "limit"}[action]
        res = ipc({"cmd": "set", "targets": targets, "mode": mode, "rate": rate}, timeout=15)
        if res.get("error") == "daemon_absent":
            self.say("Le service n'est pas lancé. Cliquez sur « Démarrer le service ».")
            return
        if res.get("error") == "timeout":
            self.say("L'action a été transmise au service d'arrière-plan (application en cours).")
            self.refresh_async()
            return
        msg = res.get("message") or res.get("error", "?")
        self.say(f"[Action] {msg}")
        self.refresh_async()

    def rescan(self):
        self.say("[Réseau] Balayage actif du réseau en cours (découverte des appareils)...")
        res = ipc({"cmd": "rescan"})
        if res.get("error") == "daemon_absent":
            self.say("Le service n'est pas lancé. Cliquez sur « Démarrer le service ».")
            return
        self.root.after(800, self.refresh_async)
        self.root.after(2000, self.refresh_async)

    def refresh_async(self):
        if getattr(self, "_refreshing", False):
            return
        self._refreshing = True
        threading.Thread(target=self._refresh, daemon=True).start()

    def _refresh(self):
        try:
            st = ipc({"cmd": "status"}, timeout=3)
            self.q.put(st)
        finally:
            self._refreshing = False

    def tick(self):
        try:
            while True:
                st = self.q.get_nowait()
                self.apply_status(st)
        except queue.Empty:
            pass
        self.refresh_async()
        self.root.after(REFRESH_MS, self.tick)

    def apply_status(self, st):
        if st.get("error") == "daemon_absent":
            self.lbl_net.configure(text="Service arrêté — cliquez sur « Démarrer le service »",
                                   fg=C_RED)
            return
        if st.get("error"):
            self.lbl_net.configure(text=f"Erreur : {st['error']}", fg=C_RED)
            return
        self.devices = st.get("devices", [])
        self.targets = {t["ip"]: t for t in st.get("targets", [])}
        self.safe_targets = set(st.get("safe", []))
        self.my_ip = st.get("my_ip")
        self.gw_ip = st.get("gateway")
        self.lbl_net.configure(
            text=f"{st.get('iface')}   ·   Mon PC : {st.get('my_ip')}   ·   "
                 f"Box : {st.get('gateway')}   ·   {len(self.devices)} appareil(s) détecté(s)",
            fg=C_DIM)
        self.lbl_total.configure(text=f"Trafic total : {human_rate(st.get('total_kbit', 0))}")
        self.render_rows()
        for e in st.get("errors", [])[-2:]:
            if e and e not in self._shown:
                self._shown.append(e)
                self.say(f"[Alerte] {e}")

    def render_rows(self):
        sel_ips = set(self.selection())
        q = self.search_var.get().lower().strip()
        idx = 1
        current_iids = set()

        for d in self.devices:
            ip = d["ip"]
            mac = d.get("mac", "?")
            vendor = d.get("vendor", "")
            if ip == self.my_ip:
                vendor = "Votre machine (Ce PC)"
            elif ip == self.gw_ip:
                vendor = f"{vendor} (Box / Passerelle)" if vendor else "Box / Passerelle"

            t = self.targets.get(ip)
            is_safe = (d.get("is_safe") or ip in self.safe_targets
                       or mac in self.safe_targets or ip in (self.my_ip, self.gw_ip))
            safe_str = "Protégé" if is_safe else "—"

            if not t:
                if is_safe:
                    state, tag = "Protégé", "safe"
                else:
                    state, tag = "Normal", "free"
            elif t["mode"] == "pause":
                state, tag = "Bloqué (Pause)", "pause"
            else:
                state, tag = f"Limité ({human_rate(t.get('rate'))})", "limit"

            if q:
                searchable = f"{ip} {mac} {vendor} {state} {safe_str}".lower()
                if q not in searchable:
                    continue

            age = d.get("age", 0)
            age_s = f"{age:.0f} s" if age < 120 else f"{age/60:.0f} min"
            row_id = f"ip_{ip.replace('.', '_')}"
            vals = (idx, safe_str, ip, mac, vendor or "—",
                    human_rate(d.get("kbit")), d.get("pkts", 0), age_s, state)

            if self.tree.exists(row_id):
                self.tree.item(row_id, values=vals, tags=(tag,))
            else:
                self.tree.insert("", "end", iid=row_id, values=vals, tags=(tag,))

            if ip in sel_ips and row_id not in self.tree.selection():
                self.tree.selection_add(row_id)

            current_iids.add(row_id)
            idx += 1

        for child in list(self.tree.get_children()):
            if child not in current_iids:
                self.tree.delete(child)

    def start_daemon(self):
        if ipc({"cmd": "ping"}, timeout=2).get("ok"):
            self.say("Le service tourne déjà.")
            return
        daemon_bin = get_daemon_bin()
        try:
            has_systemd = subprocess.run(["systemctl", "list-unit-files", "selfishnet.service"],
                                         capture_output=True, text=True).returncode == 0
            if has_systemd and os.geteuid() != 0:
                subprocess.Popen(
                    ["pkexec", "systemctl", "start", "selfishnet"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True)
            else:
                subprocess.Popen(
                    ["pkexec", daemon_bin, "daemon"] if os.geteuid() != 0
                    else [daemon_bin, "daemon"],
                    cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True)
            self.say("Démarrage du service en cours (authentification demandée)...")
        except Exception as exc:
            self.say(f"Échec du lancement : {exc} — exécutez « sudo selfishnet daemon » en terminal.")
        self.root.after(3000, self.refresh_async)


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
