#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SelfishNet Windows — Interface graphique Tkinter moderne (parité complète Linux).
"""

import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

_HERE = os.path.dirname(os.path.realpath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from selfishnet_core import (
    VERSION,
    human_rate_short,
    is_valid_mac,
    resource_path,
)
from selfishnet_windows import WindowsNetwork

REFRESH_MS = 1500
MAX_LOG_LINES = 500

C_BG = "#161b22"
C_PANEL = "#0d1117"
C_FG = "#e6edf3"
C_DIM = "#8b949e"
C_ACCENT = "#2f81f7"
C_SELECT = "#1f3a5f"
C_RED = "#f85149"
C_YELLOW = "#d29922"
C_GREEN = "#3fb950"


class App:
    def __init__(self, root):
        self.root = root
        self.network = WindowsNetwork()
        self.q = queue.Queue()
        self.devices = []
        self.targets = {}
        self.search_var = tk.StringVar()
        self._ready = False
        self._shown_errors = []

        root.title(f"SelfishNet Windows v{VERSION} — Contrôle de la bande passante")
        root.configure(bg=C_BG)
        root.geometry("1180x720")
        root.minsize(960, 540)
        root.protocol("WM_DELETE_WINDOW", self.quit_app)

        self._load_icon()
        self._styles()
        self._build()

        root.bind("<Control-a>", self._on_ctrl_a)
        root.bind("<Control-A>", self._on_ctrl_a)
        root.bind("<Control-d>", lambda _e: (self.select_none(), "break")[1])
        root.bind("<F5>", lambda _e: (self.rescan(), "break")[1])
        root.bind("<Control-r>", lambda _e: (self.rescan(), "break")[1])
        root.bind("<Control-R>", lambda _e: (self.rescan(), "break")[1])

        threading.Thread(target=self._init_backend, daemon=True, name="SelfishNetInit").start()
        root.after(400, self.tick)

    def _load_icon(self):
        ico_path = resource_path(os.path.join("assets", "selfishnet.ico"))
        png_path = resource_path(os.path.join("assets", "selfishnet.png"))
        if os.name == "nt" and os.path.isfile(ico_path):
            try:
                self.root.iconbitmap(ico_path)
            except Exception:
                pass
        if os.path.isfile(png_path):
            try:
                self._icon = tk.PhotoImage(file=png_path)
                self.root.iconphoto(True, self._icon)
            except Exception:
                pass

    def _on_ctrl_a(self, _event=None):
        focused = self.root.focus_get()
        if isinstance(focused, (tk.Entry, ttk.Entry, ttk.Spinbox, tk.Text)):
            return None
        self.select_all()
        return "break"

    def _styles(self):
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=C_BG, foreground=C_FG, fieldbackground=C_PANEL,
                     bordercolor=C_PANEL, lightcolor=C_PANEL, darkcolor=C_PANEL)
        st.configure("TButton", background=C_PANEL, foreground=C_FG,
                     borderwidth=0, focusthickness=0, padding=(11, 7))
        st.map("TButton", background=[("active", "#21262d")])
        st.configure("Danger.TButton", foreground=C_RED)
        st.configure("Warn.TButton", foreground=C_YELLOW)
        st.configure("Ok.TButton", foreground=C_GREEN)
        st.configure("Treeview", background=C_PANEL, fieldbackground=C_PANEL,
                     foreground=C_FG, rowheight=26, borderwidth=0)
        st.configure("Treeview.Heading", background="#21262d", foreground=C_DIM,
                     borderwidth=0, padding=(6, 6))
        st.map("Treeview", background=[("selected", C_SELECT)],
               foreground=[("selected", C_FG)])
        st.configure("TSpinbox", fieldbackground=C_PANEL, foreground=C_FG,
                     background=C_PANEL, arrowcolor=C_FG, borderwidth=0)

    def _build(self):
        head = tk.Frame(self.root, bg=C_BG)
        head.pack(fill="x", padx=18, pady=(16, 4))
        tk.Label(head, text="SelfishNet", font=("TkDefaultFont", 17, "bold"),
                 bg=C_BG, fg=C_FG).pack(side="left")
        tk.Label(head, text=f"  Windows v{VERSION}", font=("TkDefaultFont", 11),
                 bg=C_BG, fg=C_DIM).pack(side="left")
        ttk.Button(head, text="Rafraîchir (F5)", style="Ok.TButton",
                   command=self.rescan).pack(side="right", padx=(12, 0))
        self.lbl_total = tk.Label(head, text="", font=("TkDefaultFont", 11),
                                  bg=C_BG, fg=C_ACCENT)
        self.lbl_total.pack(side="right")

        self.lbl_net = tk.Label(self.root, text="Initialisation de Npcap et découverte réseau...",
                                font=("TkDefaultFont", 10), bg=C_BG, fg=C_DIM, anchor="w")
        self.lbl_net.pack(fill="x", padx=18)

        # Barre de recherche
        s_bar = tk.Frame(self.root, bg=C_BG)
        s_bar.pack(fill="x", padx=18, pady=(8, 2))
        tk.Label(s_bar, text="Rechercher :", font=("TkDefaultFont", 10), bg=C_BG, fg=C_FG).pack(side="left")
        self.search_entry = tk.Entry(
            s_bar, textvariable=self.search_var, bg=C_PANEL, fg=C_FG,
            insertbackground=C_FG, bd=0, highlightthickness=1,
            highlightbackground="#30363d", font=("TkDefaultFont", 10),
        )
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(8, 8), ipady=4)
        self.search_var.trace_add("write", lambda *_: self.render_rows())
        ttk.Button(s_bar, text="Effacer", command=lambda: self.search_var.set("")).pack(side="right")

        # Tableau des appareils
        wrap = tk.Frame(self.root, bg=C_BG)
        wrap.pack(fill="both", expand=True, padx=18, pady=8)
        cols = ("idx", "safe", "ip", "mac", "vendor", "rate", "pkts", "age", "state")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="extended")
        titles = {
            "idx": "N°", "safe": "Protection", "ip": "Adresse IP", "mac": "Adresse MAC",
            "vendor": "Nom / Fabricant", "rate": "Débit (↑ / ↓)", "pkts": "Paquets",
            "age": "Dernière vue", "state": "Statut",
        }
        widths = {
            "idx": 40, "safe": 85, "ip": 130, "mac": 145,
            "vendor": 200, "rate": 140, "pkts": 75, "age": 85, "state": 175,
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

        # Barre d'actions 1
        bar = tk.Frame(self.root, bg=C_BG)
        bar.pack(fill="x", padx=18)
        ttk.Button(bar, text="Mettre en pause", style="Danger.TButton",
                   command=lambda: self.act("pause")).pack(side="left", padx=(0, 8))
        tk.Label(bar, text="Limite :", bg=C_BG, fg=C_DIM).pack(side="left", padx=(6, 4))
        self.spin = ttk.Spinbox(bar, from_=16, to=100000, increment=50, width=7)
        self.spin.set(500)
        self.spin.pack(side="left")
        tk.Label(bar, text="kb/s", bg=C_BG, fg=C_DIM).pack(side="left", padx=(4, 6))
        ttk.Button(bar, text="Limiter", style="Warn.TButton",
                   command=lambda: self.act("limit")).pack(side="left", padx=4)
        tk.Label(bar, text="Durée :", bg=C_BG, fg=C_DIM).pack(side="left", padx=(10, 4))
        self.spin_min = ttk.Spinbox(bar, from_=0, to=1440, increment=5, width=5)
        self.spin_min.set(0)
        self.spin_min.pack(side="left")
        tk.Label(bar, text="min (0=∞)", bg=C_BG, fg=C_DIM).pack(side="left", padx=(4, 8))
        ttk.Button(bar, text="Libérer", style="Ok.TButton",
                   command=lambda: self.act("free")).pack(side="left", padx=4)
        ttk.Button(bar, text="Renommer", command=self.rename_selected).pack(side="right")

        # Barre d'actions 2
        bar2 = tk.Frame(self.root, bg=C_BG)
        bar2.pack(fill="x", padx=18, pady=(8, 0))
        ttk.Button(bar2, text="Tout sélectionner", command=self.select_all).pack(side="left")
        ttk.Button(bar2, text="Tout désélectionner", command=self.select_none).pack(side="left", padx=6)
        ttk.Button(bar2, text="Bloquer tout", style="Danger.TButton",
                   command=self.block_all).pack(side="left", padx=(8, 0))
        ttk.Button(bar2, text="Limiter tout", style="Warn.TButton",
                   command=lambda: self.act("limit_all")).pack(side="left", padx=4)
        ttk.Button(bar2, text="Libérer tout", style="Ok.TButton",
                   command=lambda: self.act("free_all")).pack(side="left")
        ttk.Button(bar2, text="Protéger (Safe Mode)", style="Ok.TButton",
                   command=self.safe_add).pack(side="left", padx=(12, 4))
        ttk.Button(bar2, text="Retirer protection",
                   command=self.safe_remove).pack(side="left", padx=4)

        # Journal d'activité
        self.log = tk.Text(self.root, height=6, bg=C_PANEL, fg=C_DIM, bd=0,
                           font=("TkFixedFont", 9), wrap="word", state="disabled")
        self.log.pack(fill="x", padx=18, pady=(10, 4))
        tk.Label(self.root, text="Raccourcis : F5 / Ctrl+R Rafraîchir · Ctrl+A Tout sélectionner · "
                                 "Ctrl+D Désélectionner · Ctrl+clic Sélection multiple",
                 bg=C_BG, fg=C_ACCENT, font=("TkDefaultFont", 9)).pack(anchor="w", padx=18)
        tk.Label(self.root, text="À n'utiliser que sur votre réseau / vos appareils (Npcap + Administrateur requis).",
                 bg=C_BG, fg=C_DIM, font=("TkDefaultFont", 9)).pack(anchor="w", padx=18, pady=(0, 12))

    def say(self, msg):
        self.log.configure(state="normal")
        self.log.insert("end", f"{time.strftime('%H:%M:%S')}  {msg}\n")
        lines = int(self.log.index("end-1c").split(".")[0])
        if lines > MAX_LOG_LINES:
            self.log.delete("1.0", f"{lines - MAX_LOG_LINES}.0")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _run_async(self, fn, prefix="Action"):
        if not self._ready:
            self.say("Le moteur réseau n'est pas encore prêt.")
            return

        def worker():
            try:
                msg = fn()
                self.q.put(("log", f"[{prefix}] {msg}"))
            except Exception as exc:
                self.q.put(("error_toast", f"[{prefix}] Erreur : {exc}"))
        threading.Thread(target=worker, daemon=True).start()

    def _init_backend(self):
        try:
            self.network.initialize()
            self.q.put(("ready", f"Npcap actif · {self.network.iface}"))
        except Exception as exc:
            self.q.put(("init_error", str(exc)))

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

    def rescan(self):
        self._run_async(lambda: f"Balayage ARP terminé ({self.network.rescan()} appareil(s) actif(s)).", "Réseau")

    def safe_add(self):
        ips = self.selection()
        if not ips:
            self.say("Sélectionnez d'abord un ou plusieurs appareils à protéger.")
            return

        def job():
            for ip in ips:
                self.network.safe_add(ip)
            return f"{len(ips)} appareil(s) ajouté(s) au Safe Mode."

        self._run_async(job, "Safe Mode")

    def safe_remove(self):
        ips = self.selection()
        if not ips:
            self.say("Sélectionnez d'abord un ou plusieurs appareils pour retirer la protection.")
            return

        def job():
            removed = 0
            for ip in ips:
                self.network.safe_remove(ip)
                removed += 1
            return f"{removed} appareil(s) retiré(s) du Safe Mode."

        self._run_async(job, "Safe Mode")

    def rename_selected(self):
        ips = self.selection()
        if len(ips) != 1:
            self.say("Sélectionnez exactement un appareil à renommer.")
            return
        ip = ips[0]
        dev = next((d for d in self.devices if d["ip"] == ip), {})
        key = dev.get("mac") if is_valid_mac(dev.get("mac")) else ip
        name = simpledialog.askstring(
            "Renommer l'appareil",
            f"Nom personnalisé pour {ip} ({key}) :\n(laisser vide pour effacer)",
            initialvalue=dev.get("alias", ""),
            parent=self.root,
        )
        if name is None:
            return
        self._run_async(lambda: (self.network.aliases.set(key, name), f"Alias mis à jour pour {key}")[1], "Alias")

    def block_all(self):
        if not self._ready:
            self.say("Le moteur réseau n'est pas initialisé.")
            return
        non_safe = [d["ip"] for d in self.devices if not d.get("is_safe")]
        if not messagebox.askyesno(
            "Bloquer les appareils non protégés ?",
            f"Bloquer l'accès réseau de {len(non_safe)} appareil(s) non protégé(s) ?\n\n"
            "• Votre machine, la passerelle et les appareils Safe Mode sont protégés.",
        ):
            return
        dur = self._duration_sec()

        def job():
            count = 0
            for ip in non_safe:
                try:
                    self.network.set_pause(ip, duration=dur)
                    count += 1
                except Exception:
                    pass
            return f"Pause appliquée sur {count} appareil(s)."

        self._run_async(job, "Action")

    def act(self, action):
        if not self._ready:
            self.say("Le moteur réseau n'est pas initialisé.")
            return
        try:
            rate = int(float(str(self.spin.get()).replace(",", ".")))
        except ValueError:
            rate = 500
        dur = self._duration_sec()

        if action == "free_all":
            self._run_async(lambda: (self.network.free_all_targets(), "Tous les appareils libérés.")[1], "Action")
            return

        if action == "limit_all":
            ips = [d["ip"] for d in self.devices if not d.get("is_safe")]
        else:
            ips = self.selection()
            if not ips:
                self.say("Sélectionnez d'abord un ou plusieurs appareils.")
                return

        def job():
            ok_count = 0
            for ip in ips:
                if action == "pause":
                    self.network.set_pause(ip, duration=dur)
                elif action in ("limit", "limit_all"):
                    self.network.set_limit(ip, rate_kbit=rate, duration=dur)
                elif action == "free":
                    self.network.set_free(ip)
                ok_count += 1
            return f"{action} appliqué sur {ok_count} appareil(s)."

        self._run_async(job, "Action")

    def tick(self):
        try:
            while True:
                kind, msg = self.q.get_nowait()
                if kind == "ready":
                    self._ready = True
                    self.say(msg)
                elif kind == "init_error":
                    self._ready = False
                    self.lbl_net.configure(text=f"Erreur : {msg}", fg=C_RED)
                    self.say(f"[Erreur] {msg}")
                    messagebox.showerror("SelfishNet Windows", msg)
                elif kind == "log":
                    self.say(msg)
                elif kind == "error_toast":
                    self.say(msg)
        except queue.Empty:
            pass

        if self._ready:
            self.devices = self.network.snapshot()
            self.targets = self.network.summary()
            self.lbl_net.configure(
                text=f"{self.network.iface}   ·   Mon PC : {self.network.my_ip}   ·   "
                     f"Box : {self.network.gateway}   ·   {len(self.devices)} appareil(s)",
                fg=C_DIM,
            )
            self.lbl_total.configure(text=f"Trafic total : {human_rate_short(self.network.total_kbit())}")
            self.render_rows()
            for e in self.network.errors[-2:]:
                if e and e not in self._shown_errors:
                    self._shown_errors.append(e)
                    if len(self._shown_errors) > 50:
                        self._shown_errors = self._shown_errors[-25:]
                    self.say(f"[Alerte] {e}")

        self.root.after(REFRESH_MS, self.tick)

    def render_rows(self):
        sel_ips = set(self.selection())
        q = self.search_var.get().lower().strip()
        idx = 1
        current_iids = set()

        for d in self.devices:
            ip = d["ip"]
            mac = d.get("mac", "?")
            alias = d.get("alias", "")
            vendor = d.get("vendor", "")
            if alias:
                display_name = f"{alias} ({vendor})" if vendor else alias
            elif d.get("is_self"):
                display_name = "Votre machine (Ce PC)"
            elif d.get("is_gateway"):
                display_name = f"{vendor} (Box / Passerelle)" if vendor else "Box / Passerelle"
            else:
                display_name = vendor or "—"

            t = self.targets.get(ip)
            is_safe = d.get("is_safe", False)
            safe_str = "Protégé" if is_safe else "—"

            if not t:
                state, tag = ("Protégé", "safe") if is_safe else ("Normal", "free")
            elif t["mode"] == "pause":
                state, tag = "Bloqué (Pause)", "pause"
            else:
                state, tag = f"Limité ({human_rate_short(t.get('rate'))})", "limit"
            if t and t.get("remaining_sec") is not None:
                rem = t["remaining_sec"]
                rem_s = f"{rem // 60}m{rem % 60:02d}s" if rem >= 60 else f"{rem}s"
                state += f" [{rem_s}]"

            if q:
                searchable = f"{ip} {mac} {display_name} {state} {safe_str}".lower()
                if q not in searchable:
                    continue

            age = d.get("age", 0)
            age_s = f"{age:.0f} s" if age < 120 else f"{age / 60:.0f} min"
            up_s = human_rate_short(d.get("up_kbit", 0))
            down_s = human_rate_short(d.get("down_kbit", 0))
            rate_str = f"↑{up_s} / ↓{down_s}" if (d.get("up_kbit") or d.get("down_kbit")) else human_rate_short(d.get("kbit", 0))

            row_id = f"ip_{ip.replace('.', '_')}"
            vals = (idx, safe_str, ip, mac, display_name, rate_str, d.get("packets", 0), age_s, state)

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

    def quit_app(self):
        self.lbl_net.configure(text="Restauration ARP et nettoyage des règles...", fg=C_YELLOW)
        self.root.update_idletasks()
        threading.Thread(target=self._stop_and_close, daemon=True).start()

    def _stop_and_close(self):
        try:
            self.network.stop()
        finally:
            self.root.after(0, self.root.destroy)


def main():
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        sys.exit(f"Impossible d'ouvrir l'interface : {exc}")
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
