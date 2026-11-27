#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SelfishNet Windows — Interface graphique Tkinter (UX moderne v1.1, parité Linux).
"""

import os
import queue
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
from selfishnet_windows import WindowsNetwork

REFRESH_MS = 1500
MAX_LOG_LINES = 500


class App:
    def __init__(self, root):
        self.root = root
        self.network = WindowsNetwork()
        self.q = queue.Queue()
        self.devices = []
        self.targets = {}
        self.search_var = tk.StringVar()
        self.mode_filter = "all"
        self.sort_col = "default"
        self.sort_rev = False
        self._ready = False
        self._shown_errors = []

        root.title(f"SelfishNet Windows v{VERSION} — Contrôle de la bande passante")
        root.configure(bg=THEME["bg"])
        root.geometry("1240x800")
        root.minsize(1020, 640)
        root.protocol("WM_DELETE_WINDOW", self.quit_app)

        self._load_icon()
        apply_modern_ttk_styles(root)
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

    def _build(self):
        head = tk.Frame(self.root, bg=THEME["bg"])
        head.pack(fill="x", padx=18, pady=(14, 4))
        tk.Label(head, text="SelfishNet", font=("TkDefaultFont", 17, "bold"),
                 bg=THEME["bg"], fg=THEME["fg"]).pack(side="left")
        tk.Label(head, text=f"  Windows v{VERSION}", font=("TkDefaultFont", 10),
                 bg=THEME["bg"], fg=THEME["muted"]).pack(side="left", pady=(4, 0))

        ttk.Button(head, text="Appairage Android", command=self.show_android_pairing).pack(side="right", padx=(8, 0))
        ttk.Button(head, text="Exporter", command=self.export_data).pack(side="right", padx=(8, 0))
        ttk.Button(head, text="Rafraîchir (F5)", style="Ok.TButton", command=self.rescan).pack(side="right", padx=(8, 0))

        self.lbl_net = tk.Label(
            self.root, text="Initialisation de Npcap et découverte réseau...",
            font=("TkDefaultFont", 9), bg=THEME["bg"], fg=THEME["muted"], anchor="w",
        )
        self.lbl_net.pack(fill="x", padx=18)

        kpi_bar, self.kpi_cards = create_kpi_bar(self.root)
        kpi_bar.pack(fill="x", padx=18, pady=(8, 6))

        self.sparkline = BandwidthSparkline(self.root, max_points=60, height=52)
        self.sparkline.frame.pack(fill="x", padx=18, pady=(0, 8))

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
        self.act("limit_all")

    def show_android_pairing(self):
        if not self._ready:
            self.say("Attendez la fin de l'initialisation avant d'activer l'API Android.")
            return
        try:
            uri = self.network.start_api(port=8443, host="0.0.0.0")
            self.root.clipboard_clear()
            self.root.clipboard_append(uri)
            self.say(f"[Android Companion] API active. URI copiée : {uri}")
            messagebox.showinfo(
                "Appairage Android Companion",
                "L'API Companion est maintenant active sur le port 8443.\n\n"
                f"URI d'appairage (copiée dans le presse-papiers) :\n{uri}\n\n"
                "Collez cette URI dans l'application Android SelfishNet Companion.",
            )
        except Exception as exc:
            messagebox.showerror("Appairage Android", str(exc))

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
        self._run_async(lambda: f"Balayage terminé ({self.network.rescan()} appareil(s) actif(s)).", "Réseau")

    def safe_add(self):
        ips = self.selection()
        if not ips:
            self.say("Sélectionnez d'abord un ou plusieurs appareils à protéger.")
            return
        self._run_async(lambda: ([self.network.safe_add(ip) for ip in ips], f"{len(ips)} appareil(s) protégé(s).")[1], "Safe Mode")

    def safe_remove(self):
        ips = self.selection()
        if not ips:
            self.say("Sélectionnez d'abord un ou plusieurs appareils pour retirer la protection.")
            return
        self._run_async(lambda: ([self.network.safe_remove(ip) for ip in ips], f"{len(ips)} appareil(s) retiré(s).")[1], "Safe Mode")

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
            f"Mettre en pause {len(non_safe)} appareil(s) non protégé(s) ?\n\n"
            "• Votre machine, la passerelle et les appareils Safe Mode restent protégés.",
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
                    self.lbl_net.configure(text=f"Erreur : {msg}", fg=THEME["red"])
                    self.say(f"[Erreur] {msg}")
                    messagebox.showerror("SelfishNet Windows", msg)
                elif kind in ("log", "error_toast"):
                    self.say(msg)
        except queue.Empty:
            pass

        if self._ready:
            self.devices = self.network.snapshot()
            self.targets = self.network.summary()
            total_kbit = self.network.total_kbit()
            kpis = compute_kpis(self.devices, self.targets, total_kbit)
            update_kpi_bar(self.kpi_cards, kpis)
            self.sparkline.push(total_kbit)
            self.lbl_net.configure(
                text=f"Interface {self.network.iface}   ·   Mon PC : {self.network.my_ip}   ·   Box : {self.network.gateway}",
                fg=THEME["muted"],
            )
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
            elif d.get("is_self"):
                display_name = "Votre machine (Ce PC)"
            elif d.get("is_gateway"):
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
                state, tag = f"Limité ({human_rate_short(t.get('rate'))})", "limit"
            if t and t.get("remaining_sec") is not None:
                rem = t["remaining_sec"]
                rem_s = f"{rem // 60}m{rem % 60:02d}s" if rem >= 60 else f"{rem}s"
                state += f" [{rem_s}]"

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
        self.lbl_net.configure(text="Restauration du réseau et nettoyage des règles...", fg=THEME["yellow"])
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
