#!/usr/bin/env python3
"""
Tkinter frontend for the native Windows backend.
"""

import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from selfishnet_windows import WindowsNetwork


class App:
    def __init__(self, root):
        self.root = root
        self.network = WindowsNetwork()
        self.queue = queue.Queue()
        self.selected_ip = None

        root.title("SelfishNet Windows")
        root.geometry("900x560")
        root.minsize(760, 440)
        root.protocol("WM_DELETE_WINDOW", self.quit_app)

        ttk.Label(root, text="SelfishNet Windows", font=("TkDefaultFont", 16, "bold")).pack(
            anchor="w", padx=16, pady=(12, 4)
        )
        self.status = tk.StringVar(value="Initialisation...")
        ttk.Label(root, textvariable=self.status).pack(anchor="w", padx=16)

        columns = ("ip", "mac", "last", "packets", "state")
        self.tree = ttk.Treeview(root, columns=columns, show="headings", height=18)
        labels = ("Adresse IP", "MAC", "Vu il y a", "Paquets", "Etat")
        widths = (150, 190, 100, 100, 150)
        for column, label, width in zip(columns, labels, widths):
            self.tree.heading(column, text=label)
            self.tree.column(column, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=16, pady=12)
        self.tree.bind("<<TreeviewSelect>>", self.select_device)

        controls = ttk.Frame(root)
        controls.pack(fill="x", padx=16, pady=(0, 12))
        ttk.Button(controls, text="Mettre en pause", command=self.pause_selected).pack(side="left")
        ttk.Button(controls, text="Libérer", command=self.free_selected).pack(side="left", padx=8)
        ttk.Button(controls, text="Tout libérer", command=self.free_all).pack(side="left")
        ttk.Button(controls, text="Actualiser", command=self.refresh_async).pack(side="right")

        threading.Thread(target=self.initialize, daemon=True).start()
        root.after(1000, self.tick)

    def initialize(self):
        try:
            self.network.initialize()
            self.queue.put(("ok", "Npcap actif - interface " + str(self.network.iface)))
        except Exception as exc:
            self.queue.put(("error", str(exc)))

    def tick(self):
        try:
            kind, message = self.queue.get_nowait()
            self.status.set(message)
            if kind == "error":
                messagebox.showerror("SelfishNet Windows", message)
        except queue.Empty:
            pass
        self.refresh_async()
        self.root.after(1500, self.tick)

    def refresh_async(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for device in self.network.snapshot():
            targets = self.network.summary()
            target = targets.get(device["ip"])
            state = "Normal"
            if device["is_self"]:
                state = "Cette machine"
            elif device["is_gateway"]:
                state = "Passerelle"
            if target:
                state = "Bloqué"
            self.tree.insert("", "end", values=(
                device["ip"],
                device["mac"],
                f"{device['age']:.0f} s",
                device["packets"],
                state,
            ))

    def select_device(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            self.selected_ip = None
            return
        values = self.tree.item(selection[0], "values")
        self.selected_ip = values[0]

    def pause_selected(self):
        if not self.selected_ip:
            messagebox.showwarning("SelfishNet Windows", "Sélectionnez un appareil.")
            return
        try:
            self.network.set_pause(self.selected_ip)
            self.status.set(f"{self.selected_ip} bloqué")
        except Exception as exc:
            messagebox.showerror("SelfishNet Windows", str(exc))

    def free_selected(self):
        if not self.selected_ip:
            messagebox.showwarning("SelfishNet Windows", "Sélectionnez un appareil.")
            return
        try:
            self.network.set_free(self.selected_ip)
            self.status.set(f"{self.selected_ip} libéré")
        except Exception as exc:
            messagebox.showerror("SelfishNet Windows", str(exc))

    def free_all(self):
        try:
            self.network.free_all_targets()
            self.status.set("Tous les appareils sont libérés")
        except Exception as exc:
            messagebox.showerror("SelfishNet Windows", str(exc))

    def quit_app(self):
        self.network.stop()
        self.root.destroy()


def main():
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        sys.exit(f"Impossible d'ouvrir l'interface: {exc}")
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
