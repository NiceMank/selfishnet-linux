#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SelfishNet Core — composants partagés multi-plateformes (Linux, Windows, API Companion Android).

Uniquement basé sur la bibliothèque standard Python :
  * validation stricte des entrées (IPv4, MAC, interface, débit, cible Safe Mode) ;
  * résolution hors-ligne des fabricants (OUI) compatible PyInstaller ;
  * persistance JSON atomique (Safe Mode, alias d'appareils, état) ;
  * gestionnaire de minuteurs (règles temporaires avec libération automatique) ;
  * Token Bucket pour le bridage de débit logiciel ;
  * protocole IPC Unix robuste ;
  * serveur API REST authentifié (optionnel) pour le contrôle distant / app Android Companion.
"""

import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_NAME = "MyNet Filter"
VERSION = "1.1.0"

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_IFACE_LINUX_RE = re.compile(r"^[a-zA-Z0-9_.:@-]{1,15}$")
_IFACE_GENERIC_RE = re.compile(r"^[a-zA-Z0-9_.:@\\{}\-\s()]{1,128}$")

MAX_IPC_BYTES = 256 * 1024  # 256 Ko max par message IPC


# ------------------------------------------------------------------ chemins / assets
def resource_path(rel_path):
    """Résout un chemin de ressource (source directe, installation système ou bundle PyInstaller)."""
    candidates = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(os.path.join(meipass, rel_path))
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(here, rel_path))
    candidates.append(os.path.join("/usr/local/lib/selfishnet", rel_path))
    candidates.append(os.path.join("/usr/share/selfishnet", rel_path))
    for path in candidates:
        if os.path.exists(path):
            return path
    return os.path.join(here, rel_path)


# ------------------------------------------------------------------ validateurs stricts
def validate_ipv4(ip):
    """Valide une adresse IPv4 canonique et la retourne, sinon lève ValueError."""
    if not isinstance(ip, str):
        raise ValueError("Adresse IP invalide")
    text = ip.strip()
    if not text or any(c.isspace() for c in text):
        raise ValueError(f"Adresse IP invalide : {ip!r}")
    return str(ipaddress.IPv4Address(text))


def normalize_mac(mac):
    """Normalise une adresse MAC au format aa:bb:cc:dd:ee:ff, ou renvoie None si invalide."""
    if not mac or not isinstance(mac, str):
        return None
    cleaned = mac.strip().lower().replace("-", ":")
    if cleaned in ("?", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return None
    if _MAC_RE.fullmatch(cleaned):
        return cleaned
    return None


def is_valid_mac(mac):
    """Retourne True uniquement pour une adresse MAC unicast/valide (jamais '?' ou 00:00...)."""
    return normalize_mac(mac) is not None


def validate_iface(iface, linux_strict=True):
    """Valide un nom d'interface réseau pour prévenir toute injection d'argument."""
    if not iface or not isinstance(iface, str):
        raise ValueError("Nom d'interface manquant")
    name = iface.strip()
    pattern = _IFACE_LINUX_RE if linux_strict else _IFACE_GENERIC_RE
    if not pattern.fullmatch(name) or name.startswith("-"):
        raise ValueError(f"Nom d'interface invalide : {iface!r}")
    return name


def validate_rate(rate, min_kbit=16, max_kbit=10_000_000):
    """Valide un débit en kbit/s et renvoie un entier borné."""
    try:
        val = int(float(str(rate).replace(",", ".")))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Débit invalide : {rate!r}") from exc
    if val < min_kbit or val > max_kbit:
        raise ValueError(f"Le débit doit être compris entre {min_kbit} et {max_kbit} kbit/s")
    return val


def validate_safe_target(target):
    """Valide une cible Safe Mode (doit être une IPv4 valide OU une MAC valide)."""
    if not target or not isinstance(target, str):
        raise ValueError("Cible Safe Mode manquante")
    text = target.strip().lower()
    mac = normalize_mac(text)
    if mac:
        return mac
    try:
        return validate_ipv4(text)
    except ValueError as exc:
        raise ValueError(
            f"Cible invalide ({target!r}) : utilisez une adresse IPv4 ou une adresse MAC valide."
        ) from exc


# ------------------------------------------------------------------ formatage & tri
def human_rate(kbit):
    if kbit is None:
        return "illimité"
    if kbit >= 1000:
        return f"{kbit / 1000:.1f} Mbit/s"
    return f"{int(kbit)} kbit/s"


def human_rate_short(kbit):
    if kbit is None:
        return "—"
    if kbit >= 1000:
        return f"{kbit / 1000:.1f} Mb/s"
    return f"{kbit:.0f} kb/s"


def human_bytes(b):
    for unit in ("o", "Ko", "Mo", "Go"):
        if b < 1024:
            return f"{b:.0f} {unit}" if unit == "o" else f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} To"


def sort_key_ip(ip):
    try:
        return tuple(int(x) for x in str(ip).split("."))
    except Exception:
        return (999, 999, 999, 999)


# ------------------------------------------------------------------ persistance JSON
def load_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {} if default is None else default


def save_json_atomic(path, data):
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


# ------------------------------------------------------------------ OUI / fabricants
_OUI_CACHE = {}
_OUI_LOADED = False
_OUI_LOCK = threading.Lock()


def _load_oui_databases():
    global _OUI_LOADED
    with _OUI_LOCK:
        if _OUI_LOADED:
            return
        candidates = [
            "/usr/share/nmap/nmap-mac-prefixes",
            "/usr/share/ieee-data/oui.txt",
            resource_path(os.path.join("assets", "oui.txt")),
        ]
        for path in candidates:
            if not path or not os.path.isfile(path):
                continue
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(maxsplit=1)
                        if len(parts) == 2 and len(parts[0]) == 6:
                            key = parts[0].upper()
                            vendor = parts[1].strip()
                            for marker in ("(base 16)", "(hex)"):
                                if vendor.lower().startswith(marker):
                                    vendor = vendor[len(marker):].strip()
                            if vendor and key not in _OUI_CACHE:
                                _OUI_CACHE[key] = vendor
            except OSError:
                continue
        _OUI_LOADED = True


def get_vendor(mac):
    """Identifie le fabricant depuis l'adresse MAC (ou détecte les MAC aléatoires privées)."""
    norm = normalize_mac(mac)
    if not norm:
        return ""
    mac_clean = norm.replace(":", "")
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
        _load_oui_databases()
    return _OUI_CACHE.get(prefix, "")


# ------------------------------------------------------------------ alias & safe mode
class DeviceAliasStore:
    """Stocke les noms personnalisés d'appareils (indexés par MAC normalisée ou IP)."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.lock = threading.Lock()
        raw = load_json(filepath, default={})
        self._aliases = {str(k).lower(): str(v).strip() for k, v in raw.items() if str(v).strip()} if isinstance(raw, dict) else {}

    def get(self, mac=None, ip=None):
        with self.lock:
            norm = normalize_mac(mac) if mac else None
            if norm and norm in self._aliases:
                return self._aliases[norm]
            if ip and str(ip).lower() in self._aliases:
                return self._aliases[str(ip).lower()]
            return ""

    def set(self, key, name):
        clean_key = validate_safe_target(key)
        clean_name = str(name or "").strip()[:64]
        with self.lock:
            if not clean_name:
                self._aliases.pop(clean_key, None)
            else:
                self._aliases[clean_key] = clean_name
            save_json_atomic(self.filepath, dict(self._aliases))
        return clean_key, clean_name

    def all(self):
        with self.lock:
            return dict(self._aliases)


# ------------------------------------------------------------------ minuteurs de règles
class RuleTimerManager:
    """Gère les expirations automatiques de règles temporaires (pause/limit avec durée)."""

    def __init__(self, on_expire):
        self._on_expire = on_expire
        self._lock = threading.Lock()
        self._timers = {}     # ip -> (expiry_ts, threading.Timer)

    def set_timer(self, ip, duration_sec):
        self.cancel(ip)
        if not duration_sec or duration_sec <= 0:
            return None
        expiry = time.time() + float(duration_sec)
        timer = threading.Timer(float(duration_sec), self._fire, args=(ip,))
        timer.daemon = True
        with self._lock:
            self._timers[ip] = (expiry, timer)
        timer.start()
        return expiry

    def _fire(self, ip):
        with self._lock:
            self._timers.pop(ip, None)
        try:
            self._on_expire(ip)
        except Exception:
            pass

    def cancel(self, ip):
        with self._lock:
            entry = self._timers.pop(ip, None)
        if entry:
            entry[1].cancel()

    def cancel_all(self):
        with self._lock:
            entries = list(self._timers.values())
            self._timers.clear()
        for _, timer in entries:
            timer.cancel()

    def remaining(self, ip):
        with self._lock:
            entry = self._timers.get(ip)
            if not entry:
                return None
            rem = entry[0] - time.time()
            return max(0, int(rem))

    def snapshot(self):
        now = time.time()
        with self._lock:
            return {ip: max(0, int(exp - now)) for ip, (exp, _) in self._timers.items()}


# ------------------------------------------------------------------ token bucket
class TokenBucket:
    """Seau à jetons thread-safe pour plafonner le débit en octets/seconde."""

    def __init__(self, rate_kbit, burst_seconds=0.25):
        self.lock = threading.Lock()
        self.rate_bps = max(2000.0, float(rate_kbit) * 1000.0 / 8.0)
        self.capacity = max(3000.0, self.rate_bps * burst_seconds)
        self.tokens = self.capacity
        self.last = time.monotonic()

    def update_rate(self, rate_kbit):
        with self.lock:
            self.rate_bps = max(2000.0, float(rate_kbit) * 1000.0 / 8.0)
            self.capacity = max(3000.0, self.rate_bps * 0.25)
            self.tokens = min(self.tokens, self.capacity)

    def consume(self, nbytes):
        now = time.monotonic()
        with self.lock:
            elapsed = max(0.0, now - self.last)
            self.last = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_bps)
            if self.tokens >= nbytes:
                self.tokens -= nbytes
                return True
            return False


# ------------------------------------------------------------------ IPC Unix robuste
def recv_line(conn, max_bytes=MAX_IPC_BYTES):
    """Lit une ligne JSON terminée par '\\n' depuis un socket, avec borne mémoire."""
    chunks = []
    total = 0
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ValueError("Message IPC trop volumineux")
        nl = chunk.find(b"\n")
        if nl != -1:
            chunks.append(chunk[:nl])
            break
        chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace").strip()


def ipc_request(sock_file, payload, timeout=15):
    """Envoie une requête JSON sur le socket Unix du démon et renvoie le dict de réponse."""
    sock = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(sock_file)
        sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        raw = recv_line(sock)
        return json.loads(raw or "{}")
    except (FileNotFoundError, ConnectionRefusedError):
        return {"error": "daemon_absent"}
    except PermissionError:
        return {"error": "permission_denied"}
    except socket.timeout:
        return {"error": "timeout"}
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


# ------------------------------------------------------------------ API REST Companion (Android / Web)
class RemoteAPIServer:
    """Serveur HTTP JSON léger et authentifié (Bearer token) pour pilotage distant / App Android Companion."""

    def __init__(self, handler_fn, host="127.0.0.1", port=8443, token=None, device_name=APP_NAME):
        self.handler_fn = handler_fn
        self.host = host
        self.port = int(port)
        self.token = token or secrets.token_urlsafe(32)
        self.device_name = device_name
        self._httpd = None
        self._thread = None

    def pairing_uri(self, advertise_ip=None):
        host = advertise_ip or self.host
        params = urllib.parse.urlencode({
            "host": host,
            "port": str(self.port),
            "token": self.token,
            "name": self.device_name,
            "v": "1",
        })
        return f"selfishnet://pair?{params}"

    def start(self):
        api_ref = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def _send_json(self, code, payload):
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def _authorized(self):
                auth = self.headers.get("Authorization", "")
                if not auth.startswith("Bearer "):
                    return False
                provided = auth[7:].strip()
                return hmac.compare_digest(provided, api_ref.token)

            def _read_json(self):
                length = int(self.headers.get("Content-Length", "0") or "0")
                if length <= 0:
                    return {}
                if length > MAX_IPC_BYTES:
                    raise ValueError("Payload trop volumineux")
                raw = self.rfile.read(length)
                return json.loads(raw.decode("utf-8"))

            def do_GET(self):
                path = urllib.parse.urlparse(self.path).path
                if path == "/api/v1/health":
                    self._send_json(200, {"ok": True, "version": VERSION, "name": api_ref.device_name})
                    return
                if not self._authorized():
                    self._send_json(401, {"error": "unauthorized"})
                    return
                if path == "/api/v1/status":
                    self._send_json(200, api_ref.handler_fn({"cmd": "status"}))
                    return
                if path == "/api/v1/safe":
                    self._send_json(200, api_ref.handler_fn({"cmd": "safe_list"}))
                    return
                if path == "/api/v1/aliases":
                    self._send_json(200, api_ref.handler_fn({"cmd": "alias_list"}))
                    return
                self._send_json(404, {"error": "not_found"})

            def do_POST(self):
                if not self._authorized():
                    self._send_json(401, {"error": "unauthorized"})
                    return
                path = urllib.parse.urlparse(self.path).path
                try:
                    body = self._read_json()
                except Exception as exc:
                    self._send_json(400, {"error": f"JSON invalide : {exc}"})
                    return

                route_map = {
                    "/api/v1/rescan": lambda b: {"cmd": "rescan"},
                    "/api/v1/set": lambda b: {
                        "cmd": "set",
                        "targets": b.get("targets", ""),
                        "mode": b.get("mode", "pause"),
                        "rate": b.get("rate"),
                        "duration": b.get("duration"),
                    },
                    "/api/v1/free_all": lambda b: {"cmd": "free_all"},
                    "/api/v1/safe/add": lambda b: {"cmd": "safe_add", "target": b.get("target")},
                    "/api/v1/safe/remove": lambda b: {"cmd": "safe_remove", "target": b.get("target")},
                    "/api/v1/aliases/set": lambda b: {
                        "cmd": "alias_set",
                        "target": b.get("target"),
                        "name": b.get("name", ""),
                    },
                }
                builder = route_map.get(path)
                if not builder:
                    self._send_json(404, {"error": "not_found"})
                    return
                resp = api_ref.handler_fn(builder(body))
                status_code = 400 if resp.get("error") else 200
                self._send_json(status_code, resp)

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True, name="SelfishNetAPI")
        self._thread.start()
        return self.port

    def stop(self):
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None
