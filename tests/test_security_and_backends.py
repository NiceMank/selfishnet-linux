import json
import os
import sys
import time
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import selfishnet as sn
import selfishnet_core as core
import selfishnet_windows as snw


# ------------------------------------------------------------------ Validation & Security
def test_validators_reject_command_injection():
    for bad_ip in ("127.0.0.1; id", "192.168.1.1 && whoami", "$(id)", "999.1.1.1", ""):
        with pytest.raises(ValueError):
            core.validate_ipv4(bad_ip)

    for bad_iface in ("eth0; rm -rf /", "-rf", "wlan0 | id", "", "a" * 30):
        with pytest.raises(ValueError):
            core.validate_iface(bad_iface, linux_strict=True)

    for bad_target in ("127.0.0.1; id > /tmp/pwn", "?", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "$(reboot)"):
        with pytest.raises(ValueError):
            core.validate_safe_target(bad_target)

    assert core.validate_ipv4("192.168.1.42") == "192.168.1.42"
    assert core.normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert core.normalize_mac("?") is None
    assert core.normalize_mac("00:00:00:00:00:00") is None
    assert core.validate_safe_target("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert core.validate_iface("wlan0", linux_strict=True) == "wlan0"


def test_run_never_uses_shell_true():
    with patch("selfishnet.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        rc, out = sn.run("ip -4 route show default")
        assert rc == 0
        assert out == "ok"
        _, kwargs = mock_run.call_args
        assert kwargs.get("shell") is False
        args_passed = mock_run.call_args.args[0]
        assert args_passed == ["ip", "-4", "route", "show", "default"]


def test_daemon_safe_add_rejects_injection(tmp_path):
    d = object.__new__(sn.Daemon)
    d.my_ip = "192.168.1.10"
    d.my_mac = "aa:bb:cc:dd:ee:01"
    d.gw_ip = "192.168.1.1"
    d.gw_mac = "aa:bb:cc:dd:ee:ff"
    d.safe_file = str(tmp_path / "safe.json")
    d.safe_targets = set()
    d._safe_lock = sn.threading.Lock()
    d.timers = core.RuleTimerManager(lambda _ip: None)
    d.enf = MagicMock()

    with patch("selfishnet.arp_lookup") as mock_arp:
        resp = d.handle({"cmd": "safe_add", "target": "192.168.1.5; id > /tmp/pwned"})
        assert "error" in resp
        mock_arp.assert_not_called()
        assert len(d.safe_targets) == 0


# ------------------------------------------------------------------ Bundled OUI, Aliases, Timers, TokenBucket
def test_bundled_oui_lookup():
    core._OUI_LOADED = False
    core._OUI_CACHE.clear()
    assert "Freebox" in core.get_vendor("00:07:cb:11:22:33")
    assert "Raspberry Pi" in core.get_vendor("b8:27:eb:aa:bb:cc")
    assert core.get_vendor("?") == ""

    # Verify fallback to bundled assets/oui.txt works when Linux system OUI files are absent (Windows)
    core._OUI_LOADED = False
    core._OUI_CACHE.clear()
    orig_isfile = os.path.isfile
    with patch("selfishnet_core.os.path.isfile", side_effect=lambda p: False if str(p).startswith("/usr/share/") else orig_isfile(p)):
        assert core.get_vendor("00:07:cb:11:22:33") == "Freebox"
        assert core.get_vendor("b8:27:eb:aa:bb:cc") == "Raspberry Pi"


def test_device_alias_store(tmp_path):
    store = core.DeviceAliasStore(str(tmp_path / "aliases.json"))
    key, name = store.set("AA:BB:CC:DD:EE:11", "TV Salon")
    assert key == "aa:bb:cc:dd:ee:11"
    assert name == "TV Salon"
    assert store.get(mac="aa:bb:cc:dd:ee:11") == "TV Salon"

    # Reload from disk
    store2 = core.DeviceAliasStore(str(tmp_path / "aliases.json"))
    assert store2.get(mac="aa:bb:cc:dd:ee:11") == "TV Salon"
    store2.set("aa:bb:cc:dd:ee:11", "")
    assert store2.get(mac="aa:bb:cc:dd:ee:11") == ""


def test_rule_timer_manager_fires_and_cancels():
    expired = []
    mgr = core.RuleTimerManager(lambda ip: expired.append(ip))
    mgr.set_timer("192.168.1.50", 0.05)
    mgr.set_timer("192.168.1.51", 5.0)
    mgr.cancel("192.168.1.51")
    time.sleep(0.15)
    assert expired == ["192.168.1.50"]
    assert mgr.remaining("192.168.1.51") is None
    mgr.cancel_all()


def test_token_bucket_throttling():
    bucket = core.TokenBucket(rate_kbit=100, burst_seconds=0.25)
    # Initial capacity is max(3000, 12500*0.25 = 3125 bytes)
    assert bucket.consume(2000) is True
    assert bucket.consume(2000) is False  # exceeds remaining tokens immediately


# ------------------------------------------------------------------ Remote API Server (Android Companion)
def test_remote_api_server_auth_and_routes():
    calls = []

    def fake_handler(req):
        calls.append(req)
        if req.get("cmd") == "status":
            return {"ok": True, "devices": [{"ip": "192.168.1.2"}]}
        return {"ok": True, "echo": req}

    api = core.RemoteAPIServer(fake_handler, host="127.0.0.1", port=0, token="secret-test-token")
    port = api.start()
    try:
        base = f"http://127.0.0.1:{port}"
        assert "selfishnet://pair?" in api.pairing_uri("192.168.1.10")

        # Public health check
        with urllib.request.urlopen(f"{base}/api/v1/health", timeout=5) as resp:
            data = json.loads(resp.read().decode())
            assert data["ok"] is True

        # Unauthorized without Bearer token
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{base}/api/v1/status", timeout=5)
        assert exc_info.value.code == 401

        # Authorized GET status
        req = urllib.request.Request(
            f"{base}/api/v1/status",
            headers={"Authorization": "Bearer secret-test-token"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            assert data["ok"] is True
            assert data["devices"][0]["ip"] == "192.168.1.2"

        # Authorized POST set with duration
        post_req = urllib.request.Request(
            f"{base}/api/v1/set",
            data=json.dumps({"targets": "192.168.1.2", "mode": "pause", "duration": 120}).encode(),
            headers={
                "Authorization": "Bearer secret-test-token",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(post_req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            assert data["ok"] is True
            assert data["echo"]["duration"] == 120
    finally:
        api.stop()


# ------------------------------------------------------------------ Linux Discovery & Enforcer
def test_discovery_subnet_broadcast_and_no_subprocess_in_snapshot():
    disc = sn.Discovery("eth0", "192.168.0.10", "192.168.0.1", netmask=23, my_mac="aa:bb:cc:dd:ee:01")
    # In 192.168.0.0/23, 192.168.0.255 is a VALID host, 192.168.1.255 is broadcast!
    assert disc._is_local_host("192.168.0.255") is True
    assert disc._is_local_host("192.168.1.255") is False
    assert disc._is_local_host("8.8.8.8") is False

    disc.devices["192.168.0.50"] = {"mac": None, "first": time.time(), "last": time.time(), "pkts": 1, "bytes": 100}
    with patch("selfishnet.read_proc_arp", return_value={}), patch("selfishnet.run") as mock_run:
        rows = disc.snapshot()
        mock_run.assert_not_called()
        # Internal device MAC stays None (not corrupted with '?'), while display shows '?'
        assert disc.devices["192.168.0.50"]["mac"] is None
        row = next(r for r in rows if r["ip"] == "192.168.0.50")
        assert row["mac"] == "?"


def test_enforcer_rejects_question_mark_mac_and_fallback_xt_mac(monkeypatch):
    monkeypatch.setattr(sn, "MAC_MATCH", True)
    enf = sn.Enforcer("eth0", "192.168.1.10", "aa:bb:cc:dd:ee:01", "192.168.1.1", "aa:bb:cc:dd:ee:ff", 24)
    enf._chain_ready = True
    enf._mangle_ready = True

    with patch.object(enf, "_refresh_rules"):
        enf.set_targets_batch([("192.168.1.20", "?"), ("192.168.1.21", "11:22:33:44:55:66")], "pause")
    assert "192.168.1.20" not in enf.targets
    assert "192.168.1.21" in enf.targets

    # Simulate iptables-restore failing when -m mac is present, succeeding without it
    def fake_restore(cmd, input="", **kwargs):
        if "-m mac" in input:
            return MagicMock(returncode=2, stderr="Couldn't load match mac")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("selfishnet.iptables_available", return_value=True), \
         patch("selfishnet.subprocess.run", side_effect=fake_restore):
        enf._apply_drop(dict(enf.targets))
    assert sn.MAC_MATCH is False
    assert any("règle MAC non supportée" in e for e in enf.errors)


def test_parser_safe_and_alias_without_subcommand():
    parser = sn.build_parser()
    args_safe = parser.parse_args(["safe"])
    assert callable(args_safe.func)
    args_alias = parser.parse_args(["alias"])
    assert callable(args_alias.func)
    args_dur = parser.parse_args(["pause", "2", "--duration", "300"])
    assert args_dur.duration == 300
    args_json = parser.parse_args(["status", "--json"])
    assert args_json.json is True


# ------------------------------------------------------------------ Windows Backend Fixes
def test_windows_clear_rules_locale_independent():
    with patch("selfishnet_windows.run_powershell", return_value=(0, "4")) as mock_ps:
        rc, msg = snw.clear_selfishnet_rules()
        assert rc == 0
        assert "4 règle(s)" in msg
        mock_ps.assert_called_once()


def test_windows_network_filters_public_ips_and_protects_self_and_gateway(tmp_path):
    net = snw.WindowsNetwork(state_dir=str(tmp_path))
    net.my_ip = "192.168.1.10"
    net.my_mac = "aa:bb:cc:dd:ee:01"
    net.gateway = "192.168.1.1"
    net.gateway_mac = "aa:bb:cc:dd:ee:ff"
    net.net = snw.ipaddress.IPv4Network("192.168.1.0/24")
    net._broadcast = "192.168.1.255"

    # Public Internet IPs must be rejected
    assert net._is_local_host("8.8.8.8") is False
    assert net._is_local_host("142.250.179.78") is False
    assert net._is_local_host("192.168.1.255") is False
    assert net._is_local_host("192.168.1.42") is True

    # Self & gateway cannot be paused or limited
    with pytest.raises(ValueError):
        net.set_pause("192.168.1.10")
    with pytest.raises(ValueError):
        net.set_pause("192.168.1.1")
    with pytest.raises(ValueError):
        net.set_limit("192.168.1.1", 200)

    # Safe Mode protects user-added targets
    net.safe_add("192.168.1.42")
    with pytest.raises(ValueError):
        net.set_pause("192.168.1.42")


def test_windows_poison_packet_uses_my_mac_as_eth_src_and_resolves_unknown_mac(tmp_path):
    net = snw.WindowsNetwork(state_dir=str(tmp_path))
    net.my_ip = "192.168.1.10"
    net.my_mac = "aa:bb:cc:dd:ee:01"
    net.gateway = "192.168.1.1"
    net.gateway_mac = "aa:bb:cc:dd:ee:ff"
    net.net = snw.ipaddress.IPv4Network("192.168.1.0/24")
    net.devices["192.168.1.50"] = {"ip": "192.168.1.50", "mac": "?", "last": time.time(), "packets": 1, "bytes": 60}

    # Verify set_pause resolves MAC when stored MAC is '?'
    with patch.object(net, "resolve_mac", return_value="11:22:33:44:55:66") as mock_res, \
         patch("selfishnet_windows.pause_ip", return_value=True):
        net.set_pause("192.168.1.50")
        mock_res.assert_called_once_with("192.168.1.50")
        assert net.targets["192.168.1.50"]["mac"] == "11:22:33:44:55:66"

    # Verify ARP poison Ethernet frames use src=my_mac for BOTH frames
    eth_calls = []

    class FakeLayer:
        def __init__(self, **kw):
            self.kw = kw

        def __truediv__(self, other):
            return (self.kw, other.kw)

    def fake_ether(**kw):
        eth_calls.append(kw)
        return FakeLayer(**kw)

    net._Ether = fake_ether
    net._ARP = FakeLayer
    pkts = net._build_poison_packets("192.168.1.50", "11:22:33:44:55:66")
    assert len(pkts) == 2
    assert eth_calls[0] == {"dst": "11:22:33:44:55:66", "src": "aa:bb:cc:dd:ee:01"}
    assert eth_calls[1] == {"dst": "aa:bb:cc:dd:ee:ff", "src": "aa:bb:cc:dd:ee:01"}


def test_windows_snapshot_numeric_ip_sort(tmp_path):
    net = snw.WindowsNetwork(state_dir=str(tmp_path))
    net.my_ip = "192.168.1.5"
    net.gateway = "192.168.1.1"
    net.net = snw.ipaddress.IPv4Network("192.168.1.0/24")
    now = time.time()
    for ip in ("192.168.1.10", "192.168.1.2", "192.168.1.5", "192.168.1.1"):
        net.devices[ip] = {"ip": ip, "mac": "00:07:cb:00:00:01", "last": now, "packets": 1, "bytes": 64}
    rows = net.snapshot()
    assert [r["ip"] for r in rows] == ["192.168.1.5", "192.168.1.1", "192.168.1.2", "192.168.1.10"]
    assert "Freebox" in rows[0]["vendor"]
