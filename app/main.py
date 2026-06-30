import subprocess, json, time, re, os, http.client, socket as _socket
from typing import Optional

import psutil
import cpuinfo
from fastapi import FastAPI, Body
from fastapi.staticfiles import StaticFiles

app = FastAPI()

HOST_ROOT = os.environ.get("HOST_ROOT", "")
_net_last = {"t": 0.0, "bytes_sent": 0, "bytes_recv": 0}
_PHYS_IFACE = re.compile(r"^(eth|en[ps]|wlan|wlp|bond|ens)\d")
_hw_cache: dict = {}
_hw_cache_ts = 0.0
HW_TTL = 60.0

SKIP_FS = {
    "tmpfs", "devtmpfs", "sysfs", "proc", "cgroup", "cgroup2",
    "pstore", "securityfs", "debugfs", "configfs", "fusectl",
    "hugetlbfs", "mqueue", "devpts", "overlay", "aufs", "squashfs",
    "nsfs", "rpc_pipefs", "nfsd", "bpf", "tracefs",
}


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        # smartctl peut retourner des codes non-zéro (erreurs disque) mais avec JSON valide
        return r.stdout.decode(errors="ignore")
    except Exception:
        return ""


# ──────────────────────────────────────────────────────────── SMART ──

def _smartctl_all() -> dict:
    """Scanne tous les disques physiques via lsblk puis smartctl."""
    result = {}
    try:
        raw = _run(["lsblk", "-J", "-d", "-o", "NAME,TYPE"])
        disks = [d["name"] for d in json.loads(raw).get("blockdevices", [])
                 if d.get("type") == "disk"]
    except Exception:
        disks = []

    for name in disks:
        dev = f"/dev/{name}"
        # Essayer en direct, puis avec -d sat pour disques derrière contrôleur
        raw = _run(["smartctl", "-a", "-j", dev])
        if not raw:
            raw = _run(["smartctl", "-a", "-j", "-d", "sat", dev])
        if not raw:
            continue
        try:
            info = json.loads(raw)
        except Exception:
            continue
        # Capacité : NVMe utilise nvme_smart_health_information_log
        cap = info.get("user_capacity", {}).get("bytes") or \
              info.get("nvme_smart_health_information_log", {}).get("total_data_units_written", None)
        # Température NVMe
        temp = info.get("temperature", {}).get("current") or \
               info.get("nvme_smart_health_information_log", {}).get("temperature", None)
        if temp is not None:
            temp = temp - 273 if temp > 200 else temp  # certains firmwares donnent Kelvin
        # Attributs critiques ATA (id→valeur brute)
        ata_attrs = {}
        for attr in info.get("ata_smart_attributes", {}).get("table", []):
            ata_attrs[attr["id"]] = attr.get("raw", {}).get("value", 0)

        result[dev] = {
            "device": name,
            "model": info.get("model_name", info.get("model_family", "")),
            "serial": info.get("serial_number", ""),
            "health": info.get("smart_status", {}).get("passed", None),
            "temp_c": temp,
            "capacity_bytes": info.get("user_capacity", {}).get("bytes", None),
            "rotation_rate": info.get("rotation_rate", None),
            "power_on_hours": info.get("power_on_time", {}).get("hours", None),
            # attributs critiques
            "reallocated_sectors": ata_attrs.get(5, None),
            "pending_sectors": ata_attrs.get(197, None),
            "uncorrectable": ata_attrs.get(198, None),
            "ata_errors": info.get("ata_smart_error_log", {}).get("summary", {}).get("count", None),
        }
    return result


# ──────────────────────────────────────────────────────────── RAID ──

def _parse_mdstat() -> list[dict]:
    """Parse /proc/mdstat pour l'état des arrays RAID."""
    try:
        with open("/proc/mdstat") as f:
            content = f.read()
    except Exception:
        return []

    arrays = []
    # Chercher chaque ligne "mdXXX : ..." directement (évite le problème du bloc Personalities)
    all_lines = content.split("\n")
    i = 0
    while i < len(all_lines):
        m = re.match(r"(md\d+)\s*:\s*(\w+)\s+(\S+)\s+(.*)", all_lines[i])
        if not m:
            i += 1
            continue
        # Rassembler les lignes du bloc jusqu'à la prochaine ligne vide ou prochain md
        lines = [all_lines[i]]
        i += 1
        while i < len(all_lines) and all_lines[i].strip() and not re.match(r"md\d+\s*:", all_lines[i]):
            lines.append(all_lines[i])
            i += 1

        name = m.group(1)
        state = m.group(2)
        level = m.group(3)
        members_raw = m.group(4)

        members = []
        for mem in re.finditer(r"(\w+)\[(\d+)\](\(\w\))?", members_raw):
            flag = mem.group(3) or ""
            mstate = "faulty" if "(F)" in flag else ("spare" if "(S)" in flag else "active")
            members.append({"device": mem.group(1), "state": mstate})

        total_devs = active_devs = 0
        disk_status = ""
        size_bytes = 0
        sync_action = sync_pct = sync_speed = None

        for line in lines[1:]:
            line = line.strip()
            if "blocks" in line:
                bm = re.search(r"\[(\d+)/(\d+)\]", line)
                sm = re.search(r"\[([U_]+)\]", line)
                km = re.search(r"^(\d+)\s+blocks", line)
                if bm: total_devs, active_devs = int(bm.group(1)), int(bm.group(2))
                if sm: disk_status = sm.group(1)
                if km: size_bytes = int(km.group(1)) * 1024
            elif re.search(r"(resync|recovery|reshape|check)\s*=", line):
                am = re.search(r"(resync|recovery|reshape|check)", line)
                pm = re.search(r"=\s*([\d.]+)%", line)
                vm = re.search(r"speed=(\S+)", line)
                if am: sync_action = am.group(1)
                if pm: sync_pct = float(pm.group(1))
                if vm: sync_speed = vm.group(1)

        degraded = "_" in disk_status
        arrays.append({
            "name": name, "state": state, "level": level,
            "members": members, "total_devs": total_devs, "active_devs": active_devs,
            "disk_status": disk_status, "size_bytes": size_bytes, "degraded": degraded,
            "sync_action": sync_action, "sync_pct": sync_pct, "sync_speed": sync_speed,
        })

    return sorted(arrays, key=lambda x: x["name"])


# ─────────────────────────────────────────────────── HARDWARE CACHE ──

def _dmidecode_memory() -> list[dict]:
    out = _run(["dmidecode", "-t", "17"])
    if not out:
        return []
    sticks = []
    for block in out.split("\nMemory Device\n"):
        if "Size:" not in block:
            continue
        def get(k):
            m = re.search(rf"\t{k}:\s*(.+)", block)
            return m.group(1).strip() if m else ""
        size_str = get("Size")
        if size_str in ("", "No Module Installed", "Unknown"):
            continue
        sticks.append({
            "size": size_str,
            "type": get("Type"),
            "speed": get("Speed"),
            "manufacturer": get("Manufacturer"),
            "part_number": get("Part Number").strip(),
            "locator": get("Locator"),
        })
    return sticks


def _dmidecode_board() -> dict:
    out = _run(["dmidecode", "-t", "2"])
    def get(k):
        m = re.search(rf"\t{k}:\s*(.+)", out)
        return m.group(1).strip() if m else ""
    return {"manufacturer": get("Manufacturer"), "product": get("Product Name")}


def get_hardware() -> dict:
    global _hw_cache, _hw_cache_ts
    if time.time() - _hw_cache_ts < HW_TTL and _hw_cache:
        return _hw_cache
    cpu = cpuinfo.get_cpu_info()
    _hw_cache = {
        "cpu": {
            "brand": cpu.get("brand_raw", ""),
            "arch": cpu.get("arch", ""),
            "hz_advertised": cpu.get("hz_advertised_friendly", ""),
            "cores_physical": psutil.cpu_count(logical=False),
            "cores_logical": psutil.cpu_count(logical=True),
        },
        "board": _dmidecode_board(),
        "memory_sticks": _dmidecode_memory(),
        "smart": _smartctl_all(),
    }
    _hw_cache_ts = time.time()
    return _hw_cache


# ──────────────────────────────────────────────────────────── DISKS ──

def _flatten_lsblk(dev: dict, result: list | None = None) -> list:
    if result is None:
        result = []
    result.append(dev)
    for child in dev.get("children", []):
        _flatten_lsblk(child, result)
    return result


def _read_host_disks() -> list[dict]:
    try:
        raw = _run(["lsblk", "-J", "-b", "-o",
                    "NAME,SIZE,TYPE,MOUNTPOINT,MOUNTPOINTS,FSTYPE,LABEL"])
        data = json.loads(raw)
    except Exception:
        return []

    result = []
    seen_mp: set = set()

    for dev in data.get("blockdevices", []):
        for item in _flatten_lsblk(dev):
            if item.get("type") in ("loop", "rom", "sr"):
                continue
            fstype = item.get("fstype") or ""
            if fstype in SKIP_FS:
                continue

            mps = list(item.get("mountpoints") or [])
            mp = item.get("mountpoint")
            if mp and mp not in mps:
                mps.insert(0, mp)
            mps = [m for m in mps if m and m not in ("[SWAP]", "")]

            for mountpoint in mps:
                if HOST_ROOT:
                    if not mountpoint.startswith(HOST_ROOT + "/") and mountpoint != HOST_ROOT:
                        continue
                    display_mp = mountpoint[len(HOST_ROOT):] or "/"
                    real_path = mountpoint
                else:
                    display_mp = mountpoint
                    real_path = mountpoint

                if display_mp in seen_mp:
                    continue
                try:
                    st = os.statvfs(real_path)
                    total = st.f_blocks * st.f_frsize
                    if total == 0:
                        continue
                    free = st.f_bavail * st.f_frsize
                    used = total - st.f_bfree * st.f_frsize
                    pct = round(used / total * 100, 1) if total else 0
                    seen_mp.add(display_mp)
                    result.append({
                        "device": "/dev/" + item["name"],
                        "mountpoint": display_mp,
                        "fstype": fstype,
                        "label": item.get("label") or "",
                        "total": total,
                        "used": used,
                        "free": free,
                        "percent": pct,
                    })
                except Exception:
                    continue

    return result


# ───────────────────────────────────────────────────────────── LIVE ──

def get_live() -> dict:
    global _net_last

    cpu_percent = psutil.cpu_percent(interval=0.3)
    cpu_freq = psutil.cpu_freq()
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disks = _read_host_disks()

    # Trafic réseau : ne sommer que les interfaces physiques (exclut br-, veth, docker0…)
    per_nic = psutil.net_io_counters(pernic=True)
    phys = {k: v for k, v in per_nic.items() if _PHYS_IFACE.match(k)}
    recv_total = sum(v.bytes_recv for v in phys.values())
    sent_total = sum(v.bytes_sent for v in phys.values())
    now = time.time()
    dt = now - _net_last["t"] if _net_last["t"] else 1.0
    dl = (recv_total - _net_last["bytes_recv"]) / dt if _net_last["t"] else 0
    ul = (sent_total - _net_last["bytes_sent"]) / dt if _net_last["t"] else 0
    _net_last = {"t": now, "bytes_sent": sent_total, "bytes_recv": recv_total}

    # Interfaces physiques uniquement pour l'affichage
    net_ifaces = {}
    stats = psutil.net_if_stats()
    for iface, addrs in psutil.net_if_addrs().items():
        if not _PHYS_IFACE.match(iface):
            continue
        for a in addrs:
            if a.family == 2:
                up = stats.get(iface, None)
                net_ifaces[iface] = {"ip": a.address, "up": bool(up and up.isup)}
                break

    uptime_s = int(time.time() - psutil.boot_time())

    temps = {}
    try:
        for name, entries in psutil.sensors_temperatures().items():
            if entries:
                temps[name] = [
                    {"label": e.label or name, "current": e.current,
                     "high": e.high, "critical": e.critical}
                    for e in entries
                ]
    except Exception:
        pass

    return {
        "ts": int(now),
        "uptime_s": uptime_s,
        "cpu": {
            "percent": cpu_percent,
            "percent_per_core": psutil.cpu_percent(interval=None, percpu=True),
            "freq_mhz": round(cpu_freq.current, 0) if cpu_freq else None,
            "freq_max_mhz": round(cpu_freq.max, 0) if cpu_freq else None,
        },
        "memory": {
            "total": mem.total, "available": mem.available, "used": mem.used,
            "percent": mem.percent,
            "buffers": getattr(mem, "buffers", 0),
            "cached": getattr(mem, "cached", 0),
        },
        "swap": {"total": swap.total, "used": swap.used, "percent": swap.percent},
        "disks": disks,
        "network": {
            "dl_bps": max(0.0, dl),
            "ul_bps": max(0.0, ul),
            "total_recv": recv_total,
            "total_sent": sent_total,
            "interfaces": net_ifaces,
        },
        "temperatures": temps,
    }


# ──────────────────────────────────────────────────────────── ROUTES ──

_os_cache: dict = {}


def _get_os_info() -> dict:
    uname = os.uname()
    os_name = _run(["lsb_release", "-ds"]).strip()
    if not os_name:
        try:
            with open(HOST_ROOT + "/etc/os-release" if HOST_ROOT else "/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        os_name = line.split("=", 1)[1].strip().strip('"')
                        break
        except Exception:
            os_name = uname.sysname
    return {"hostname": uname.nodename, "os": os_name,
            "kernel": uname.release, "arch": uname.machine}


@app.get("/api/os")
def api_os():
    global _os_cache
    if not _os_cache:
        _os_cache = _get_os_info()
    return _os_cache


@app.get("/api/hardware")
def api_hardware():
    return get_hardware()


@app.get("/api/live")
def api_live():
    return get_live()


@app.get("/api/raid")
def api_raid():
    return _parse_mdstat()


# ──────────────────────────────────────────────────────────── NETMAP ──

NETMAP_DATA = "/app/netmap_devices.json"
NETMAP_RANGE = "192.168.1.10-150"


def _netmap_load() -> dict:
    try:
        with open(NETMAP_DATA) as f:
            return json.load(f)
    except Exception:
        return {}


def _netmap_save(data: dict):
    with open(NETMAP_DATA, "w") as f:
        json.dump(data, f, indent=2)


def _netmap_parse(output: str) -> list[dict]:
    hosts = []
    current: dict = {}
    in_script = False
    for line in output.splitlines():
        m_host = re.search(r"Nmap scan report for (.+)", line)
        if m_host:
            if current.get("ip"):
                hosts.append(current)
            raw = m_host.group(1)
            ip_m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", raw)
            if ip_m:
                current = {"ip": ip_m.group(1), "hostname": raw.split("(")[0].strip(), "mac": "", "vendor": "", "netbios": ""}
            else:
                current = {"ip": raw.strip(), "hostname": "", "mac": "", "vendor": "", "netbios": ""}
            in_script = False
            continue
        m_mac = re.search(r"MAC Address: ([0-9A-F:]+)\s*(?:\((.+)\))?", line, re.I)
        if m_mac:
            current["mac"] = m_mac.group(1)
            current["vendor"] = m_mac.group(2) or ""
            continue
        # Résultat du script nbstat
        m_nb = re.search(r"NetBIOS name: ([^,]+)", line, re.I)
        if m_nb:
            nb = m_nb.group(1).strip()
            if nb and nb.lower() not in ("<unknown>", ""):
                current["netbios"] = nb
    if current.get("ip"):
        hosts.append(current)
    return hosts



@app.get("/api/netmap/scan")
def api_netmap_scan():
    try:
        r = subprocess.run(
            ["nmap", "-sn", "-T4", "-R", "--dns-servers", "192.168.1.1",
             "--host-timeout", "3s", "--script", "nbstat", NETMAP_RANGE],
            capture_output=True, text=True, timeout=180
        )
        hosts = _netmap_parse(r.stdout)
        return {"hosts": hosts, "names": _netmap_load()}
    except Exception as e:
        return {"hosts": [], "names": {}, "error": str(e)}


@app.get("/api/netmap/names")
def api_netmap_names():
    return _netmap_load()


@app.post("/api/netmap/name")
def api_netmap_name(payload: dict = Body(...)):
    ip = payload.get("ip", "").strip()
    name = payload.get("name", "").strip()
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return {"ok": False, "error": "IP invalide"}
    data = _netmap_load()
    if name:
        data[ip] = name
    elif ip in data:
        del data[ip]
    _netmap_save(data)
    return {"ok": True}


# ─────────────────────────────────────────────────────── NETCONN ──

_CONNTRACK = "/proc/net/nf_conntrack"
_CONNTRACK_ACCT = "/proc/sys/net/netfilter/nf_conntrack_acct"
_conn_prev: dict = {}   # key=conn_id → {"b_fwd": int, "b_rev": int, "ts": float}

# Activer le comptage de bytes à l'initialisation
try:
    with open(_CONNTRACK_ACCT, "w") as _f:
        _f.write("1")
except Exception:
    pass

_LOCAL_NETS = re.compile(r"^(192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)$")
_LAN = re.compile(r"^192\.168\.1\.\d+$")

_PORT_NAMES = {
    80: "http", 443: "https", 22: "ssh", 21: "ftp", 53: "dns",
    3306: "mysql", 5432: "pg", 6379: "redis", 1883: "mqtt",
    32400: "plex", 8096: "jellyfin", 8123: "ha", 3500: "gitea",
    8000: "homelabdash", 9300: "percohub",
}


def _parse_conntrack() -> list[dict]:
    try:
        with open(_CONNTRACK) as f:
            lines = f.readlines()
    except Exception:
        return []

    conns = []
    for line in lines:
        parts = line.split()
        proto = parts[2] if len(parts) > 2 else ""
        state = ""
        for p in parts:
            if p in ("ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT", "CLOSE"):
                state = p
                break

        kv = {}
        seen_src = seen_dst = False
        for p in parts:
            if "=" not in p:
                continue
            k, v = p.split("=", 1)
            if k == "src":
                kv["src2" if seen_src else "src"] = v
                seen_src = True
            elif k == "dst":
                kv["dst2" if seen_dst else "dst"] = v
                seen_dst = True
            elif k in ("sport", "dport", "bytes", "packets"):
                if k not in kv:
                    kv[k] = int(v)
                else:
                    kv[k + "2"] = int(v)

        src, dst = kv.get("src", ""), kv.get("dst", "")
        sport, dport = kv.get("sport", 0), kv.get("dport", 0)
        b_fwd = kv.get("bytes", 0)
        b_rev = kv.get("bytes2", 0)

        # Déterminer le sens : LAN→ext ou ext→LAN
        src_lan = bool(_LAN.match(src))
        dst_lan = bool(_LAN.match(dst))
        src2_lan = bool(_LAN.match(kv.get("src2", "")))

        if src_lan and not dst_lan:
            local_ip, remote_ip, local_port, remote_port = src, dst, sport, dport
            dl, ul = b_rev, b_fwd
        elif dst_lan and not src_lan:
            local_ip, remote_ip, local_port, remote_port = dst, src, dport, sport
            dl, ul = b_fwd, b_rev
        elif src_lan and dst_lan:
            local_ip, remote_ip, local_port, remote_port = src, dst, sport, dport
            dl, ul = b_rev, b_fwd
        else:
            continue

        conns.append({
            "local_ip": local_ip,
            "remote_ip": remote_ip,
            "local_port": local_port,
            "remote_port": remote_port,
            "proto": proto,
            "state": state,
            "dl_bytes": dl,
            "ul_bytes": ul,
            "service": _PORT_NAMES.get(remote_port, _PORT_NAMES.get(local_port, "")),
        })
    return conns


@app.get("/api/netconn")
def api_netconn():
    global _conn_prev
    now = time.time()
    conns = _parse_conntrack()

    # Regrouper par IP locale
    by_ip: dict = {}
    for c in conns:
        ip = c["local_ip"]
        if ip not in by_ip:
            by_ip[ip] = {"ip": ip, "conns": 0, "established": 0,
                         "dl_bytes": 0, "ul_bytes": 0, "top": []}
        entry = by_ip[ip]
        entry["conns"] += 1
        if c["state"] == "ESTABLISHED":
            entry["established"] += 1
        entry["dl_bytes"] += c["dl_bytes"]
        entry["ul_bytes"] += c["ul_bytes"]
        if c["state"] == "ESTABLISHED" and len(entry["top"]) < 5:
            entry["top"].append({
                "remote": c["remote_ip"],
                "port": c["remote_port"],
                "service": c["service"],
                "proto": c["proto"],
            })

    # Calcul du débit (delta vs snapshot précédent)
    dt = now - _conn_prev.get("_ts", now - 1)
    dt = max(dt, 0.5)
    result = []
    for ip, d in sorted(by_ip.items(), key=lambda x: x[1]["dl_bytes"] + x[1]["ul_bytes"], reverse=True):
        prev = _conn_prev.get(ip, {})
        dl_prev = prev.get("dl_bytes", d["dl_bytes"])
        ul_prev = prev.get("ul_bytes", d["ul_bytes"])
        dl_bps = max(0, (d["dl_bytes"] - dl_prev) / dt)
        ul_bps = max(0, (d["ul_bytes"] - ul_prev) / dt)
        result.append({**d, "dl_bps": dl_bps, "ul_bps": ul_bps})

    # Sauvegarder le snapshot
    _conn_prev = {ip: {"dl_bytes": d["dl_bytes"], "ul_bytes": d["ul_bytes"]} for ip, d in by_ip.items()}
    _conn_prev["_ts"] = now

    return {"hosts": result, "ts": int(now)}


# ─────────────────────────────────────────────────────── DOCKERNET ──

_dockernet_prev: dict = {}   # bridge_id → {"recv": int, "sent": int, "ts": float}


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, sock_path: str):
        super().__init__("localhost")
        self._sock_path = sock_path

    def connect(self):
        s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        s.connect(self._sock_path)
        self.sock = s


def _docker_api(path: str) -> list | dict:
    conn = _UnixHTTP("/var/run/docker.sock")
    conn.request("GET", path)
    r = conn.getresponse()
    return json.loads(r.read())


def _docker_net_map() -> dict:
    """Retourne {bridge_short_id: {name, containers}} via API Docker socket."""
    try:
        nets = _docker_api("/networks?filters=%7B%22driver%22%3A%7B%22bridge%22%3Atrue%7D%7D")
        net_by_id = {n["Id"][:12]: {"name": n["Name"], "containers": []} for n in nets}

        # Remplir les containers via /containers/json
        containers = _docker_api("/containers/json")
        for c in containers:
            name = c.get("Names", [""])[0].lstrip("/")
            for net_name, net_cfg in c.get("NetworkSettings", {}).get("Networks", {}).items():
                net_id = net_cfg.get("NetworkID", "")[:12]
                if net_id in net_by_id:
                    net_by_id[net_id]["containers"].append(name)

        return net_by_id
    except Exception:
        return {}


@app.get("/api/dockernet")
def api_dockernet():
    global _dockernet_prev
    now = time.time()

    net_map = _docker_net_map()
    per_nic = psutil.net_io_counters(pernic=True)

    # Ne garder que les bridges (br-XXXXXXXXXXXX)
    bridge_re = re.compile(r"^br-([0-9a-f]{12})$")
    result = []

    dt = now - _dockernet_prev.get("_ts", now - 1)
    dt = max(dt, 0.5)

    for iface, stats in per_nic.items():
        m = bridge_re.match(iface)
        if not m:
            continue
        bid = m.group(1)
        info = net_map.get(bid, {})
        if not info:
            continue

        prev = _dockernet_prev.get(bid, {})
        dl_bps = max(0, (stats.bytes_recv - prev.get("recv", stats.bytes_recv)) / dt)
        ul_bps = max(0, (stats.bytes_sent - prev.get("sent", stats.bytes_sent)) / dt)

        _dockernet_prev[bid] = {"recv": stats.bytes_recv, "sent": stats.bytes_sent}

        result.append({
            "bridge": iface,
            "name": info["name"],
            "containers": info["containers"],
            "dl_bps": dl_bps,
            "ul_bps": ul_bps,
        })

    _dockernet_prev["_ts"] = now
    # Trier par trafic total décroissant
    result.sort(key=lambda x: x["dl_bps"] + x["ul_bps"], reverse=True)
    return {"networks": result, "ts": int(now)}


app.mount("/", StaticFiles(directory="/app/static", html=True), name="static")
