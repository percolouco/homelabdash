import subprocess, json, time, re, os
from typing import Optional

import psutil
import cpuinfo
from fastapi import FastAPI, Body
from fastapi.staticfiles import StaticFiles

app = FastAPI()

HOST_ROOT = os.environ.get("HOST_ROOT", "")
_net_last = {"t": 0.0, "bytes_sent": 0, "bytes_recv": 0}
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

    net_now = psutil.net_io_counters()
    now = time.time()
    dt = now - _net_last["t"] if _net_last["t"] else 1.0
    dl = (net_now.bytes_recv - _net_last["bytes_recv"]) / dt if _net_last["t"] else 0
    ul = (net_now.bytes_sent - _net_last["bytes_sent"]) / dt if _net_last["t"] else 0
    _net_last = {"t": now, "bytes_sent": net_now.bytes_sent, "bytes_recv": net_now.bytes_recv}

    # Interfaces : filtrer loopback et bridges Docker
    net_ifaces = {}
    stats = psutil.net_if_stats()
    for iface, addrs in psutil.net_if_addrs().items():
        if iface == "lo" or iface.startswith("br-") or iface == "docker0":
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
            "total_recv": net_now.bytes_recv,
            "total_sent": net_now.bytes_sent,
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


app.mount("/", StaticFiles(directory="/app/static", html=True), name="static")
