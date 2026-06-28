import subprocess, json, time, re, os
from pathlib import Path

import psutil
import cpuinfo
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

app = FastAPI()

HOST_ROOT = os.environ.get("HOST_ROOT", "")  # "/rootfs" en container, "" en local
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


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=10).decode(errors="ignore")
    except Exception:
        return ""


def _smartctl_all() -> dict:
    result = {}
    try:
        devs = json.loads(_run(["smartctl", "--scan-open", "-j"]))
        for d in devs.get("devices", []):
            name = d.get("name", "")
            if not name:
                continue
            info = json.loads(_run(["smartctl", "-a", "-j", name]))
            short = name.split("/")[-1]
            result[name] = {
                "device": short,
                "model": info.get("model_name", info.get("model_family", "")),
                "serial": info.get("serial_number", ""),
                "health": info.get("smart_status", {}).get("passed", None),
                "temp_c": info.get("temperature", {}).get("current", None),
                "capacity_bytes": info.get("user_capacity", {}).get("bytes", None),
                "rotation_rate": info.get("rotation_rate", None),
            }
    except Exception:
        pass
    return result


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
    return {
        "manufacturer": get("Manufacturer"),
        "product": get("Product Name"),
        "version": get("Version"),
    }


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


def _host_path(p: str) -> str:
    return HOST_ROOT + p if HOST_ROOT else p


def _flatten_lsblk(dev: dict, result: list | None = None) -> list:
    if result is None:
        result = []
    result.append(dev)
    for child in dev.get("children", []):
        _flatten_lsblk(child, result)
    return result


def _read_host_disks() -> list[dict]:
    """Enumère les vrais disques via lsblk (lit /sys) et accède aux montages via /rootfs."""
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
            if item.get("type") not in ("part", "lvm", "disk", "raid1", "md"):
                if item.get("type") == "disk" and not item.get("children"):
                    pass  # disque sans partition (rare, garder)
                elif item.get("type") != "disk":
                    pass
                # on garde tout sauf loop/rom/etc
                if item.get("type") in ("loop", "rom", "sr"):
                    continue

            mps = item.get("mountpoints") or []
            mp = item.get("mountpoint")
            if mp and mp not in mps:
                mps.insert(0, mp)
            mps = [m for m in mps if m and m not in ("[SWAP]", "")]

            fstype = item.get("fstype") or ""
            if fstype in SKIP_FS:
                continue

            for mountpoint in mps:
                # ne garder que les montages hôtes (commencent par HOST_ROOT si défini)
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


def get_live() -> dict:
    global _net_last

    cpu_percent = psutil.cpu_percent(interval=0.3)
    cpu_freq = psutil.cpu_freq()
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()

    disks = _read_host_disks()

    # réseau — avec network_mode:host on lit directement les stats hôte
    net_now = psutil.net_io_counters()
    now = time.time()
    dt = now - _net_last["t"] if _net_last["t"] else 1.0
    dl = (net_now.bytes_recv - _net_last["bytes_recv"]) / dt if _net_last["t"] else 0
    ul = (net_now.bytes_sent - _net_last["bytes_sent"]) / dt if _net_last["t"] else 0
    _net_last = {"t": now, "bytes_sent": net_now.bytes_sent, "bytes_recv": net_now.bytes_recv}

    net_ifaces = {}
    for iface, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == 2:  # AF_INET
                net_ifaces[iface] = a.address
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
        "swap": {
            "total": swap.total, "used": swap.used, "percent": swap.percent,
        },
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


_os_cache: dict = {}


def _get_os_info() -> dict:
    uname = os.uname()
    os_name = _run(["lsb_release", "-ds"]).strip()
    if not os_name:
        try:
            with open(_host_path("/etc/os-release")) as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        os_name = line.split("=", 1)[1].strip().strip('"')
                        break
        except Exception:
            os_name = uname.sysname
    return {
        "hostname": uname.nodename,
        "os": os_name,
        "kernel": uname.release,
        "arch": uname.machine,
    }


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


app.mount("/", StaticFiles(directory="/app/static", html=True), name="static")
