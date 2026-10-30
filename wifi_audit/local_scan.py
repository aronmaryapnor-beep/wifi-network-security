"""Read-only inspection of the Wi-Fi connection of THIS computer (the one you own).
It only reports the security mode/cipher negotiated with the current access point;
it does not scan for or interact with other networks."""

import platform
import re
import subprocess


def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _windows():
    out = _run(["netsh", "wlan", "show", "interfaces"])
    if not out:
        return None
    def get(label):
        m = re.search(rf"^\s*{label}\s*:\s*(.+)$", out, re.M)
        return m.group(1).strip() if m else None
    return {"ssid": get("SSID"), "security_mode": get("Authentication"),
            "encryption": get("Cipher"), "band": get("Radio type")}


def _linux():
    out = _run(["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY", "dev", "wifi"])
    for line in out.splitlines():
        parts = line.split(":")
        if parts and parts[0] == "yes":
            sec = parts[-1].strip() or "Open"
            return {"ssid": ":".join(parts[1:-1]), "security_mode": sec,
                    "encryption": "AES" if "WPA" in sec and "TKIP" not in sec else None}
    return None


def _mac():
    out = _run(["system_profiler", "SPAirPortDataType"])
    m = re.search(r"Current Network Information:\s*\n\s*(.+?):\s*\n(.*?)(?:\n\s*\n|$)", out, re.S)
    if not m:
        return None
    block = m.group(2)
    sec = re.search(r"Security:\s*(.+)", block)
    return {"ssid": m.group(1).strip(), "security_mode": sec.group(1).strip() if sec else None,
            "encryption": None}


def current_connection():
    system = platform.system()
    if system == "Windows":
        return _windows()
    if system == "Linux":
        return _linux()
    if system == "Darwin":
        return _mac()
    return None
