"""Rule engine: compares a router/Wi-Fi configuration against the security baseline
described in the project report (Section 5.1)."""

from dataclasses import dataclass, asdict

PASS, WARN, FAIL, UNKNOWN = "PASS", "WARN", "FAIL", "UNKNOWN"


@dataclass
class Finding:
    id: str
    area: str
    status: str
    weight: int
    observed: str
    expected: str
    why: str
    fix: str

    def to_dict(self):
        return asdict(self)


def _s(value):
    return None if value is None else str(value).strip().lower()


def _bool(value):
    if isinstance(value, bool):
        return value
    v = _s(value)
    if v in ("true", "yes", "enabled", "on", "1"):
        return True
    if v in ("false", "no", "disabled", "off", "0"):
        return False
    return None


def _unknown(fid, area, weight, expected, why, fix):
    return Finding(fid, area, UNKNOWN, weight, "not provided", expected, why, fix)


def check_security_mode(cfg):
    area, w = "Security protocol", 10
    expected = "WPA3-Personal (preferred) or WPA2-Personal with AES"
    why = "Obsolete protocols can be broken quickly; modern ones resist offline guessing and eavesdropping."
    fix = "Set security mode to WPA3-Personal (SAE), or WPA2-Personal (AES) if some devices lack WPA3."
    mode = _s(cfg.get("security_mode"))
    if mode is None:
        return _unknown("SEC-01", area, w, expected, why, fix)
    obs = cfg["security_mode"]
    if mode in ("open", "none", "") or "open" in mode:
        return Finding("SEC-01", area, FAIL, w, obs, expected, "The network is unencrypted; all traffic is exposed.", fix)
    if "wep" in mode:
        return Finding("SEC-01", area, FAIL, w, obs, expected, why, fix)
    if "wpa3" in mode and "wpa2" in mode:
        return Finding("SEC-01", area, WARN, w, obs, expected,
                       "WPA2/WPA3 transition mode works for mixed devices but allows downgrade to WPA2.",
                       "Use WPA3-only once all devices support it.")
    if "wpa3" in mode:
        return Finding("SEC-01", area, PASS, w, obs, expected, why, fix)
    if "wpa2" in mode:
        return Finding("SEC-01", area, PASS, w, obs, expected, why,
                       "Consider moving to WPA3-Personal when devices support it.")
    if "wpa" in mode:
        return Finding("SEC-01", area, FAIL, w, obs, expected, why, fix)
    return Finding("SEC-01", area, WARN, w, obs, expected, "Unrecognised security mode.", fix)


def check_encryption(cfg):
    area, w = "Encryption", 8
    expected = "AES / CCMP (no TKIP, no WEP)"
    why = "TKIP and WEP have known cryptographic weaknesses."
    fix = "Select AES / CCMP only and disable TKIP."
    enc = _s(cfg.get("encryption"))
    if enc is None:
        return _unknown("ENC-01", area, w, expected, why, fix)
    obs = cfg["encryption"]
    has_aes = any(k in enc for k in ("aes", "ccmp", "gcmp", "sae"))
    has_weak = "tkip" in enc or "wep" in enc
    if has_weak and not has_aes:
        return Finding("ENC-01", area, FAIL, w, obs, expected, why, fix)
    if has_weak:
        return Finding("ENC-01", area, WARN, w, obs, expected,
                       "Mixed TKIP+AES mode lets weaker clients negotiate weak encryption.", fix)
    if has_aes:
        return Finding("ENC-01", area, PASS, w, obs, expected, why, fix)
    return Finding("ENC-01", area, WARN, w, obs, expected, "Unrecognised encryption value.", fix)


def check_passphrase(cfg):
    area, w = "Wi-Fi passphrase", 9
    expected = "16+ characters, unique, not guessable"
    why = "Short or reused passphrases can be guessed offline from a captured handshake."
    fix = "Use a long random passphrase or a 4-5 word passphrase; never reuse it elsewhere."
    n = cfg.get("passphrase_length")
    if n is None:
        return _unknown("PSK-01", area, w, expected, why, fix)
    try:
        n = int(n)
    except (TypeError, ValueError):
        return _unknown("PSK-01", area, w, expected, why, fix)
    obs = f"{n} characters"
    if n < 12:
        return Finding("PSK-01", area, FAIL, w, obs, expected, why, fix)
    if n < 16:
        return Finding("PSK-01", area, WARN, w, obs, expected, why, fix)
    return Finding("PSK-01", area, PASS, w, obs, expected, why, fix)


def _bool_rule(cfg, key, fid, area, w, expected, why, fix, good_when, fail_if_bad=True, bad_status=None):
    v = _bool(cfg.get(key))
    if v is None:
        return _unknown(fid, area, w, expected, why, fix)
    obs = "Yes" if v else "No"
    ok = (v == good_when)
    if ok:
        return Finding(fid, area, PASS, w, obs, expected, why, fix)
    return Finding(fid, area, bad_status or (FAIL if fail_if_bad else WARN), w, obs, expected, why, fix)


def check_admin_credentials(cfg):
    return _bool_rule(cfg, "admin_default_credentials_changed", "ADM-01", "Router admin account", 9,
                      "Default admin username/password changed",
                      "Default credentials are public and let anyone on the LAN reconfigure the router.",
                      "Set a strong, unique administrator password (and rename the admin user if possible).",
                      good_when=True)


def check_admin_https(cfg):
    return _bool_rule(cfg, "admin_https", "ADM-02", "Admin interface transport", 4,
                      "HTTPS administration enabled",
                      "HTTP administration sends credentials in clear text on the LAN.",
                      "Enable HTTPS for the router admin page where available.",
                      good_when=True, fail_if_bad=False)


def check_wps(cfg):
    return _bool_rule(cfg, "wps_enabled", "WPS-01", "WPS", 6,
                      "WPS disabled",
                      "WPS PIN pairing has known design weaknesses that enable brute force.",
                      "Disable WPS in the wireless settings.",
                      good_when=False)


def check_remote_mgmt(cfg):
    return _bool_rule(cfg, "remote_management", "RMT-01", "Remote management", 7,
                      "Remote management disabled",
                      "Exposes the router login to the Internet.",
                      "Disable remote/WAN management unless operationally required (then restrict by IP + VPN).",
                      good_when=False)


def check_upnp(cfg):
    return _bool_rule(cfg, "upnp_enabled", "UPN-01", "UPnP", 3,
                      "UPnP disabled unless needed",
                      "UPnP lets devices open inbound ports automatically.",
                      "Disable UPnP if no application requires it.",
                      good_when=False, fail_if_bad=False)


def check_guest(cfg):
    area, w = "Guest network", 5
    expected = "Separate guest SSID with client isolation"
    why = "Visitors should not reach trusted devices (PCs, NAS, printers)."
    fix = "Enable a guest network and turn on client / AP isolation."
    g = _bool(cfg.get("guest_network_enabled"))
    iso = _bool(cfg.get("guest_isolation"))
    if g is None:
        return _unknown("GST-01", area, w, expected, why, fix)
    if not g:
        return Finding("GST-01", area, WARN, w, "No guest network", expected, why, fix)
    if iso is None:
        return Finding("GST-01", area, WARN, w, "Guest enabled; isolation unknown", expected, why, fix)
    if iso:
        return Finding("GST-01", area, PASS, w, "Guest enabled with isolation", expected, why, fix)
    return Finding("GST-01", area, FAIL, w, "Guest enabled without isolation", expected, why, fix)


def check_firmware(cfg):
    return _bool_rule(cfg, "firmware_up_to_date", "FWR-01", "Firmware", 8,
                      "Latest vendor firmware installed",
                      "Old firmware carries publicly known vulnerabilities.",
                      "Update from the manufacturer's official site and enable update notifications.",
                      good_when=True)


def check_pmf(cfg):
    area, w = "Protected management frames", 4
    expected = "PMF (802.11w) required or optional"
    why = "Without PMF, deauthentication frames can be forged to disrupt clients."
    fix = "Enable PMF / 802.11w (required for WPA3)."
    v = _s(cfg.get("pmf"))
    if v is None:
        return _unknown("PMF-01", area, w, expected, why, fix)
    if v in ("required", "mandatory"):
        return Finding("PMF-01", area, PASS, w, cfg["pmf"], expected, why, fix)
    if v in ("optional", "capable"):
        return Finding("PMF-01", area, PASS, w, cfg["pmf"], expected, why, fix)
    return Finding("PMF-01", area, WARN, w, cfg["pmf"], expected, why, fix)


def check_ssid(cfg):
    return _bool_rule(cfg, "ssid_is_default", "SSD-01", "SSID naming", 2,
                      "SSID does not reveal router make/model",
                      "Default SSIDs hint at the router model and its known weaknesses.",
                      "Choose a neutral SSID that has no personal or vendor information.",
                      good_when=False, fail_if_bad=False)


def check_clients(cfg):
    area, w = "Connected clients", 4
    expected = "All connected devices identified"
    why = "Unknown clients may indicate unauthorised access."
    fix = "Review the client list; change the Wi-Fi passphrase if an unknown device is confirmed."
    n = cfg.get("unknown_clients")
    if n is None:
        return _unknown("CLI-01", area, w, expected, why, fix)
    try:
        n = int(n)
    except (TypeError, ValueError):
        return _unknown("CLI-01", area, w, expected, why, fix)
    if n == 0:
        return Finding("CLI-01", area, PASS, w, "0 unknown devices", expected, why, fix)
    return Finding("CLI-01", area, FAIL, w, f"{n} unknown device(s)", expected, why, fix)


ALL_CHECKS = [
    check_security_mode, check_encryption, check_passphrase, check_admin_credentials,
    check_admin_https, check_wps, check_remote_mgmt, check_upnp, check_guest,
    check_firmware, check_pmf, check_ssid, check_clients,
]


def audit(cfg):
    """Run every check. Returns (findings, summary dict)."""
    findings = [check(cfg) for check in ALL_CHECKS]
    scored = [f for f in findings if f.status != UNKNOWN]
    total = sum(f.weight for f in scored)
    earned = sum(f.weight * (1.0 if f.status == PASS else 0.5 if f.status == WARN else 0.0) for f in scored)
    score = round(100 * earned / total) if total else 0
    if score >= 90:
        grade = "A - Strong"
    elif score >= 75:
        grade = "B - Good"
    elif score >= 60:
        grade = "C - Needs improvement"
    elif score >= 40:
        grade = "D - Weak"
    else:
        grade = "F - Critical"
    summary = {
        "score": score,
        "grade": grade,
        "passed": sum(f.status == PASS for f in findings),
        "warnings": sum(f.status == WARN for f in findings),
        "failed": sum(f.status == FAIL for f in findings),
        "unknown": sum(f.status == UNKNOWN for f in findings),
    }
    return findings, summary
