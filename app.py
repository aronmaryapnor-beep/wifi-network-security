"""Wi-Fi Network Security - Streamlit app.
Run with:  streamlit run app.py
"""

import json
from pathlib import Path

import streamlit as st

from wifi_audit.checks import audit
from wifi_audit.local_scan import current_connection
from wifi_audit.passphrase import evaluate
from wifi_audit.report import to_html, to_markdown

ROOT = Path(__file__).parent
STATUS_ICON = {"PASS": "✅ PASS", "WARN": "⚠️ WARN", "FAIL": "❌ FAIL", "UNKNOWN": "➖ N/A"}

st.set_page_config(page_title="Wi-Fi Network Security", page_icon="📶", layout="wide")

st.sidebar.title("📶 Wi-Fi Network Security")
st.sidebar.caption("Aron Maryapnor · Roll 19028\nTY BSc IT Cybersecurity Field Project")
page = st.sidebar.radio(
    "Go to",
    ["🏠 Simple Explanation", "🛡️ Router Audit", "🔑 Passphrase Checker",
     "📊 Protocols", "⚠️ Threats & Fixes", "📋 Checklist", "💻 This Computer"],
)
st.sidebar.info("Use only on networks you own or have written permission to test.")


# ---------------------------------------------------------------- Home
def page_home():
    st.title("Wi-Fi Network Security")
    st.subheader("Securing wireless networks through encryption, access control and threat mitigation")

    st.markdown("### What is the problem?")
    st.write(
        "Wi-Fi uses radio waves, and radio waves do not stop at your wall. "
        "Anyone nearby can *try* to join your network or listen to it. "
        "If the router uses an old lock, an easy password, or its factory settings, "
        "they may succeed."
    )

    st.markdown("### What does this project do?")
    c1, c2, c3 = st.columns(3)
    c1.info("**1. Check**\n\nYou enter your router's settings. The app compares them with a safe baseline.")
    c2.warning("**2. Score**\n\nEach setting is PASS, WARN or FAIL. You get a score out of 100.")
    c3.success("**3. Fix**\n\nThe app lists what to change first and why, in plain words.")

    st.markdown("### The 6 things that matter most")
    st.markdown(
        """
| # | Setting | Simple meaning |
|---|---|---|
| 1 | **WPA3 / WPA2-AES** | The *lock* on your Wi-Fi. Old locks (WEP, WPA, TKIP) can be picked. |
| 2 | **Strong Wi-Fi password** | The *key*. Long and unique beats short and clever. |
| 3 | **Router admin password** | The key to the *router's control panel*. Never leave the default. |
| 4 | **Turn off WPS & remote access** | Closes convenient-but-risky back doors. |
| 5 | **Guest network** | Visitors get a separate room, not your whole house. |
| 6 | **Update firmware** | Fixes holes that attackers already know about. |
"""
    )

    st.markdown("### Key words in one line each")
    with st.expander("Open the mini-dictionary"):
        st.markdown(
            """
- **SSID** - the Wi-Fi network's name.
- **Encryption** - scrambling data so eavesdroppers see nonsense.
- **WPA2 / WPA3** - security standards for Wi-Fi (WPA3 is the newest).
- **AES** - the strong scrambling method used by WPA2/WPA3.
- **WPS** - a "push-button" pairing feature with known weaknesses.
- **Evil twin** - a fake hotspot with a trusted name, made to trick you.
- **Deauthentication** - a forged message that kicks devices off Wi-Fi.
- **Guest isolation** - guests cannot see your other devices.
"""
        )
    st.caption("Start with **Router Audit** in the sidebar to try it.")


# ---------------------------------------------------------------- Audit
def load_sample(name):
    return json.loads((ROOT / "configs" / name).read_text(encoding="utf-8"))


def page_audit():
    st.title("🛡️ Router Audit")
    st.write("Open your router's admin page, read its settings, and enter them below. "
             "**Do not type your Wi-Fi password** - only its length.")

    src = st.radio("Start from", ["Blank form", "Sample: insecure router", "Sample: secure router",
                                  "Upload my JSON file"], horizontal=True)
    base = {}
    if src == "Sample: insecure router":
        base = load_sample("sample_insecure_config.json")
    elif src == "Sample: secure router":
        base = load_sample("sample_secure_config.json")
    elif src == "Upload my JSON file":
        up = st.file_uploader("Config JSON", type="json")
        if up:
            try:
                base = json.load(up)
            except json.JSONDecodeError:
                st.error("That file is not valid JSON.")

    modes = ["WPA3-Personal", "WPA2/WPA3-Personal", "WPA2-Personal", "WPA-Personal", "WEP", "Open"]
    encs = ["AES", "AES+TKIP", "TKIP"]
    pmfs = ["required", "optional", "disabled"]

    def idx(options, value, default=0):
        return options.index(value) if value in options else default

    with st.form("audit_form"):
        a, b = st.columns(2)
        with a:
            st.markdown("**Router details**")
            model = st.text_input("Router brand / model", base.get("router_model", ""))
            fw = st.text_input("Firmware version", base.get("firmware_version", ""))
            ssid = st.text_input("SSID (network name)", base.get("ssid", ""))
            st.markdown("**Wireless security**")
            mode = st.selectbox("Security mode", modes, idx(modes, base.get("security_mode"), 2))
            enc = st.selectbox("Encryption", encs, idx(encs, base.get("encryption")))
            plen = st.number_input("Wi-Fi password length (characters)", 0, 128,
                                   int(base.get("passphrase_length", 12)))
            pmf = st.selectbox("Protected management frames (802.11w)", pmfs, idx(pmfs, base.get("pmf"), 1))
        with b:
            st.markdown("**Router hardening**")
            admin = st.checkbox("Default admin password was changed",
                                base.get("admin_default_credentials_changed", False))
            https = st.checkbox("Admin page uses HTTPS", base.get("admin_https", False))
            wps = st.checkbox("WPS is ENABLED", base.get("wps_enabled", False))
            remote = st.checkbox("Remote management is ENABLED", base.get("remote_management", False))
            upnp = st.checkbox("UPnP is ENABLED", base.get("upnp_enabled", False))
            fwok = st.checkbox("Firmware is up to date", base.get("firmware_up_to_date", False))
            dssid = st.checkbox("SSID is the factory default / shows router model", base.get("ssid_is_default", False))
            st.markdown("**Guest access & devices**")
            guest = st.checkbox("Guest network is enabled", base.get("guest_network_enabled", False))
            iso = st.checkbox("Guest isolation is on", base.get("guest_isolation", False))
            unk = st.number_input("Unknown devices in the client list", 0, 100,
                                  int(base.get("unknown_clients", 0)))
        go = st.form_submit_button("Run audit", type="primary")

    if not go:
        st.stop()

    cfg = {
        "router_model": model or "not provided", "firmware_version": fw or "not provided",
        "ssid": ssid or "not provided", "security_mode": mode, "encryption": enc,
        "passphrase_length": plen, "pmf": pmf,
        "admin_default_credentials_changed": admin, "admin_https": https,
        "wps_enabled": wps, "remote_management": remote, "upnp_enabled": upnp,
        "firmware_up_to_date": fwok, "ssid_is_default": dssid,
        "guest_network_enabled": guest, "guest_isolation": iso, "unknown_clients": unk,
    }
    findings, summary = audit(cfg)

    st.divider()
    st.subheader(f"Result: {summary['score']}/100 - {summary['grade']}")
    st.progress(summary["score"] / 100)
    m1, m2, m3 = st.columns(3)
    m1.metric("Passed", summary["passed"])
    m2.metric("Warnings", summary["warnings"])
    m3.metric("Failed", summary["failed"])

    st.markdown("#### All checks")
    st.dataframe(
        [{"ID": f.id, "Area": f.area, "Status": STATUS_ICON[f.status],
          "Your setting": str(f.observed), "Should be": f.expected} for f in findings],
        hide_index=True,
    )

    todo = sorted([f for f in findings if f.status in ("FAIL", "WARN")],
                  key=lambda x: (x.status != "FAIL", -x.weight))
    st.markdown("#### What to fix first")
    if not todo:
        st.success("Nothing to fix. Keep firmware updated and review settings regularly.")
    for i, f in enumerate(todo, 1):
        with st.expander(f"{i}. {STATUS_ICON[f.status]} - {f.area}", expanded=i <= 3):
            st.markdown(f"**Fix:** {f.fix}")
            st.markdown(f"**Why it matters:** {f.why}")

    d1, d2, d3 = st.columns(3)
    d1.download_button("⬇️ Report (HTML)", to_html(cfg, findings, summary), "wifi_report.html", "text/html")
    d2.download_button("⬇️ Report (Markdown)", to_markdown(cfg, findings, summary), "wifi_report.md")
    d3.download_button("⬇️ Settings (JSON)", json.dumps(cfg, indent=2), "my_router.json", "application/json")


# ---------------------------------------------------------------- Passphrase
def page_passphrase():
    st.title("🔑 Passphrase Checker")
    st.write("Your text is analysed in memory and is **never saved or sent anywhere**. "
             "Still, test a *similar* password rather than your real one if you prefer.")
    pw = st.text_input("Type a Wi-Fi password to test", type="password")
    if pw:
        r = evaluate(pw)
        color = {"Weak": "red", "Fair": "orange", "Good": "blue", "Strong": "green"}[r["rating"]]
        st.markdown(f"### Rating: :{color}[{r['rating']}]")
        c1, c2 = st.columns(2)
        c1.metric("Length", r["length"])
        c2.metric("Estimated strength (bits)", r["entropy_bits"])
        st.progress(min(r["entropy_bits"] / 100, 1.0))
        for issue in r["issues"]:
            st.warning(issue)
        if not r["issues"] and r["rating"] in ("Good", "Strong"):
            st.success("No obvious problems found.")
    st.markdown("#### Tips for a good Wi-Fi password")
    st.markdown("- Use **16 or more characters**.\n"
                "- Four or five random words (e.g. *lamp-river-orbit-tulip-seven*) are easy to type and hard to guess.\n"
                "- Never reuse it for email, banking or other accounts.\n"
                "- No names, birthdays, phone numbers or router model.")


# ---------------------------------------------------------------- Protocols
def page_protocols():
    st.title("📊 Wi-Fi Security Protocols")
    st.write("Think of each protocol as a type of lock. Newer is better.")
    st.dataframe([
        {"Protocol": "Open", "Year": "-", "Safety": "❌ Unsafe", "In simple words": "No lock at all."},
        {"Protocol": "WEP", "Year": 1999, "Safety": "❌ Broken", "In simple words": "Can be opened in minutes."},
        {"Protocol": "WPA / TKIP", "Year": 2003, "Safety": "❌ Deprecated", "In simple words": "Patched old lock, still weak."},
        {"Protocol": "WPA2-Personal (AES)", "Year": 2004, "Safety": "✅ Acceptable", "In simple words": "Good if the password is strong."},
        {"Protocol": "WPA3-Personal", "Year": 2018, "Safety": "✅ Preferred", "In simple words": "Resists password guessing much better."},
        {"Protocol": "WPA2/WPA3-Enterprise", "Year": "2004/2018", "Safety": "✅ Strongest", "In simple words": "Each user has own login; for organisations."},
    ], hide_index=True)
    st.info("**Recommendation:** WPA3-Personal if all your devices support it, otherwise WPA2-Personal with AES. "
            "Avoid mixed TKIP+AES mode.")


# ---------------------------------------------------------------- Threats
def page_threats():
    st.title("⚠️ Threats & How to Stop Them")
    rows = [
        ("Weak password", "Someone guesses or finds your Wi-Fi password.", "Long, unique password; WPA3."),
        ("Evil-twin hotspot", "A fake hotspot copies a trusted name to trick you.", "Check the network; avoid logins on unknown Wi-Fi; use HTTPS/VPN."),
        ("Eavesdropping", "Someone watches unprotected Wi-Fi traffic.", "WPA2-AES / WPA3."),
        ("Rogue device", "An unknown device joins your network.", "Strong password; check the client list."),
        ("Router compromise", "Default login or old firmware lets attackers change settings.", "Change admin password; update firmware."),
        ("Deauthentication attack", "Forged messages disconnect your devices.", "Enable protected management frames; WPA3."),
    ]
    for name, what, fix in rows:
        with st.expander(name):
            st.markdown(f"**What happens:** {what}")
            st.markdown(f"**Defence:** {fix}")


# ---------------------------------------------------------------- Checklist
def page_checklist():
    st.title("📋 Security Checklist")
    items = [
        "Security mode is WPA3-Personal or WPA2-Personal with AES",
        "WEP, WPA and TKIP are not enabled",
        "Wi-Fi password is long (16+) and unique",
        "Default router admin password changed",
        "Admin page uses HTTPS",
        "WPS disabled",
        "Remote management disabled",
        "UPnP disabled unless needed",
        "Guest network enabled with isolation",
        "Protected management frames enabled",
        "Firmware is up to date",
        "Connected-device list reviewed",
    ]
    done = sum(st.checkbox(t, key=f"chk{i}") for i, t in enumerate(items))
    st.progress(done / len(items))
    st.write(f"**{done} of {len(items)} complete**")
    if done == len(items):
        st.balloons()


# ---------------------------------------------------------------- Local
def page_local():
    st.title("💻 This Computer's Wi-Fi")
    st.write("Reads the security mode of the Wi-Fi network **the computer running this app** is connected to. "
             "It works only when you run the app on your own laptop (not on a cloud server).")
    if st.button("Check my connection"):
        info = current_connection()
        if not info:
            st.error("Could not read a Wi-Fi connection (not connected, no Wi-Fi adapter, or unsupported system).")
            return
        st.json(info)
        findings, _ = audit(info)
        for f in findings:
            if f.id in ("SEC-01", "ENC-01") and f.status != "UNKNOWN":
                {"PASS": st.success, "WARN": st.warning, "FAIL": st.error}[f.status](
                    f"{f.area}: {f.observed} - {f.status}")


{
    "🏠 Simple Explanation": page_home,
    "🛡️ Router Audit": page_audit,
    "🔑 Passphrase Checker": page_passphrase,
    "📊 Protocols": page_protocols,
    "⚠️ Threats & Fixes": page_threats,
    "📋 Checklist": page_checklist,
    "💻 This Computer": page_local,
}[page]()
