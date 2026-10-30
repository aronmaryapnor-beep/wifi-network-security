# Wi-Fi Security Protocol Comparison

| Protocol | Year | Cipher / mechanism | Status | Notes |
|---|---|---|---|---|
| Open | - | None | Unsafe | No encryption; traffic is readable by anyone in range. |
| WEP | 1999 | RC4 with 24-bit IV | Broken | Keys recoverable in minutes; must not be used. |
| WPA (TKIP) | 2003 | RC4 + TKIP | Deprecated | Interim fix for WEP hardware; known weaknesses. |
| WPA2-Personal (AES-CCMP) | 2004 | AES-CCMP, PSK | Acceptable | Secure with a strong passphrase; vulnerable to offline guessing of weak passphrases. |
| WPA2-Enterprise | 2004 | AES-CCMP, 802.1X/EAP | Strong | Per-user credentials via RADIUS. |
| WPA3-Personal | 2018 | SAE (Dragonfly) handshake, AES | Preferred | Resists offline dictionary attacks; forward secrecy; PMF required. |
| WPA3-Enterprise | 2018 | 802.1X, 192-bit suite option | Strongest | For organisations. |

**Recommendation:** WPA3-Personal where all devices support it; otherwise WPA2-Personal with AES only. Avoid mixed TKIP+AES mode.
