# Wi-Fi Security Assessment Report

| Item | Value |
|---|---|
| Router brand / model | Example Router AC-1200 (sample data) |
| Firmware version | 2.3.0 |
| SSID | Flat-12B |
| Review date | 2026-10-28 |
| Assessor | Aron Maryapnor |

**Score: 81/100 - B - Good**  
Passed: 7 | Warnings: 4 | Failed: 0 | Not assessed: 2

## Findings

| ID | Area | Status | Observed | Expected |
|---|---|---|---|---|
| SEC-01 | Security protocol | WARN | WPA2/WPA3-Personal | WPA3-Personal (preferred) or WPA2-Personal with AES |
| ENC-01 | Encryption | PASS | AES | AES / CCMP (no TKIP, no WEP) |
| PSK-01 | Wi-Fi passphrase | WARN | 13 characters | 16+ characters, unique, not guessable |
| ADM-01 | Router admin account | PASS | Yes | Default admin username/password changed |
| ADM-02 | Admin interface transport | WARN | No | HTTPS administration enabled |
| WPS-01 | WPS | PASS | No | WPS disabled |
| RMT-01 | Remote management | PASS | No | Remote management disabled |
| UPN-01 | UPnP | N/A | not provided | UPnP disabled unless needed |
| GST-01 | Guest network | WARN | No guest network | Separate guest SSID with client isolation |
| FWR-01 | Firmware | PASS | Yes | Latest vendor firmware installed |
| PMF-01 | Protected management frames | PASS | optional | PMF (802.11w) required or optional |
| SSD-01 | SSID naming | N/A | not provided | SSID does not reveal router make/model |
| CLI-01 | Connected clients | PASS | 0 unknown devices | All connected devices identified |

## Recommendations (highest impact first)

1. **Security protocol** (WARN) - Use WPA3-only once all devices support it.  
   *Why:* WPA2/WPA3 transition mode works for mixed devices but allows downgrade to WPA2.
2. **Wi-Fi passphrase** (WARN) - Use a long random passphrase or a 4-5 word passphrase; never reuse it elsewhere.  
   *Why:* Short or reused passphrases can be guessed offline from a captured handshake.
3. **Guest network** (WARN) - Enable a guest network and turn on client / AP isolation.  
   *Why:* Visitors should not reach trusted devices (PCs, NAS, printers).
4. **Admin interface transport** (WARN) - Enable HTTPS for the router admin page where available.  
   *Why:* HTTP administration sends credentials in clear text on the LAN.

## Not assessed (no data supplied)

- UPnP: UPnP disabled unless needed
- SSID naming: SSID does not reveal router make/model

---
*Assessment limited to a network owned by the assessor or covered by explicit authorisation. A configuration review cannot guarantee a network is fully secure.*
