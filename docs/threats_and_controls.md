# Threats and Defensive Controls

| Threat | Description | Defensive control | Audit check |
|---|---|---|---|
| Weak password | Passphrase guessed or reused | Long unique passphrase; WPA3 SAE | PSK-01, SEC-01 |
| Evil-twin access point | Rogue hotspot copies a trusted SSID | Verify network identity; avoid sensitive activity on untrusted hotspots; use HTTPS/VPN | SSD-01 (neutral SSID), user awareness |
| Eavesdropping | Weak/no encryption lets traffic be observed | WPA2-AES / WPA3; end-to-end encrypted services | SEC-01, ENC-01 |
| Rogue device | Unknown client joins the network | Strong credentials; review client list; rotate passphrase | CLI-01 |
| Router compromise | Default credentials or old firmware | Change admin credentials; HTTPS admin; update firmware; disable remote management | ADM-01, ADM-02, RMT-01, FWR-01 |
| WPS brute force | PIN pairing weakness | Disable WPS | WPS-01 |
| Deauthentication disruption | Forged management frames drop clients | Protected management frames (802.11w), WPA3 | PMF-01 |
| Guest-to-LAN access | Visitors reach trusted devices | Guest SSID with client isolation | GST-01 |
| Automatic port exposure | UPnP opens inbound ports | Disable UPnP unless needed | UPN-01 |
