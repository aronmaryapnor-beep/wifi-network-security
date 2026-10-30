# Lab Procedure (authorised network only)

1. **Authorisation** - use your own router, or get written permission from the owner. Note router make/model and purpose.
2. **Capture current state** - log in to the router admin page. Record security mode, encryption, WPS, guest network, remote management, UPnP, PMF and firmware version. Take screenshots *before* changes (hide passwords, MAC addresses, serial numbers).
3. **Fill the config** - `python run_audit.py template > configs/my_router.json` and enter the observed values. Enter only the passphrase *length*, never the passphrase.
4. **Baseline audit** - `python run_audit.py audit configs/my_router.json --format html --out reports/before.html`.
5. **Harden** - apply the recommendations (WPA3/WPA2-AES, long unique passphrase, change admin password, disable WPS and remote management, enable guest isolation, update firmware, enable PMF).
6. **Re-audit** - update the config values and run again to `reports/after.html`. Compare scores.
7. **Verify connectivity** - reconnect authorised devices and confirm they work.
8. **Review clients** - compare router client list with known devices; investigate unknown entries using the router's device details.
9. **Document** - add redacted screenshots to `screenshots/` (Fig 6.1 security mode, 6.2 hardening settings, 6.3 client list / guest network) and complete `docs/assessment_record_template.md`.
10. **Local check** - run `python run_audit.py local` on a client device to confirm the negotiated security mode and cipher.
