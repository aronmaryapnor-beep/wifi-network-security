# Wi-Fi Network Security

**Securing wireless networks through encryption, access control and threat mitigation**

TY BSc IT Cybersecurity Field Project - S.I.W.S N.R. Swamy College of Commerce & Economics and Smt. Thirumalai College of Science (Autonomous)

| | |
|---|---|
| Student | Aron Maryapnor |
| Roll No / Student ID | 19028 / 20242517043 |
| Guide | Ms. Gayatri Venkatachalam |
| Academic year | 2026-2027 |

## What this project is

A defensive toolkit that implements the assessment framework from the project report:

- **Configuration auditor** - checks a router's settings (protocol, encryption, passphrase length, admin credentials, WPS, remote management, UPnP, guest isolation, PMF, firmware, unknown clients) against the baseline in report Section 5.1 and produces a scored report (Markdown / HTML / JSON).
- **Passphrase strength checker** - hidden input, never stored or logged.
- **Local connection inspector** - reads the security mode and cipher of the Wi-Fi network *this computer* is currently connected to.
- **Documentation pack** - checklist, assessment record template, protocol comparison, threat and control matrix, lab procedure.

> **Ethics:** use only on a network you own or have written permission to assess. The toolkit does not scan, capture, crack or attack any network.

## Run the Streamlit web app (recommended)

```bash
pip install -r requirements.txt
streamlit run app.py
```

The browser opens at http://localhost:8501. Pages in the sidebar:

| Page | What it does |
|---|---|
| Simple Explanation | Plain-language overview, the 6 key settings, mini-dictionary |
| Router Audit | Fill in your router settings, get a score, a fix list and downloadable reports |
| Passphrase Checker | Rates a Wi-Fi password (never saved) |
| Protocols | WEP / WPA / WPA2 / WPA3 compared like "types of locks" |
| Threats & Fixes | Common attacks and the defence for each |
| Checklist | Tick-off checklist with progress bar |
| This Computer | Shows the security mode of the Wi-Fi your laptop is on (run locally only) |

## Requirements

- Streamlit app: Python 3.9+ and `streamlit` (see `requirements.txt`).
- Command-line tools (`run_audit.py`): Python 3.8+, standard library only.

## Quick start

```bash
# 1. See the auditor in action on bundled sample data
python run_audit.py audit configs/sample_insecure_config.json
python run_audit.py audit configs/sample_secure_config.json --format html --out reports/secure.html

# 2. Audit YOUR router: generate a blank file, fill it from the router admin page
python run_audit.py template > configs/my_router.json
python run_audit.py audit configs/my_router.json --format html --out reports/my_router.html

# 3. Check a passphrase (typed hidden)
python run_audit.py passphrase

# 4. Inspect this computer's current Wi-Fi connection (Windows / Linux / macOS)
python run_audit.py local

# 5. Run tests
python -m unittest discover tests -v
```

`audit` exits with code 1 if any check fails, so it can be used in a periodic checklist or script.

## Project layout

```
app.py                    Streamlit web app
run_audit.py              command-line interface
wifi_audit/
  checks.py               rule engine + scoring (13 checks)
  passphrase.py           passphrase strength estimator
  local_scan.py           read-only local connection inspection
  report.py               Markdown / HTML report generators
configs/                  sample configurations (secure, insecure, partially filled)
reports/                  sample generated reports
docs/                     checklist, lab procedure, record template, protocol & threat tables
tests/                    unit tests
requirements.txt          streamlit dependency
screenshots/              put your redacted lab screenshots here (Report Section 6)
```

## How scoring works

Each check has a weight (e.g. protocol 10, passphrase 9, admin credentials 9). PASS earns full weight, WARN half, FAIL zero. Items with no data are marked *Not assessed* and excluded from the score. Grades: A >= 90, B >= 75, C >= 60, D >= 40, F below.

## Completing the report

The report states that router model, screenshots and measured values must come from your own authorised lab. Follow `docs/lab_procedure.md`, fill `configs/my_router.json`, save the generated report in `reports/`, and add redacted screenshots to `screenshots/` (Figures 6.1-6.3).

## Limitations

A configuration review cannot guarantee a network is fully secure. Results depend on router model, firmware and the accuracy of the values entered. Enterprise features (802.1X/RADIUS, wireless IDS) are future scope.
