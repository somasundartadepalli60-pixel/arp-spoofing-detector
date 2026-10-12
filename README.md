# ARP Spoofing Detector - enhanced edition

## Setup
1. Install Python 3.10 or later with Tcl/Tk, and Npcap on Windows.
2. Open a terminal in this folder and run `python -m pip install -r requirements.txt`.
3. Run `python arp_spoofing_detector.py` or double-click `start_windows.bat`.

## Your local demonstration flow
Python files are run, not separately compiled:
1. In the extracted folder run `python arp_spoofing_detector.py`.
2. Click **Start Monitoring** to watch a real adapter with a trusted cache. Alternatively click **Start Local Demo** for a synthetic offline baseline when there is no suitable network or capture driver.
3. Keep the detector open. In a second terminal in the SAME extracted folder run `python simulate_attack.py`.
4. The simulator picks an existing baseline IP and a fresh fake MAC. The GUI shows **DEMO CONFLICT**, writes logs, and submits an email with subject beginning **[LOCAL DEMO]** to the configured receiver.
5. Check Inbox or Spam. The GUI email counter means SMTP accepted the message, not confirmed inbox delivery.

**Run Local Simulation** performs the same local request without opening another terminal. Re-running generates a different MAC, producing another demo alert. An explicitly repeated IP/MAC pair is suppressed within that session.
The simulator uses a session-scoped local file bridge and the detector's ARP comparison logic. It does not send spoofed network traffic or poison the system cache. The fake IP is a claimed existing baseline IP, not an arbitrary unknown IP. A new unknown IP alone is not evidence of ARP spoofing.
A demo is labelled in the dashboard, TXT/CSV evidence, PDF report and email. Demo observations do not suppress subsequent real-network alerts.
Kali, Ettercap and other external attack applications are not required. SMTP delivery still requires Internet access and valid credentials.

## Options and continuous scanning
- Select an IPv4 adapter or use Default adapter. Automatic selection can fall back to an adapter with a nonempty ARP cache.
- Start Monitoring captures a trusted baseline, then captures ARP replies and repeatedly reads the system ARP cache. Set the cache scan interval from 1 to 300 seconds before starting.
- The start-on-next-launch option is saved locally, along with the interval. It is off by default.
- Stop Monitoring stops both capture and scanning. An outstanding system-cache read can take up to its eight-second timeout to finish.
- Only changed mappings for baseline IPs alert. Unknown IPs are not automatically trusted or treated as attackers. Duplicate IP/MAC conflicts are suppressed per monitoring session across packet and cache observations.
- Continuous monitoring is detection and alerting. It does not block traffic or guarantee prevention.

## Alerts and email
Dashboard conflicts, TXT/CSV logs, desktop notifications and email use the same alert flow. Email Config supports saving settings and sending an explicit test email. Every alert goes to the configured receiver, not to an automatically discovered device owner.
`ARP_SMTP_PASSWORD` takes precedence over the password in email_config.json. Use the sender account's app password. Port 587 uses STARTTLS; port 465 uses SSL.
This delivered configuration retains your supplied app password. Do not share the ZIP or configuration publicly.

## Evidence
Reports distinguish the ARP claimed IP, baseline MAC, changed advertised MAC and Ethernet source MAC. ARP cannot prove a real attacker IP or identity. A cache-derived observation has no Ethernet-source or packet-target evidence; these fields are shown as unknown.
Password capture and packet-payload capture are not implemented.

## ARP tables and PDF reports
ARP Tables shows the trusted baseline and latest cache separately. Automatic scans update the latest cache without replacing the baseline. Stop monitoring before manually refreshing the baseline.
Reports exports a PDF with observation period, adapter details, traffic/scan counters, saved alert evidence, the trusted table, latest cache and analyst notes. Saved alerts can span multiple sessions; counters describe the current application or monitoring session as labelled.
Reports also exports a reusable PDF outline/template. A copy is included as report_template.pdf.
No email passwords are included in PDF reports.

## Verification
Run `python test_application.py` for offline detector, deduplication, parser, logging and PDF checks. These tests do not capture packets or send email. See VERIFICATION.md for GUI and integration results and limitations.

## Display clarity
The cache interval uses larger high-contrast text, explicit selection colors and native up/down controls. Change it while stopped. Windows DPI awareness is enabled where available to reduce bitmap scaling blur.
