# Update verification

Changes: automatic monitoring falls back from an adapter with an empty baseline to an IPv4 adapter with a nonempty ARP cache; added Email Config button; enabled first-run configuration checks. Explicit adapter selections remain respected.

17 GUI/integration checks passed. Actual default monitoring successfully selected an adapter with a real baseline and started capture. A controlled Scapy conflict passed directly to the running monitor appeared on the dashboard and in local logs. No spoofed packet was transmitted on the network and no actual attack was observed.

One email was sent through the application alert service using the supplied Gmail credentials. Gmail accepted the message and the dashboard recorded one successful email. Subject: [TEST ONLY] ARP Detector alert verification. Receiver must check Inbox or Spam to confirm receipt.

Alerts require an ARP reply with a changed MAC for an IP present in the trusted baseline. Normal traffic does not generate spoofing alerts. The receiver is the address configured in email_config.json.

This ZIP retains the supplied email configuration, including the app password. Keep it private.
