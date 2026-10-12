"""ARP observation, local configuration, logging and SMTP services."""
import os
import json
import threading
import csv
import subprocess
import socket
import smtplib
import re
import ssl
import ipaddress
import queue
import time
from pathlib import Path
from datetime import datetime
from html import escape
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from scapy.all import sniff, ARP, Ether, conf, get_if_addr, get_if_hwaddr
from plyer import notification

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = {"host": "smtp.gmail.com", "port": 587, "sender": "",
                  "password": "", "receiver": "", "cc": ""}
FIELDS = ["time", "spoofed_ip", "expected_mac", "spoofed_mac", "ether_mac",
          "attacker_ip", "my_ip", "my_mac", "target_ip", "target_mac", "interface"]


def valid_email(value):
    return bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value or ""))


class ConfigStore:
    def __init__(self, path=None):
        self.path = Path(path or BASE_DIR / "email_config.json")
        self.warning = ""
        self.config = dict(DEFAULT_CONFIG)
        if self.path.exists():
            try:
                saved = json.loads(self.path.read_text(encoding="utf-8"))
                if not isinstance(saved, dict):
                    raise ValueError("Expected a JSON object")
                saved.setdefault("receiver", saved.get("receiver_email", ""))
                self.config.update({k: saved[k] for k in DEFAULT_CONFIG if k in saved})
            except (OSError, ValueError) as exc:
                self.warning = f"Could not load email settings: {exc}"

    def save(self, config):
        updated = dict(DEFAULT_CONFIG, **config)
        if updated["receiver"] and not valid_email(updated["receiver"]):
            raise ValueError("Enter a valid recipient email address.")
        if updated["sender"] and not valid_email(updated["sender"]):
            raise ValueError("Enter a valid sender email address.")
        if updated.get("cc"):
            cc_addrs = [e.strip() for e in updated["cc"].split(",") if e.strip()]
            for addr in cc_addrs:
                if not valid_email(addr):
                    raise ValueError(f"Invalid CC email address: {addr}")
        updated["port"] = int(updated["port"])
        if not 1 <= updated["port"] <= 65535:
            raise ValueError("SMTP port must be between 1 and 65535.")
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(updated, indent=2), encoding="utf-8")
        os.replace(temporary, self.path)
        self.config = updated


def system_arp():
    return subprocess.check_output(["arp", "-a"], timeout=8,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).decode(errors="replace")


def parse_arp(text, local_ip=None, interface=None):
    """Read Windows, Linux and macOS arp output, omitting invalid/multicast entries."""
    result = {}
    section = None
    for line in text.splitlines():
        # Windows adapter header (works without depending on the localized label).
        header = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+---\s+0x", line)
        if header:
            section = header.group(1)
            continue
        if local_ip and section and section != local_ip:
            continue
        if interface and " on " in line and line.rsplit(" on ", 1)[1].split()[0] != interface:
            continue
        if interface and section is None and " on " not in line:
            parts = line.split()
            if len(parts) >= 5 and parts[-1] != interface:
                continue
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        mac_match = re.search(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b", line)
        if not ip_match or not mac_match:
            continue
        try:
            ip = ipaddress.IPv4Address(ip_match.group())
        except ValueError:
            continue
        mac = mac_match.group().lower().replace("-", ":")
        if ip.is_multicast or ip.is_unspecified or ip.is_loopback or int(mac[:2], 16) & 1 or mac == "00:00:00:00:00:00":
            continue
        result[str(ip)] = mac
    return result


def own_info(interface):
    adapter = interface or conf.iface
    ip, mac = get_if_addr(adapter), get_if_hwaddr(adapter).lower()
    if not ip or ip == "0.0.0.0":
        raise ValueError("The selected adapter has no IPv4 address. Choose a connected adapter.")
    return {"my_ip": ip, "my_mac": mac, "hostname": socket.gethostname(),
            "interface": str(adapter)}


def format_alert(event):
    return (
        ("LOCAL DEMO ONLY - synthetic conflict, not an actual attack\n" if event.get("simulation") else "") +
        f"Possible ARP spoofing detected\nTime: {event['time']}\n\n"
        f"Observed sender\nReal attacker IP: {event['attacker_ip']}\n"
        f"Ethernet source MAC: {event['ether_mac']}\nARP advertised MAC: {event['spoofed_mac']}\n\n"
        f"Your monitoring device\nIP: {event['my_ip']}\nMAC: {event['my_mac']}\n\n"
        f"Packet target\nIP: {event['target_ip']}\nMAC: {event['target_mac']}\n\n"
        f"Impersonated device\nClaimed / spoofed IP: {event['spoofed_ip']}\n"
        f"Original baseline MAC: {event['expected_mac']}\nSpoofed MAC: {event['spoofed_mac']}\n"
        f"Capture interface: {event['interface']}\n\n"
        "Investigate this change. A legitimate device replacement can also change its MAC address.\n"
        "ARP does not establish the sender's real IP or identity."
    )


def send_email(config, subject, body):
    if not all(config.get(k) for k in ("host", "sender", "receiver")):
        return False, "Email not configured; alert remains in local logs."
    try:
        if not valid_email(config["sender"]) or not valid_email(config["receiver"]):
            raise ValueError("Invalid sender or recipient address")
        msg = MIMEMultipart("alternative")
        msg["From"], msg["To"], msg["Subject"] = config["sender"], config["receiver"], subject
        if config.get("cc"):
            msg["Cc"] = config["cc"]
        msg.attach(MIMEText(body, "plain", "utf-8"))
        msg.attach(MIMEText('<html><body><h2>ARP Detector</h2><pre>' + escape(body) + '</pre></body></html>', "html", "utf-8"))
        port = int(config.get("port", 587))
        context = ssl.create_default_context()
        if port == 465:
            client = smtplib.SMTP_SSL(config["host"], port, timeout=10, context=context)
        else:
            client = smtplib.SMTP(config["host"], port, timeout=10)
        with client as smtp:
            smtp.ehlo()
            if port != 465:
                smtp.starttls(context=context)
                smtp.ehlo()
            password = os.environ.get("ARP_SMTP_PASSWORD") or config.get("password", "")
            if password:
                smtp.login(config["sender"], password.strip().replace(" ", ""))
            smtp.send_message(msg)
        return True, "Email sent."
    except Exception as exc:
        return False, f"Email failed: {exc}"


class AlertLogger:
    def __init__(self, directory=None):
        self.directory = Path(directory or BASE_DIR / "logs")
        self.directory.mkdir(parents=True, exist_ok=True)
        # Versioned filenames keep existing legacy logs intact.
        self.csv_path = self.directory / "alerts.csv"
        self.txt_path = self.directory / "alerts.txt"
        self.lock = threading.Lock()

    def write(self, event):
        with self.lock:
            header = not self.csv_path.exists() or self.csv_path.stat().st_size == 0
            with self.csv_path.open("a", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=FIELDS)
                if header:
                    writer.writeheader()
                writer.writerow({key: event.get(key, "") for key in FIELDS})
            with self.txt_path.open("a", encoding="utf-8") as stream:
                stream.write(format_alert(event) + "\n" + "=" * 65 + "\n")

    def read(self):
        with self.lock:
            return self.txt_path.read_text(encoding="utf-8") if self.txt_path.exists() else "No alerts recorded."


class Detector:
    def __init__(self, baseline, info):
        self.baseline, self.info = dict(baseline), dict(info)
        self.seen = set()

    def process(self, packet):
        if not packet.haslayer(ARP) or packet[ARP].op != 2:
            return None, None
        arp = packet[ARP]
        mac = arp.hwsrc.lower()
        ether = packet[Ether].src.lower() if packet.haslayer(Ether) else mac
        expected = self.baseline.get(arp.psrc)
        conflict = bool(expected and mac != expected)
        row = {"time": datetime.now().strftime("%H:%M:%S"), "ip": arp.psrc,
               "mac": mac, "target": arp.pdst, "conflict": conflict}
        event = None
        key = (arp.psrc, mac)
        if conflict and key not in self.seen:
            self.seen.add(key)
            event = dict(self.info, time=datetime.now().isoformat(timespec="seconds"),
                         spoofed_ip=arp.psrc, expected_mac=expected, spoofed_mac=mac,
                         ether_mac=ether, attacker_ip="Unknown (cannot be established from ARP)",
                         target_ip=arp.pdst, target_mac=arp.hwdst.lower())
        return row, event


    def process_cache(self, cache):
        """Compare observed OS-cache changes without inventing packet identities."""
        events = []
        for ip, mac in cache.items():
            expected = self.baseline.get(ip)
            key = (ip, mac)
            if expected and mac != expected and key not in self.seen:
                self.seen.add(key)
                events.append(dict(self.info, time=datetime.now().isoformat(timespec="seconds"),
                    spoofed_ip=ip, expected_mac=expected, spoofed_mac=mac,
                    ether_mac="Unknown (observed in system ARP cache)",
                    attacker_ip="Unknown (cannot be established from ARP)",
                    target_ip="Unknown (cache observation)", target_mac="Unknown"))
        return events


class Monitor(threading.Thread):
    def __init__(self, interface, events, on_alert, scan_interval=5):
        super().__init__(daemon=True)
        self.interface, self.events, self.on_alert = interface, events, on_alert
        self.stop_event = threading.Event()
        self.detector = None
        self.packet_count = 0
        self.scan_interval = max(1, int(scan_interval))
        self.scan_count = 0

    def stop(self):
        self.stop_event.set()

    def process(self, packet):
        if self.stop_event.is_set():
            return
        row, event = self.detector.process(packet)
        if row:
            self.packet_count += 1
            # Bound GUI feed traffic; counts still include every processed reply.
            if self.packet_count % 10 == 0 or self.packet_count < 100 or event:
                if self.events.qsize() < 1000:
                    self.events.put(("packet", row))
        if event:
            self.on_alert(event)

    def process_demo(self, ip, mac):
        if self.stop_event.is_set() or not self.detector:
            return False
        info = self.detector.info
        packet = Ether(src=mac) / ARP(op=2, psrc=ip, hwsrc=mac,
            pdst=info['my_ip'], hwdst=info['my_mac'])
        # Demo observations must not suppress a later real network conflict.
        if not hasattr(self, 'demo_detector'):
            self.demo_detector = Detector(self.detector.baseline, info)
        row, event = self.demo_detector.process(packet)
        if event is None:
            return False
        self.demo_count = getattr(self, 'demo_count', 0) + 1
        row['simulation'] = True
        self.events.put(('packet', row))
        event['simulation'] = True
        event['attacker_ip'] = 'Local demo only (not a real attacker)'
        self.on_alert(event)
        return True

    def run(self):
        try:
            info = own_info(self.interface)
            kwargs = {"local_ip": info["my_ip"]}
            if os.name != "nt":
                kwargs["interface"] = str(self.interface or conf.iface)
            cache_text = system_arp()
            baseline = parse_arp(cache_text, **kwargs)
            # Default capture devices can be disconnected Ethernet adapters.
            # For automatic selection, use an IPv4 adapter with a real cache.
            if not baseline and self.interface is None:
                for candidate in conf.ifaces.values():
                    try:
                        candidate_info = own_info(candidate)
                        candidate_kwargs = {"local_ip": candidate_info["my_ip"]}
                        if os.name != "nt":
                            candidate_kwargs["interface"] = str(candidate)
                        candidate_baseline = parse_arp(cache_text, **candidate_kwargs)
                        if candidate_baseline:
                            self.interface = candidate
                            info, baseline = candidate_info, candidate_baseline
                            break
                    except Exception:
                        continue
            if not baseline:
                raise RuntimeError("The selected adapter's ARP cache is empty. Use the trusted network normally, then start again.")
            self.detector = Detector(baseline, info)
            self.events.put(("baseline", (baseline, info)))
            if self.stop_event.is_set():
                return
            self.events.put(("status", f"Monitoring ARP replies on {info['interface']}"))
            next_scan = time.monotonic()
            while not self.stop_event.is_set():
                if time.monotonic() >= next_scan:
                    try:
                        scan_kwargs = {"local_ip": info["my_ip"]}
                        if os.name != "nt":
                            scan_kwargs["interface"] = str(self.interface or conf.iface)
                        cache = parse_arp(system_arp(), **scan_kwargs)
                        self.scan_count += 1
                        self.events.put(("cache", (cache, info)))
                        for event in self.detector.process_cache(cache):
                            self.on_alert(event)
                    except Exception as exc:
                        self.events.put(("status", f"ARP cache scan failed: {exc}"))
                    next_scan = time.monotonic() + self.scan_interval
                if self.stop_event.is_set():
                    break
                sniff(iface=self.interface or conf.iface, filter="arp", store=False,
                      timeout=1, prn=self.process, stop_filter=lambda _: self.stop_event.is_set())
        except Exception as exc:
            self.events.put(("error", f"Monitoring stopped: {exc}"))
        finally:
            self.events.put(("stopped", None))


class LocalDemoMonitor(Monitor):
    """Synthetic baseline for demonstrations without a driver or live network."""
    def run(self):
        info = {'my_ip':'192.0.2.10','my_mac':'02:00:00:00:00:10',
                'interface':'LOCAL DEMO - no network capture','hostname':socket.gethostname()}
        baseline = {'192.0.2.1':'02:00:00:00:00:01'}
        self.detector = Detector(baseline, info)
        self.events.put(('baseline', (baseline, info)))
        self.events.put(('status','Local demo ready. Run simulate_attack.py; no network capture.'))
        while not self.stop_event.is_set():
            self.events.put(('cache', (baseline, info)))
            if self.stop_event.wait(self.scan_interval):
                break
        self.events.put(('stopped', None))


class AlertService(threading.Thread):
    def __init__(self, logger, events):
        super().__init__(daemon=True)
        self.logger, self.events = logger, events
        self.jobs = queue.Queue()
        self.start()

    def submit(self, event, config):
        # Logging and dashboard visibility are immediate; slow SMTP is serialized.
        try:
            self.logger.write(event)
        except OSError as exc:
            self.events.put(("error", f"Could not save alert log: {exc}"))
        self.events.put(("alert", event))
        self.jobs.put((event, dict(config)))

    def run(self):
        while True:
            item = self.jobs.get()
            try:
                if item is None:
                    return
                event, config = item
                try:
                    notification.notify(title="Local ARP demo" if event.get("simulation") else "Possible ARP spoofing",
                        message=f"{event['spoofed_ip']}: {event['expected_mac']} changed to {event['spoofed_mac']}",
                        app_name="ARP Detector", timeout=10)
                except Exception as exc:
                    self.events.put(("status", f"Desktop notification unavailable: {exc}"))
                result = send_email(config, f"{'[LOCAL DEMO]' if event.get('simulation') else '[ARP ALERT]'} Mapping conflict: {event['spoofed_ip']}", format_alert(event))
                self.events.put(("email", result))
            finally:
                self.jobs.task_done()

    def close(self):
        self.jobs.put(None)
