"""Run this file to open the Tkinter ARP detector application."""
import json
import csv
from datetime import datetime
import queue
import threading
import time
import shutil
import tkinter as tk
from tkinter import ttk, filedialog
from tkinter.simpledialog import askstring
from tkinter import messagebox
from pathlib import Path
from demo_bridge import create_session, take_requests, end_session, submit_request
from PIL import Image, ImageTk
import cv2
from scapy.all import conf

from detector_core import (BASE_DIR, ConfigStore, AlertLogger, AlertService, Monitor,
                           own_info, parse_arp, system_arp, valid_email, send_email,
                           format_alert, LocalDemoMonitor)

BG, PANEL, TEXT, MUTED, ACCENT = "#09121e", "#122235", "#e5edf5", "#9fb0c3", "#39dfba"


class VideoBackground(tk.Canvas):
    """OpenCV decodes the clip; Pillow/ImageTk renders frames in Tk's UI thread."""
    def __init__(self, parent, path):
        super().__init__(parent, height=142, bg=BG, highlightthickness=0)
        self.capture = cv2.VideoCapture(str(path))
        self.callback = None
        self.frame_count = 0
        self.image_item = self.create_image(0, 0, anchor="nw")
        self.create_text(24, 45, anchor="w", text="ARP SPOOFING DETECTOR",
                         fill="white", font=("Segoe UI", 22, "bold"), tags="heading")
        self.create_text(26, 82, anchor="w", text="Observe your network. Investigate unexpected changes.",
                         fill="#b5dbdc", font=("Segoe UI", 11), tags="heading")
        self.interval = max(20, int(1000 / (self.capture.get(cv2.CAP_PROP_FPS) or 24)))
        self.tick()

    def tick(self):
        if self.capture.isOpened():
            ok, frame = self.capture.read()
            if not ok:
                self.capture.set(cv2.CAP_PROP_POS_FRAMES, 0)
                ok, frame = self.capture.read()
            if ok:
                rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                resized = Image.fromarray(rgb).resize((max(self.winfo_width(), 640), 142), Image.Resampling.LANCZOS)
                self.photo = ImageTk.PhotoImage(resized, master=self)
                self.itemconfigure(self.image_item, image=self.photo)
                self.tag_raise("heading")
                self.frame_count += 1
        else:
            self.itemconfigure("heading", text="Video unavailable — check assets/background.mp4")
        self.callback = self.after(self.interval, self.tick)

    def close(self):
        if self.callback:
            self.after_cancel(self.callback)
            self.callback = None
        self.capture.release()


class Application:
    def __init__(self, root, *, first_run=False, config_path=None, log_dir=None, demo_dir=None):
        self.root = root
        self.root.title("ARP Spoofing Detector | Supraja Technologies")
        self.root.geometry("1180x850")
        self.root.minsize(920, 700)
        self.root.configure(bg=BG)
        self.events = queue.Queue()
        self.store = ConfigStore(config_path)
        self.logger = AlertLogger(log_dir)
        self.alerts = AlertService(self.logger, self.events)
        self.monitor = None
        self.demo_dir = Path(demo_dir or BASE_DIR / ".local_demo")
        self.demo_session = None
        self.closing = False
        self.started = None
        self.alert_count = self.email_count = 0
        self.baseline = {}
        self.current_cache = {}
        self.monitor_info = {}
        self.cache_time = "Not read"
        self.session_start = "Not started"
        self.session_end = "Not stopped"
        self.scan_seconds = tk.IntVar(value=5)
        self.auto_start = tk.BooleanVar(value=False)
        self.report_operator = tk.StringVar()
        self.report_notes = tk.StringVar()
        self.scan_settings = tk.StringVar(value="ARP cache scanning every 5 seconds while monitoring")
        self.status = tk.StringVar(value="Stopped — ready to configure")
        self.counters = tk.StringVar(value="ARP replies: 0    Alerts: 0    Emails: 0    Uptime: 00:00")
        self.local = tk.StringVar(value="Choose a connected adapter, then start monitoring.")
        self._style()
        self._build()
        self.load_preferences()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.poll_id = self.root.after(100, self.poll)
        if first_run:
            self.root.after(300, self.first_run)
        if self.auto_start.get():
            self.root.after(2000, self.start)

    def _style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("TButton", background=PANEL, foreground=TEXT, padding=(12, 8))
        style.map("TButton", background=[("active", "#25435e")], foreground=[("disabled", "#6f8192")])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, padding=(16, 10))
        style.map("TNotebook.Tab", background=[("selected", "#205349")])
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT, rowheight=27)
        style.configure("Treeview.Heading", background="#20374c", foreground=TEXT)
        style.map("Treeview", background=[("selected", "#24605a")])
        style.configure("TEntry", fieldbackground="#e9f0f7", foreground="#142030")
        style.configure("TCombobox", fieldbackground="#f1f5f9", foreground="#142030", selectbackground="#205349", selectforeground="white")
        style.map("TCombobox", fieldbackground=[("readonly", "#f1f5f9")], foreground=[("readonly", "#142030")])
        style.configure("TCheckbutton", background=BG, foreground=TEXT)
        style.map("TCheckbutton", foreground=[("active", TEXT)], background=[("active", BG)])

    def _build(self):
        top = ttk.Frame(self.root, padding=(18, 10))
        top.pack(fill="x")
        ttk.Label(top, text="SUPRAJA TECHNOLOGIES", foreground=ACCENT, font=("Segoe UI", 12, "bold")).pack(side="left")
        self.project_button = ttk.Button(top, text="Project Info", command=self.show_project)
        self.project_button.pack(side="right", padx=4)
        ttk.Button(top, text="Email Config", command=self.email_dialog).pack(side="right", padx=4)
        self.video = VideoBackground(self.root, BASE_DIR / "assets" / "background.mp4")
        self.video.pack(fill="x", padx=18)
        controls = ttk.Frame(self.root, padding=(18, 10))
        self.controls = controls
        controls.pack(fill="x")
        self.start_button = ttk.Button(controls, text="Start Monitoring", command=self.start)
        self.start_button.pack(side="left", padx=(0, 8))
        self.stop_button = ttk.Button(controls, text="Stop Monitoring", command=self.stop, state="disabled")
        self.stop_button.pack(side="left")
        ttk.Label(controls, text="Adapter:").pack(side="left", padx=(18, 8))
        self.interfaces = {"Default adapter": None}
        for iface in conf.ifaces.values():
            label = f"{iface.description or iface.name} [{iface.ip or 'no IPv4'}]"
            self.interfaces[label] = iface
        self.interface = tk.StringVar(value="Default adapter")
        self.adapter_box = ttk.Combobox(controls, textvariable=self.interface, values=list(self.interfaces), state="readonly", width=42)
        self.adapter_box.pack(side="left", fill="x", expand=True)
        options = ttk.Frame(self.root, padding=(18, 0))
        options.pack(fill="x")
        ttk.Label(options, text="Cache scan interval (seconds):").pack(side="left")
        self.scan_spin = tk.Spinbox(options, from_=1, to=300, textvariable=self.scan_seconds, width=6,
            bg="#f1f5f9", fg="#101827", buttonbackground="#dbe5ee", insertbackground="#101827",
            selectbackground="#205349", selectforeground="white", disabledbackground="#dbe5ee",
            disabledforeground="#334155", font=("Segoe UI", 12, "bold"), relief="solid", bd=1,
            highlightthickness=1, highlightcolor=ACCENT)
        self.scan_spin.pack(side="left", padx=8, ipady=3)
        ttk.Checkbutton(options, text="Start monitoring on next launch", variable=self.auto_start, command=self.save_preferences).pack(side="left", padx=8)
        demo_tools = ttk.Frame(self.root, padding=(18, 6))
        demo_tools.pack(fill="x")
        self.demo_start_button = ttk.Button(demo_tools, text="Start Local Demo", command=lambda:self.start(local_demo=True))
        self.demo_start_button.pack(side="left", padx=(0, 8))
        ttk.Button(demo_tools, text="Run Local Simulation", command=self.run_local_simulation).pack(side="left", padx=(0, 10))
        ttk.Label(demo_tools, text="Or run python simulate_attack.py after monitoring starts.", foreground=MUTED).pack(side="left")
        ttk.Label(self.root, textvariable=self.scan_settings, foreground=MUTED, padding=(18, 2)).pack(anchor="w")
        self.status_label = ttk.Label(self.root, textvariable=self.status, foreground=ACCENT, padding=(18, 4))
        self.status_label.pack(anchor="w")
        ttk.Label(self.root, textvariable=self.counters, padding=(18, 2)).pack(anchor="w")
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill="both", expand=True, padx=18, pady=10)
        dashboard = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(dashboard, text="Dashboard")
        ttk.Label(dashboard, textvariable=self.local).pack(anchor="w", pady=(0, 8))
        ttk.Label(dashboard, text="Live ARP replies (latest 250; feed sampled during heavy traffic)").pack(anchor="w")
        self.feed = self.table(dashboard, ("Time", "Claimed IP", "Advertised MAC", "Target IP", "State"), height=5)
        self.feed.tag_configure("conflict", foreground="#ff8a8a")
        ttk.Label(dashboard, text="Latest alert", foreground=ACCENT).pack(anchor="w", pady=(8, 0))
        self.alert_text = self.textbox(dashboard, height=7)
        self.set_text(self.alert_text, "No alerts. Start monitoring on a trusted network.")
        self.arp_page = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(self.arp_page, text="ARP Tables")
        tools = ttk.Frame(self.arp_page)
        tools.pack(fill="x")
        ttk.Button(tools, text="Read Current ARP Cache", command=self.scan_arp).pack(side="left")
        ttk.Button(tools, text="Refresh Baseline", command=self.refresh_baseline).pack(side="left", padx=8)
        ttk.Label(self.arp_page, text="Trusted baseline — captured when monitoring starts", foreground=ACCENT).pack(anchor="w", pady=(12, 4))
        self.baseline_table = self.table(self.arp_page, ("IP Address", "MAC Address"), height=5)
        ttk.Label(self.arp_page, text="Current system cache — reading this does not replace the baseline").pack(anchor="w", pady=(12, 4))
        self.cache_table = self.table(self.arp_page, ("IP Address", "MAC Address"), height=5)
        self.logs_page = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(self.logs_page, text="View Logs")
        logbar = ttk.Frame(self.logs_page)
        logbar.pack(fill="x")
        for label, cmd in (("Refresh", self.load_logs), ("Export TXT", lambda:self.export_log("txt")),
                           ("Export CSV", lambda:self.export_log("csv")), ("Clear Logs", self.clear_logs)):
            ttk.Button(logbar, text=label, command=cmd).pack(side="left", padx=(0, 8))
        self.logs_text = self.textbox(self.logs_page, height=16)
        self.load_logs()
        self.network_page = ttk.Frame(self.tabs, padding=18)
        self.tabs.add(self.network_page, text="Network Info")
        ttk.Button(self.network_page, text="Refresh Adapter Information", command=self.network_info).pack(anchor="w")
        self.network_text = self.textbox(self.network_page, height=14)
        self.set_text(self.network_text, "Select a connected adapter above, then refresh to see its IP and MAC.")
        self._reports_page()
        self._project_page()
        self.tabs.bind("<<NotebookTabChanged>>", self._tab_changed)

    def _tab_changed(self, event=None):
        # Give the project team page enough room for every developer at once.
        if self.tabs.select() == str(self.project_page):
            self.video.pack_forget()
        elif not self.video.winfo_manager():
            self.video.pack(fill="x", padx=18, before=self.controls)

    def table(self, parent, columns, height):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, pady=4)
        table = ttk.Treeview(frame, columns=columns, show="headings", height=height)
        for column in columns:
            table.heading(column, text=column)
            table.column(column, width=140, minwidth=80, stretch=True)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=scroll.set)
        table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return table

    def textbox(self, parent, height):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, pady=6)
        box = tk.Text(frame, height=height, bg=PANEL, fg=TEXT, insertbackground=TEXT,
                      relief="flat", wrap="word", font=("Consolas", 10), padx=12, pady=10)
        scroll = ttk.Scrollbar(frame, command=box.yview)
        box.configure(yscrollcommand=scroll.set)
        box.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return box

    @staticmethod
    def set_text(widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _project_page(self):
        data = json.loads((BASE_DIR / "project_info.json").read_text(encoding="utf-8"))
        self.project_page = ttk.Frame(self.tabs, padding=16)
        self.tabs.add(self.project_page, text="Project Info")
        company = data["company"]
        ttk.Label(self.project_page, text=company["name"], font=("Segoe UI", 16, "bold"), foreground=ACCENT).pack(anchor="w")
        ttk.Label(self.project_page, text=f"{company['address']}  |  {company['website']}\n{company['email']}  |  {company['phone']}").pack(anchor="w", pady=(6, 10))
        ttk.Label(self.project_page, text=company["about"], wraplength=830).pack(anchor="w")
        ttk.Label(self.project_page, text="Developer Details — 5 Developers", font=("Segoe UI", 13, "bold"), foreground=ACCENT).pack(anchor="w", pady=(16, 4))
        self.developer_table = self.table(self.project_page, ("Name", "Role", "Email / Contact"), height=5)
        self.developer_table.column("Name", width=130)
        self.developer_table.column("Email / Contact", width=320)
        for developer in data["developers"]:
            contact = " / ".join(value for value in (developer.get("email"), developer.get("contact number")) if value)
            self.developer_table.insert("", "end", values=(developer["name"], developer.get("role", "Developer"), contact))
        ttk.Label(self.project_page, text="Project team details are visible to all users. Edit project_info.json to update the supplied placeholders.", foreground=MUTED, wraplength=830).pack(anchor="w", pady=(8, 0))

    def show_project(self):
        self.tabs.select(self.project_page)

    def first_run(self):
        if self.store.warning:
            messagebox.showwarning("Email settings", self.store.warning, parent=self.root)
        if not valid_email(self.store.config.get("receiver")):
            while True:
                email = askstring("Email Setup", "Enter your email to receive spoofing alerts.\nCancel to use local alerts only.", parent=self.root)
                if email is None:
                    self.status.set("Email setup skipped. Local alerts remain available.")
                    return
                if valid_email(email.strip()):
                    try:
                        self.store.save(dict(self.store.config, receiver=email.strip()))
                    except (ValueError, OSError) as exc:
                        messagebox.showerror("Email settings", str(exc), parent=self.root)
                        return
                    self.email_dialog()
                    return
                messagebox.showwarning("Invalid email", "Enter a valid email address.", parent=self.root)

    def email_dialog(self):
        window = tk.Toplevel(self.root)
        window.title("Email Configuration")
        window.configure(bg=BG)
        window.transient(self.root)
        frame = ttk.Frame(window, padding=22)
        frame.pack(fill="both", expand=True)
        fields = {}
        labels = (("host", "SMTP host"), ("port", "Port (587 STARTTLS / 465 SSL)"),
                  ("sender", "Sender email"), ("password", "SMTP / app password"),
                  ("receiver", "Recipient email"), ("cc", "CC emails (teammates)"))
        for i, (key, label) in enumerate(labels):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky="w", pady=6)
            var = tk.StringVar(value=str(self.store.config.get(key, "")))
            ttk.Entry(frame, textvariable=var, width=37, show="*" if key == "password" else "").grid(row=i, column=1, pady=6, padx=12)
            fields[key] = var
        ttk.Label(frame, text="Settings, including the password, are saved locally.\nYou can instead leave the password blank and set ARP_SMTP_PASSWORD.", wraplength=530, foreground=MUTED).grid(row=len(labels), column=0, columnspan=2, pady=12)
        result = tk.StringVar()
        ttk.Label(frame, textvariable=result, wraplength=530).grid(row=len(labels) + 1, column=0, columnspan=2)

        def save():
            try:
                self.store.save({key: var.get().strip() if key != "password" else var.get() for key, var in fields.items()})
            except (ValueError, OSError) as exc:
                result.set(str(exc))
                return False
            result.set("Settings saved.")
            return True

        def test():
            if not save():
                return
            result.set("Sending test email; result will appear in the main status line.")
            config = dict(self.store.config)
            threading.Thread(target=lambda:self.events.put(("test_email", send_email(config,
                             "ARP Detector test email", "Your ARP Detector email configuration is working."))), daemon=True).start()

        buttons = ttk.Frame(frame)
        buttons.grid(row=len(labels) + 2, column=0, columnspan=2, pady=14)
        ttk.Button(buttons, text="Save", command=save).pack(side="left", padx=6)
        ttk.Button(buttons, text="Send Test Email", command=test).pack(side="left", padx=6)
        ttk.Button(buttons, text="Close", command=window.destroy).pack(side="left", padx=6)

    def start(self, local_demo=False):
        if self.monitor and self.monitor.is_alive():
            return
        try:
            interval = int(self.scan_seconds.get())
            if not 1 <= interval <= 86400:
                raise ValueError()
        except (ValueError, tk.TclError):
            messagebox.showerror("Scanning", "Enter a scan interval between 1 and 300 seconds.", parent=self.root)
            return
        self.save_preferences()
        self.scan_settings.set("Local demo baseline only - no live network scanning" if local_demo else
            f"ARP cache scanning every {interval} seconds while monitoring")
        self.status.set("Capturing baseline from the selected adapter...")
        self.start_button.configure(state="disabled")
        self.demo_start_button.configure(state="disabled")
        self.scan_spin.configure(state="disabled")
        end_session(self.demo_dir)
        self.demo_session = None
        self.stop_button.configure(state="normal")
        self.adapter_box.configure(state="disabled")
        self.started = time.monotonic()
        self.session_start = datetime.now().astimezone().isoformat(timespec="seconds")
        self.session_end = "Monitoring"
        monitor_class = LocalDemoMonitor if local_demo else Monitor
        self.monitor = monitor_class(self.interfaces[self.interface.get()], self.events,
                               lambda event:self.alerts.submit(event, self.store.config), scan_interval=interval)
        self.monitor.start()

    def stop(self):
        if self.monitor and self.monitor.is_alive():
            self.monitor.stop()
            self.status.set("Stopping capture...")
            self.stop_button.configure(state="disabled")

    def refresh_baseline(self):
        if self.monitor and self.monitor.is_alive():
            messagebox.showinfo("Baseline", "Stop monitoring first. Starting again captures a fresh baseline.", parent=self.root)
            return
        if messagebox.askyesno("Refresh trusted baseline", "Only trust a baseline from a known-good network. Capture the current cache as the new baseline?", parent=self.root):
            self.scan_arp(baseline=True)

    def scan_arp(self, baseline=False):
        interface = self.interfaces[self.interface.get()]
        def worker():
            try:
                info = own_info(interface)
                import os
                cache = parse_arp(system_arp(), local_ip=info["my_ip"],
                                  interface=str(interface or conf.iface) if os.name != "nt" else None)
                self.events.put(("baseline" if baseline else "cache", (cache, info)))
            except Exception as exc:
                self.events.put(("error", str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def network_info(self):
        interface = self.interfaces[self.interface.get()]
        def worker():
            try:
                self.events.put(("network", own_info(interface)))
            except Exception as exc:
                self.events.put(("error", str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def load_logs(self):
        try:
            self.set_text(self.logs_text, self.logger.read())
        except OSError as exc:
            self.status.set(f"Unable to read logs: {exc}")

    def export_log(self, kind):
        source = self.logger.csv_path if kind == "csv" else self.logger.txt_path
        if not source.exists():
            messagebox.showinfo("Export", "No alerts have been recorded yet.", parent=self.root)
            return
        destination = filedialog.asksaveasfilename(parent=self.root, defaultextension=f".{kind}", filetypes=[(kind.upper(), f"*.{kind}")])
        if destination:
            try:
                with self.logger.lock:
                    shutil.copyfile(source, destination)
                self.status.set(f"Exported {kind.upper()} log.")
            except OSError as exc:
                messagebox.showerror("Export failed", str(exc), parent=self.root)

    def clear_logs(self):
        if messagebox.askyesno("Clear logs", "Delete this version's saved alert logs? Export them first if needed.", parent=self.root):
            try:
                with self.logger.lock:
                    self.logger.csv_path.unlink(missing_ok=True)
                    self.logger.txt_path.unlink(missing_ok=True)
                self.load_logs()
            except OSError as exc:
                messagebox.showerror("Clear logs", str(exc), parent=self.root)

    def poll(self):
        if self.demo_session and self.monitor and self.monitor.is_alive():
            for request in take_requests(self.demo_dir, self.demo_session):
                if not self.monitor.process_demo(request['claimed_ip'], request['fake_mac']):
                    self.status.set("Local demo conflict already reported or monitoring stopped.")
        for _ in range(200):
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "packet":
                self.feed.insert("", "end", values=(value["time"], value["ip"], value["mac"], value["target"],
                                 "DEMO CONFLICT" if value.get("simulation") else "CONFLICT" if value["conflict"] else "Observed"), tags=("conflict",) if value["conflict"] else ())
                children = self.feed.get_children()
                if len(children) > 250:
                    self.feed.delete(children[0])
                self.feed.yview_moveto(1)
            elif kind == "alert":
                self.alert_count += 1
                self.set_text(self.alert_text, format_alert(value))
                self.status.set(f"{'LOCAL DEMO conflict' if value.get('simulation') else 'Possible spoofing'} detected for {value['spoofed_ip']}")
                self.load_logs()
            elif kind in ("baseline", "cache"):
                cache, info = value
                self.monitor_info = dict(info)
                if kind == "cache":
                    self.current_cache = dict(cache)
                    self.cache_time = datetime.now().isoformat(timespec="seconds")
                table = self.baseline_table if kind == "baseline" else self.cache_table
                table.delete(*table.get_children())
                for ip, mac in cache.items():
                    table.insert("", "end", values=(ip, mac))
                if kind == "baseline":
                    self.baseline = cache
                    if not self.closing and self.monitor and self.monitor.is_alive():
                        try:
                            self.demo_session = create_session(self.demo_dir, cache, info)
                        except OSError as exc:
                            self.status.set(f"Local simulator unavailable: {exc}")
                    self.local.set(f"Your IP: {info['my_ip']}    MAC: {info['my_mac']}    Baseline entries: {len(cache)}")
            elif kind == "report":
                self.status.set(f"PDF saved: {value}")
            elif kind == "network":
                self.set_text(self.network_text, "\n\n".join(f"{key.replace('_', ' ').title()}: {val}" for key, val in value.items()))
            elif kind in ("email", "test_email"):
                ok, message = value
                if ok and kind == "email":
                    self.email_count += 1
                self.status.set(message)
            elif kind == "stopped":
                self.session_end = datetime.now().astimezone().isoformat(timespec="seconds")
                self.start_button.configure(state="normal")
                self.demo_start_button.configure(state="normal")
                self.scan_spin.configure(state="normal")
                end_session(self.demo_dir)
                self.demo_session = None
                self.stop_button.configure(state="disabled")
                self.adapter_box.configure(state="readonly")
                self.started = None
                if self.status.get() == "Stopping capture...":
                    self.status.set("Stopped")
            elif kind in ("status", "error"):
                self.status.set(value)
        elapsed = int(time.monotonic() - self.started) if self.started else 0
        packets = self.monitor.packet_count if self.monitor else 0
        scans = self.monitor.scan_count if self.monitor else 0
        self.status_label.configure(foreground=ACCENT if not self.started or int(time.monotonic() * 2) % 2 else "#9af2df")
        demos = getattr(self.monitor, 'demo_count', 0) if self.monitor else 0
        self.counters.set(f"ARP replies: {packets}    Demo events: {demos}    Cache scans: {scans}    Alerts: {self.alert_count}    Emails: {self.email_count}    Uptime: {elapsed // 60:02d}:{elapsed % 60:02d}")
        if not self.closing:
            self.poll_id = self.root.after(100, self.poll)

    def load_preferences(self):
        try:
            data = json.loads((BASE_DIR / "monitor_settings.json").read_text(encoding="utf-8"))
            self.scan_seconds.set(max(1, min(300, int(data.get("scan_interval", 5)))))
            self.auto_start.set(bool(data.get("auto_start", False)))
        except (OSError, ValueError, TypeError):
            pass

    def save_preferences(self):
        try:
            interval = int(self.scan_seconds.get())
            if not 1 <= interval <= 300:
                raise ValueError("Scan interval must be between 1 and 300 seconds")
            (BASE_DIR / "monitor_settings.json").write_text(json.dumps({"scan_interval": interval,
                "auto_start": self.auto_start.get()}, indent=2), encoding="utf-8")
        except (OSError, ValueError, tk.TclError) as exc:
            self.status.set(f"Could not save monitoring options: {exc}")

    def _reports_page(self):
        page = ttk.Frame(self.tabs, padding=18)
        self.tabs.add(page, text="Reports")
        ttk.Label(page, text="Monitoring reports", foreground=ACCENT, font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(page, text="Export saved alerts, sender evidence, trusted baseline and the latest cache.\nReal attacker identity cannot be established from ARP. Passwords are not captured.", wraplength=800).pack(anchor="w", pady=12)
        ttk.Label(page, text="Prepared by (optional)").pack(anchor="w")
        ttk.Entry(page, textvariable=self.report_operator, width=50).pack(anchor="w", pady=6)
        ttk.Label(page, text="Analyst notes (optional)").pack(anchor="w")
        ttk.Entry(page, textvariable=self.report_notes, width=90).pack(anchor="w", pady=6)
        buttons = ttk.Frame(page)
        buttons.pack(anchor="w", pady=16)
        ttk.Button(buttons, text="Export PDF Report", command=self.export_pdf).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Export Report Template", command=lambda:self.export_pdf(template=True)).pack(side="left")
        ttk.Label(page, text="Saved alerts can span multiple sessions. Counters describe the current application session.\nContinuous scanning runs while monitoring is active. Start with a trusted ARP baseline.\nThe application detects changes and sends alerts; it does not automatically block devices.", wraplength=800, foreground=MUTED).pack(anchor="w", pady=16)

    def export_pdf(self, template=False):
        destination = filedialog.asksaveasfilename(parent=self.root, defaultextension=".pdf",
            initialfile="arp_report_template.pdf" if template else "arp_monitoring_report.pdf",
            filetypes=[("PDF", "*.pdf")])
        if not destination:
            return
        events = []
        try:
            with self.logger.lock:
                if self.logger.csv_path.exists():
                    with self.logger.csv_path.open(newline="", encoding="utf-8") as stream:
                        events = list(csv.DictReader(stream))
        except OSError as exc:
            messagebox.showerror("Report", str(exc), parent=self.root)
            return
        snapshot = {"operator":self.report_operator.get(), "notes":self.report_notes.get(),
            "info":dict(self.monitor_info), "baseline":dict(self.baseline), "cache":dict(self.current_cache),
            "cache_time":self.cache_time, "status":self.status.get(), "events":events,
            "session_start":self.session_start, "session_end":self.session_end,
            "packets":self.monitor.packet_count if self.monitor else 0,
            "scans":self.monitor.scan_count if self.monitor else 0,
            "demos":getattr(self.monitor, 'demo_count', 0) if self.monitor else 0,
            "alerts":self.alert_count, "emails":self.email_count}
        def worker():
            try:
                from report_generator import build_report
                build_report(destination, snapshot, template=template)
                self.events.put(("report", destination))
            except Exception as exc:
                self.events.put(("error", f"PDF export failed: {exc}"))
        threading.Thread(target=worker, daemon=True).start()

    def run_local_simulation(self):
        if not self.demo_session or not self.monitor or not self.monitor.is_alive():
            messagebox.showinfo("Local simulation", "Start Monitoring or Start Local Demo first.", parent=self.root)
            return
        try:
            request, path = submit_request(self.demo_dir)
            self.status.set(f"Local demo submitted for {request['claimed_ip']}; awaiting detection.")
        except (ValueError, OSError) as exc:
            messagebox.showerror("Local simulation", str(exc), parent=self.root)

    def close(self):
        if self.closing:
            return
        self.closing = True
        end_session(self.demo_dir)
        self.demo_session = None
        if self.monitor:
            self.monitor.stop()
        self.status.set("Closing — finishing capture and queued alerts...")
        self._finish_close()

    def _finish_close(self):
        if (self.monitor and self.monitor.is_alive()) or self.alerts.jobs.unfinished_tasks:
            self.root.after(100, self._finish_close)
            return
        self.alerts.close()
        self.video.close()
        self.root.after_cancel(self.poll_id)
        self.root.destroy()


def main():
    # Native-size text avoids Windows bitmap scaling blur where supported.
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass
    root = tk.Tk()
    root.withdraw()
    splash = tk.Toplevel(root)
    splash.title("ARP Detector — Starting")
    splash.geometry("760x230")
    splash.configure(bg=BG)
    animation = VideoBackground(splash, BASE_DIR / "assets" / "background.mp4")
    animation.pack(fill="both", expand=True)
    ttk.Label(splash, text="Supraja Technologies | Loading application...").pack(pady=10)
    def launch():
        animation.close()
        splash.destroy()
        root.deiconify()
        Application(root, first_run=True)
    splash.protocol("WM_DELETE_WINDOW", lambda: (animation.close(), root.destroy()))
    root.after(1200, launch)
    root.mainloop()


if __name__ == "__main__":
    main()
