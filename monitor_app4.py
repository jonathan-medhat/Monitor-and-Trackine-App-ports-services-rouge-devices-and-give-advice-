import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import subprocess
import threading
import re
import socket
import psutil
from datetime import datetime
import time

class AutoCybersecurityMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 AUTO Monitor & Tracking App - Live Scanning")
        self.root.geometry("1000x800")
        self.root.configure(bg="#1a1a1a")
        
        self.setup_gui()
        self.known_devices = {}
        self.scan_cycle = 30  # Auto-scan every 30 seconds
        self.is_auto_running = False
        self.scan_thread = None
        
        # Start auto-scan after 3 seconds
        self.root.after(3000, self.start_auto_monitoring)
    
    def setup_gui(self):
        # Header
        header = tk.Label(self.root, text="LIVE AUTO MONITORING", font=("Arial", 22, "bold"), 
                         fg="#00ff88", bg="#1a1a1a")
        header.pack(pady=15)
        
        # Control buttons
        control_frame = tk.Frame(self.root, bg="#1a1a1a")
        control_frame.pack(pady=10)
        
        self.auto_btn = tk.Button(control_frame, text="▶️ AUTO SCAN ON", command=self.toggle_auto_scan,
                                 bg="#44ff44", fg="black", font=("Arial", 14, "bold"), width=15, height=2)
        self.auto_btn.pack(side=tk.LEFT, padx=10)
        
        tk.Button(control_frame, text="🔍 MANUAL PORT SCAN", command=self.scan_ports,
                 bg="#ff4444", fg="white", font=("Arial", 12, "bold"), width=18, height=2).pack(side=tk.LEFT, padx=5)
        
        tk.Button(control_frame, text="🛑 STOP ALL", command=self.stop_all_scans,
                 bg="#ffaa00", fg="black", font=("Arial", 12, "bold"), width=12, height=2).pack(side=tk.LEFT, padx=5)
        
        # Settings frame
        settings_frame = tk.LabelFrame(self.root, text="⚙️ Auto-Scan Settings", font=("Arial", 12, "bold"), 
                                      fg="#00ff88", bg="#1a1a1a")
        settings_frame.pack(pady=10, padx=15, fill="x")
        settings_frame.configure(bg="#1a1a1a")
        
        tk.Label(settings_frame, text="Target IP:", fg="white", bg="#1a1a1a").grid(row=0, column=0, padx=5, pady=5)
        self.target_ip = tk.Entry(settings_frame, width=15, font=("Courier", 10), bg="#2d2d2d", fg="white")
        self.target_ip.insert(0, "127.0.0.1")
        self.target_ip.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(settings_frame, text="Network:", fg="white", bg="#1a1a1a").grid(row=0, column=2, padx=5, pady=5)
        self.network = tk.Entry(settings_frame, width=18, font=("Courier", 10), bg="#2d2d2d", fg="white")
        self.network.insert(0, "192.168.1.0/24")
        self.network.grid(row=0, column=3, padx=5, pady=5)
        
        tk.Label(settings_frame, text="Interval (s):", fg="white", bg="#1a1a1a").grid(row=0, column=4, padx=5, pady=5)
        self.interval_var = tk.StringVar(value="30")
        tk.Entry(settings_frame, textvariable=self.interval_var, width=5, bg="#2d2d2d", fg="white").grid(row=0, column=5, padx=5, pady=5)
        
        # Results tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(pady=10, padx=15, fill="both", expand=True)
        
        # Ports tab
        self.ports_frame = tk.Frame(notebook, bg="#1a1a1a")
        notebook.add(self.ports_frame, text="📡 PORTS")
        self.ports_text = scrolledtext.ScrolledText(self.ports_frame, height=20, width=110, 
                                                  font=("Courier", 9), bg="#0d1b2a", fg="#ff6b6b")
        self.ports_text.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Services tab
        self.services_frame = tk.Frame(notebook, bg="#1a1a1a")
        notebook.add(self.services_frame, text="⚙️ SERVICES")
        self.services_text = scrolledtext.ScrolledText(self.services_frame, height=20, width=110, 
                                                     font=("Courier", 9), bg="#0d1b2a", fg="#4ecdc4")
        self.services_text.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Rogue devices tab
        self.rogue_frame = tk.Frame(notebook, bg="#1a1a1a")
        notebook.add(self.rogue_frame, text="🚨 ROGUE DEVICES")
        self.rogue_text = scrolledtext.ScrolledText(self.rogue_frame, height=20, width=110, 
                                                  font=("Courier", 9), bg="#0d1b2a", fg="#ffe66d")
        self.rogue_text.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Status & Advice
        status_frame = tk.Frame(self.root, bg="#1a1a1a")
        status_frame.pack(pady=10, padx=15, fill="x")
        
        self.status_label = tk.Label(status_frame, text="🟢 LIVE MONITORING ACTIVE", 
                                   fg="#00ff88", bg="#1a1a1a", font=("Arial", 12, "bold"))
        self.status_label.pack(side=tk.LEFT)
        
        self.advice_label = tk.Label(status_frame, text="Auto-scanning every 30 seconds...", 
                                   fg="#ffaa00", bg="#1a1a1a", font=("Arial", 11), wraplength=900)
        self.advice_label.pack(side=tk.RIGHT)
    
    def log_to_tab(self, tab_text, msg, tab_widget):
        timestamp = datetime.now().strftime("%H:%M:%S")
        tab_widget.insert(tk.END, f"[{timestamp}] {msg}\n")
        tab_widget.see(tk.END)
        self.root.update_idletasks()
    
    def toggle_auto_scan(self):
        if not self.is_auto_running:
            self.start_auto_monitoring()
        else:
            self.stop_auto_monitoring()
    
    def start_auto_monitoring(self):
        if self.is_auto_running:
            return
        
        self.is_auto_running = True
        self.auto_btn.config(text="⏸️ AUTO SCAN PAUSE", bg="#ff6b6b")
        self.status_label.config(text="🔴 LIVE MONITORING RUNNING", fg="#ff4444")
        self.log_to_tab("PORTS", "🚀 AUTO-MONITORING STARTED - Full cycle every 30s", self.ports_text)
        
        self.scan_cycle_loop()
    
    def stop_auto_monitoring(self):
        self.is_auto_running = False
        self.auto_btn.config(text="▶️ AUTO SCAN ON", bg="#44ff44")
        self.status_label.config(text="🟢 MONITORING PAUSED", fg="#00ff88")
        self.log_to_tab("PORTS", "⏹️ AUTO-MONITORING PAUSED", self.ports_text)
    
    def scan_cycle_loop(self):
        if not self.is_auto_running:
            return
        
        try:
            self.scan_ports(auto=True)
            time.sleep(5)
            self.scan_services(auto=True)
            time.sleep(5)
            self.scan_rogue_devices(auto=True)
        except:
            pass
        
        interval = int(self.interval_var.get() or 30)
        self.root.after(interval * 1000, self.scan_cycle_loop)
    
    def run_single_scan(self, cmd, scan_type, auto=False):
        def scan_thread():
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                output = result.stdout + result.stderr
                
                if scan_type == "ports":
                    self.log_to_tab("PORTS", f"{'AUTO' if auto else 'MANUAL'} PORT SCAN COMPLETE", self.ports_text)
                    self.log_to_tab("PORTS", result.stdout, self.ports_text)
                    self.analyze_ports(result.stdout)
                    
                elif scan_type == "services":
                    self.log_to_tab("SERVICES", f"{'AUTO' if auto else 'MANUAL'} SERVICES SCAN", self.services_text)
                    self.log_to_tab("SERVICES", result.stdout, self.services_text)
                    self.analyze_services(result.stdout)
                    
                elif scan_type == "rogue":
                    self.log_to_tab("ROGUE", f"{'AUTO' if auto else 'MANUAL'} DEVICE DISCOVERY", self.rogue_text)
                    self.log_to_tab("ROGUE", result.stdout, self.rogue_text)
                    self.analyze_rogue(result.stdout)
                    
            except Exception as e:
                self.log_to_tab("PORTS", f"❌ Scan error: {e}", self.ports_text)
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def analyze_ports(self, output):
        risks = []
        if "22/tcp" in output:
            risks.append("✅ SSH: Enable key auth")
        if "23/tcp" in output:
            risks.append("🚨 Telnet OPEN - DISABLE!")
        self.update_advice(" | ".join(risks) if risks else "✅ Ports OK")
    
    def analyze_services(self, output):
        if "0.0.0.0" in output:
            self.update_advice("🚨 Services exposed to ALL interfaces!", "ff4444")
        else:
            self.update_advice("✅ Services localhost-bound")
    
    def analyze_rogue(self, output):
        macs = re.findall(r'([a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}[:-]){5}[a-f0-9]{2}', output, re.I)
        if len(macs) > len(self.known_devices):
            self.update_advice(f"🚨 NEW DEVICES: {len(macs)} total", "ff4444")
            self.known_devices = {mac: True for mac in macs}
    
    def update_advice(self, text, color="00ff88"):
        self.advice_label.config(text=text, fg=f"#{color}")
    
    # SCAN METHODS
    def scan_ports(self, auto=False):
        target = self.target_ip.get().strip() or "127.0.0.1"
        cmd = ["nmap", "-sV", "--open", "-T4", target]
        self.run_single_scan(cmd, "ports", auto)
    
    def scan_services(self, auto=False):
        cmd = ["ss", "-tuln"]
        self.run_single_scan(cmd, "services", auto)
    
    def scan_rogue_devices(self, auto=False):
        network = self.network.get().strip() or "192.168.1.0/24"
        cmd = ["netdiscover", "-r", network, "-P", "-s1"]
        self.run_single_scan(cmd, "rogue", auto)
    
    def stop_all_scans(self):
        self.stop_auto_monitoring()
        self.ports_text.delete(1.0, tk.END)
        self.services_text.delete(1.0, tk.END)
        self.rogue_text.delete(1.0, tk.END)
        self.log_to_tab("PORTS", "🛑 ALL SCANS STOPPED & CLEARED", self.ports_text)

if __name__ == "__main__":
    root = tk.Tk()
    app = AutoCybersecurityMonitor(root)
    root.mainloop()
