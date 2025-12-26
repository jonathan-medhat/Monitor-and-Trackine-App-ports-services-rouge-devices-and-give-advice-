import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import subprocess
import threading
import re
import socket
import psutil

class MonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Kali Advanced Monitor & Tracking v2.0")
        self.root.geometry("900x700")
        
        # Title
        title = tk.Label(root, text="🔒 Advanced Cybersecurity Monitor", font=("Arial", 18, "bold"))
        title.pack(pady=10)
        
        # Input frame for manual targets
        input_frame = tk.LabelFrame(root, text="Target Configuration", font=("Arial", 12, "bold"))
        input_frame.pack(pady=10, padx=10, fill=tk.X)
        
        tk.Label(input_frame, text="Target IP:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.target_ip = tk.Entry(input_frame, width=15, font=("Courier", 10))
        self.target_ip.insert(0, "127.0.0.1")
        self.target_ip.grid(row=0, column=1, padx=5)
        
        tk.Label(input_frame, text="Network Range:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.network_range = tk.Entry(input_frame, width=18, font=("Courier", 10))
        self.network_range.insert(0, "192.168.1.0/24")
        self.network_range.grid(row=0, column=3, padx=5)
        
        tk.Label(input_frame, text="Interface:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.interface = ttk.Combobox(input_frame, width=12, values=["eth0", "wlan0", "wlan0mon"])
        self.interface.set("eth0")
        self.interface.grid(row=1, column=1, padx=5)
        
        # Main buttons frame
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=10)
        
        # Row 1: Basic scans
        tk.Button(btn_frame, text="🔍 Port Scan", command=self.scan_ports, 
                 bg="#ff6b6b", width=12, height=2).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="🌐 Device Discovery", command=self.scan_devices, 
                 bg="#4ecdc4", width=14, height=2).grid(row=0, column=1, padx=5)
        tk.Button(btn_frame, text="📊 Local Services", command=self.scan_services, 
                 bg="#45b7d1", width=12, height=2).grid(row=0, column=2, padx=5)
        
        # Row 2: Advanced features
        tk.Button(btn_frame, text="🕵️ ARP Spoof Detect", command=self.detect_arp_spoof, 
                 bg="#feca57", width=14, height=2).grid(row=1, column=0, padx=5, pady=5)
        tk.Button(btn_frame, text="⚡ ARP Spoof Attack", command=self.arp_spoof_demo, 
                 bg="#ff9ff3", width=14, height=2).grid(row=1, column=1, padx=5, pady=5)
        tk.Button(btn_frame, text="📈 System Monitor", command=self.system_monitor, 
                 bg="#54a0ff", width=12, height=2).grid(row=1, column=2, padx=5, pady=5)
        
        # Output area
        tk.Label(root, text="Scan Results:", font=("Arial", 12, "bold")).pack(anchor=tk.W, padx=10)
        self.output = scrolledtext.ScrolledText(root, height=22, width=100, font=("Courier", 9))
        self.output.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
        
        # Advice and status
        advice_frame = tk.Frame(root)
        advice_frame.pack(pady=5, fill=tk.X, padx=10)
        
        self.advice_label = tk.Label(advice_frame, text="Enter target IP and click scan buttons", 
                                   fg="orange", font=("Arial", 12, "bold"), wraplength=850)
        self.advice_label.pack(side=tk.LEFT, expand=True)
        
        self.status_label = tk.Label(advice_frame, text="Ready", fg="green", font=("Arial", 10))
        self.status_label.pack(side=tk.RIGHT)
    
    def log(self, message):
        self.output.insert(tk.END, f"[{self.timestamp()}] {message}\n")
        self.output.see(tk.END)
        self.root.update()
    
    def timestamp(self):
        return subprocess.run(["date", "+%H:%M:%S"], capture_output=True, text=True).stdout.strip()
    
    def update_status(self, status):
        self.status_label.config(text=status)
    
    def get_target(self):
        return self.target_ip.get().strip() or "127.0.0.1"
    
    def get_network(self):
        return self.network_range.get().strip() or "192.168.1.0/24"
    
    def get_interface(self):
        return self.interface.get() or "eth0"
    
    def generate_advice(self, output, scan_type):
        advice = f"Analysis for {scan_type}: "
        output_lower = output.lower()
        
        if scan_type == "ports":
            open_ports = re.findall(r'(\d+)/tcp\s+open', output)
            if "22/tcp" in output:
                advice += "✅ SSH detected - Enable key auth"
            if "23/tcp" in output:
                advice += "❌ CRITICAL: Telnet open - Disable NOW!"
            if open_ports:
                advice += f"Found {len(open_ports)} open ports"
        
        elif scan_type == "arp_spoof":
            if "ARP mismatch" in output or "duplicate IP" in output_lower:
                advice += "🚨 ARP SPOOFING DETECTED! Attacker in network"
            else:
                advice += "✅ No ARP spoofing detected"
        
        elif scan_type == "devices":
            macs = len(re.findall(r'[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}', output))
            advice += f"Found {macs} devices - Check unknown MACs"
        
        self.advice_label.config(text=advice)
    
    def run_scan(self, cmd, scan_type, timeout=120):
        def thread_scan():
            target = self.get_target()
            iface = self.get_interface()
            self.update_status(f"Scanning {target}... ({scan_type})")
            self.log(f"Target: {target} | Interface: {iface}")
            self.log(f"Command: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                self.log("="*80)
                self.log(result.stdout)
                if result.stderr:
                    self.log(f"STDERR: {result.stderr}")
                self.generate_advice(result.stdout + result.stderr, scan_type)
            except subprocess.TimeoutExpired:
                self.log("⏰ TIMEOUT - Target slow/unresponsive")
            except Exception as e:
                self.log(f"❌ ERROR: {e}")
            finally:
                self.update_status("Ready")
        
        threading.Thread(target=thread_scan, daemon=True).start()
    
    def scan_ports(self):
        target = self.get_target()
        cmd = ["nmap", "-sV", "-sC", "-p-", "--open", "-T4", target]
        self.run_scan(cmd, "ports")
    
    def scan_devices(self):
        network = self.get_network()
        cmd = ["netdiscover", "-r", network, "-P"]
        self.run_scan(cmd, "devices", 300)
    
    def scan_services(self):
        cmd = ["ss", "-tuln", "-o"]
        self.run_scan(cmd, "services", 30)
    
    def detect_arp_spoof(self):
        iface = self.get_interface()
        cmd = ["bettercap", "-iface", iface, "-eval", "arp.spoof.lookup on; net.probe on; net.show; sleep 5; arp.print_table"]
        self.run_scan(cmd, "arp_spoof", 60)
    
    def arp_spoof_demo(self):
        if messagebox.askyesno("WARNING", "This simulates ARP spoofing (EDUCATIONAL ONLY)\nUse on YOUR network/lab only! Continue?"):
            target = self.get_target()
            iface = self.get_interface()
            cmd = ["bettercap", "-iface", iface, "-eval", 
                   f"set arp.spoof.targets {target}; arp.spoof on; sleep 10; arp.spoof off"]
            self.run_scan(cmd, "arp_spoof_demo", 30)
    
    def system_monitor(self):
        def monitor_loop():
            while True:
                cpu = psutil.cpu_percent(interval=1)
                net_io = psutil.net_io_counters()
                self.log(f"CPU: {cpu:.1f}% | RX: {net_io.bytes_recv/1024/1024:.1f}MB TX: {net_io.bytes_sent/1024/1024:.1f}MB")
                self.root.after(5000, monitor_loop)  # Update every 5s
                break  # Run once for demo
        
        threading.Thread(target=monitor_loop, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = MonitorApp(root)
    root.mainloop()
