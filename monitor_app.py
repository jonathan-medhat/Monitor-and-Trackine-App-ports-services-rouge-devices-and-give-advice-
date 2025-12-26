import tkinter as tk
from tkinter import scrolledtext, messagebox
import subprocess
import threading
import re
import socket

class MonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Kali Monitor & Tracking App v1.0")
        self.root.geometry("800x600")
        
        # Title
        title = tk.Label(root, text="Cybersecurity Monitor", font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        # Buttons frame
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="🔍 Scan Local Ports (nmap)", 
                 command=self.scan_ports, bg="#ff6b6b", width=20).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="🌐 Discover Devices (netdiscover)", 
                 command=self.scan_devices, bg="#4ecdc4", width=22).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="💻 Local Services (ss)", 
                 command=self.scan_services, bg="#45b7d1", width=20).pack(side=tk.LEFT, padx=5)
        
        # Output area
        tk.Label(root, text="Scan Results:", font=("Arial", 10, "bold")).pack(anchor=tk.W, padx=10)
        self.output = scrolledtext.ScrolledText(root, height=20, width=90)
        self.output.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
        
        # Advice area
        self.advice_label = tk.Label(root, text="Click a button to start scanning...", 
                                   fg="orange", font=("Arial", 12, "bold"), wraplength=780)
        self.advice_label.pack(pady=10)
        
        # Status
        self.status_label = tk.Label(root, text="Ready", fg="green")
        self.status_label.pack()
    
    def log(self, message):
        self.output.insert(tk.END, message + "\n")
        self.output.see(tk.END)
        self.root.update()
    
    def update_status(self, status):
        self.status_label.config(text=status)
    
    def generate_advice(self, output, scan_type):
        advice = ""
        output_lower = output.lower()
        
        if scan_type == "ports":
            if "22/tcp open" in output:
                advice = "✅ SSH (22) detected: Good, but enable key authentication & disable password login"
            elif "23/tcp open" in output:
                advice = "❌ Telnet (23) OPEN - CRITICAL: Disable immediately, use SSH instead!"
            elif "80/tcp open" in output or "443/tcp open" in output:
                advice = "🌐 Web services running: Check for vulnerabilities with Nikto/OWASP ZAP"
        
        elif scan_type == "devices":
            if "unknown" in output_lower or len(re.findall(r'[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}', output)) > 5:
                advice = "⚠️ Multiple/Unknown devices found: Review MAC addresses, isolate suspicious ones"
            else:
                advice = "✅ Network looks clean - no obvious rogue devices"
        
        elif scan_type == "services":
            if "LISTEN" in output and "0.0.0.0" in output:
                advice = "⚠️ Services listening on all interfaces (0.0.0.0) - Restrict to localhost if possible"
        
        self.advice_label.config(text=advice or "No specific risks detected")
    
    def run_scan(self, cmd, scan_type):
        def thread_scan():
            self.update_status(f"Scanning... ({scan_type})")
            self.log(f"Running: {' '.join(cmd)}")
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                self.log("="*60)
                self.log(result.stdout)
                if result.stderr:
                    self.log(f"Warnings: {result.stderr}")
                self.generate_advice(result.stdout + result.stderr, scan_type)
                self.log("="*60)
            except subprocess.TimeoutExpired:
                self.log("❌ Scan timeout - network too slow or target unresponsive")
            except Exception as e:
                self.log(f"❌ Error: {e}")
            finally:
                self.update_status("Ready")
        
        threading.Thread(target=thread_scan, daemon=True).start()
    
    def scan_ports(self):
        cmd = ["nmap", "-sV", "-p-", "--open", "-T4", "127.0.0.1"]
        self.run_scan(cmd, "ports")
    
    def scan_devices(self):
        # Auto-detect local subnet
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            subnet = ".".join(local_ip.split(".")[:-1]) + ".0/24"
            cmd = ["netdiscover", "-r", subnet, "-P"]
        except:
            cmd = ["netdiscover", "-r", "192.168.1.0/24", "-P"]
        self.run_scan(cmd, "devices")
    
    def scan_services(self):
        cmd = ["ss", "-tuln"]
        self.run_scan(cmd, "services")

if __name__ == "__main__":
    root = tk.Tk()
    app = MonitorApp(root)
    root.mainloop()
