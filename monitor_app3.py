import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import subprocess
import threading
import re
import socket
import psutil
from datetime import datetime

class CybersecurityMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Monitor & Tracking App - Cybersecurity")
        self.root.geometry("950x750")
        self.root.configure(bg="#1a1a1a")
        
        self.setup_gui()
        self.known_devices = {}  # Track known MACs for rogue detection
    
    def setup_gui(self):
        # Header
        header = tk.Label(self.root, text="Monitor & Tracking App", font=("Arial", 20, "bold"), 
                         fg="#00ff88", bg="#1a1a1a")
        header.pack(pady=15)
        
        # Input section
        input_frame = tk.LabelFrame(self.root, text="🎯 Target Settings", font=("Arial", 12, "bold"), 
                                   fg="#00ff88", bg="#1a1a1a")
        input_frame.pack(pady=10, padx=15, fill="x")
        input_frame.configure(bg="#1a1a1a")
        
        tk.Label(input_frame, text="Target IP:", fg="white", bg="#1a1a1a").grid(row=0, column=0, padx=5, pady=5)
        self.target_ip = tk.Entry(input_frame, width=15, font=("Courier", 10), bg="#2d2d2d", fg="white")
        self.target_ip.insert(0, "127.0.0.1")
        self.target_ip.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(input_frame, text="Network:", fg="white", bg="#1a1a1a").grid(row=0, column=2, padx=5, pady=5)
        self.network = tk.Entry(input_frame, width=18, font=("Courier", 10), bg="#2d2d2d", fg="white")
        self.network.insert(0, "192.168.1.0/24")
        self.network.grid(row=0, column=3, padx=5, pady=5)
        
        # Main scan buttons
        btn_frame = tk.Frame(self.root, bg="#1a1a1a")
        btn_frame.pack(pady=15)
        
        tk.Button(btn_frame, text="🔍 PORT SCAN", command=self.scan_ports,
                 bg="#ff4444", fg="white", font=("Arial", 12, "bold"), width=15, height=2).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="📡 SERVICES", command=self.scan_services,
                 bg="#44ff44", fg="black", font=("Arial", 12, "bold"), width=15, height=2).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="🌐 ROGUE DEVICES", command=self.scan_rogue_devices,
                 bg="#4444ff", fg="white", font=("Arial", 12, "bold"), width=18, height=2).pack(side=tk.LEFT, padx=10)
        
        # Results area
        tk.Label(self.root, text="📋 SCAN RESULTS", font=("Arial", 14, "bold"), 
                fg="#00ff88", bg="#1a1a1a").pack(anchor="w", padx=15, pady=(10,5))
        
        self.results = scrolledtext.ScrolledText(self.root, height=25, width=110, 
                                               font=("Courier", 9), bg="#0d1b2a", fg="#90e0ef",
                                               insertbackground="white")
        self.results.pack(padx=15, pady=5, fill="both", expand=True)
        
        # Advice section
        advice_frame = tk.LabelFrame(self.root, text="💡 SECURITY ADVICE", font=("Arial", 12, "bold"),
                                    fg="#ffaa00", bg="#1a1a1a")
        advice_frame.pack(pady=10, padx=15, fill="x")
        advice_frame.configure(bg="#1a1a1a")
        
        self.advice = tk.Label(advice_frame, text="Run a scan to get security recommendations", 
                              fg="#ffaa00", bg="#1a1a1a", font=("Arial", 11), 
                              wraplength=900, justify="left")
        self.advice.pack(pady=10, padx=15)
        
        # Status
        self.status = tk.Label(self.root, text="🟢 READY", fg="#00ff88", bg="#1a1a1a", 
                              font=("Arial", 11, "bold"))
        self.status.pack(pady=5)
    
    def log(self, msg, color="white"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.results.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.results.see(tk.END)
        self.root.update()
    
    def clear_results(self):
        self.results.delete(1.0, tk.END)
    
    def update_status(self, status, color="00ff88"):
        self.status.config(text=status, fg=f"#{color}")
    
    def get_target(self):
        return self.target_ip.get().strip() or "127.0.0.1"
    
    def get_network(self):
        return self.network.get().strip() or "192.168.1.0/24"
    
    def run_command(self, cmd, scan_type):
        def scan_thread():
            self.clear_results()
            target = self.get_target()
            self.update_status(f"🔄 Scanning {target}...", "ffaa00")
            self.log(f"🚀 Starting {scan_type.upper()} scan on {target}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                self.log("=" * 80)
                self.log(result.stdout)
                if result.stderr:
                    self.log(f"⚠️  {result.stderr}", "ffaa00")
                
                self.analyze_results(result.stdout + result.stderr, scan_type)
                
            except subprocess.TimeoutExpired:
                self.log("⏰ SCAN TIMEOUT - Target slow or unresponsive")
                self.update_advice("TIMEOUT", "ff4444")
            except Exception as e:
                self.log(f"❌ ERROR: {e}", "ff4444")
                self.update_status("❌ ERROR", "ff4444")
            finally:
                self.update_status("🟢 READY", "00ff88")
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def analyze_results(self, output, scan_type):
        self.log("\n🤖 SECURITY ANALYSIS:")
        self.log("-" * 50)
        
        if scan_type == "ports":
            open_ports = re.findall(r'(\d+)/tcp\s+open', output)
            services = re.findall(r'(\d+)/tcp\s+open\s+([a-zA-Z0-9/-]+)', output)
            
            risks = []
            if "22/tcp" in output and "ssh" in output.lower():
                risks.append("✅ SSH detected - Enable key authentication")
            if "23/tcp" in output:
                risks.append("🚨 CRITICAL: Telnet (23) OPEN - DISABLE IMMEDIATELY!")
            if "80/tcp" in output or "443/tcp" in output:
                risks.append("🌐 Web server running - Scan with Nikto/OWASP ZAP")
            if len(open_ports) > 10:
                risks.append(f"⚠️  {len(open_ports)} open ports - Review firewall rules")
            
            advice = " | ".join(risks) if risks else "✅ No critical vulnerabilities detected"
            self.update_advice(advice)
        
        elif scan_type == "services":
            exposed = "0.0.0.0" in output or "*.*" in output
            if exposed:
                self.update_advice("🚨 Services listening on ALL interfaces (0.0.0.0) - Restrict to localhost!", "ff4444")
            else:
                self.update_advice("✅ Services properly bound to localhost - Good configuration")
        
        elif scan_type == "rogue":
            macs = re.findall(r'([a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}[:-]){5}([a-f0-9]{2})', output, re.I)
            unknown_macs = [mac for mac in macs if mac[0] not in self.known_devices]
            
            if len(unknown_macs) > 0:
                rogue_count = len(set(unknown_macs))
                self.known_devices.update({mac[0]: "seen" for mac in unknown_macs})
                self.update_advice(f"🚨 {rogue_count} ROGUE DEVICES detected! Isolate immediately!", "ff4444")
            else:
                self.update_advice("✅ No rogue devices detected on network")
    
    def update_advice(self, text, color="00ff88"):
        self.advice.config(text=text, fg=f"#{color}")
    
    # SCAN FUNCTIONS
    def scan_ports(self):
        target = self.get_target()
        cmd = ["nmap", "-sV", "-sC", "-p-", "--open", "-T4", target]
        self.run_command(cmd, "ports")
    
    def scan_services(self):
        cmd = ["ss", "-tuln", "-o"]
        self.run_command(cmd, "services")
    
    def scan_rogue_devices(self):
        network = self.get_network()
        cmd = ["netdiscover", "-r", network, "-P", "-s1"]
        self.run_command(cmd, "rogue")
    
    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = CybersecurityMonitor(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
