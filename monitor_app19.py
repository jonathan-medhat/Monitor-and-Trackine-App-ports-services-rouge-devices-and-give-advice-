import customtkinter as ctk
import tkinter as tk
import subprocess
import threading
from datetime import datetime

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class CyberMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Cybersecurity Monitor (Nmap + TCPDump + Netdiscover + Ping)")
        self.root.geometry("1200x950")

        self.nmap_process = None
        self.tcpdump_process = None
        self.ping_process = None
        self.netdiscover_process = None

        self.nmap_log = []
        self.traffic_log = []
        self.netdiscover_log = []

        self.packet_count = 0

        self.build_ui()

    # ================= UI =================
    def build_ui(self):
        ctk.CTkLabel(
            self.root,
            text="🛡 Cybersecurity Monitor",
            font=("Segoe UI", 22, "bold"),
            text_color="#22c55e"
        ).pack(pady=10)

        # ---------- NMAP ----------
        nmap = ctk.CTkFrame(self.root)
        nmap.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(nmap, text="Target IP").grid(row=0, column=0)
        self.target = ctk.CTkEntry(nmap, width=200)
        self.target.insert(0, "127.0.0.1")
        self.target.grid(row=0, column=1, padx=5)

        self.scan_type = ctk.CTkOptionMenu(
            nmap,
            values=[
                "Normal",
                "-Pn No Ping",
                "-sS TCP SYN",
                "-sA TCP ACK",
                "-sU UDP Scan"
            ],
            width=220
        )
        self.scan_type.set("Normal")
        self.scan_type.grid(row=0, column=2, padx=10)

        ctk.CTkButton(
            nmap, text="▶ START NMAP",
            fg_color="#22c55e",
            command=self.start_nmap
        ).grid(row=0, column=3, padx=5)

        ctk.CTkButton(
            nmap, text="■ STOP NMAP",
            fg_color="#ef4444",
            command=self.stop_nmap
        ).grid(row=0, column=4, padx=5)

        # ---------- NETDISCOVER ----------
        netd = ctk.CTkFrame(self.root)
        netd.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(netd, text="Router IP").grid(row=0, column=0)
        self.router_ip = ctk.CTkEntry(netd, width=200)
        self.router_ip.insert(0, "192.168.1.1")
        self.router_ip.grid(row=0, column=1, padx=5)

        ctk.CTkButton(
            netd, text="▶ START NETDISCOVER",
            fg_color="#6366f1",
            command=self.start_netdiscover
        ).grid(row=0, column=2, padx=5)

        ctk.CTkButton(
            netd, text="■ STOP NETDISCOVER",
            fg_color="#ef4444",
            command=self.stop_netdiscover
        ).grid(row=0, column=3, padx=5)

        # ---------- TCPDUMP ----------
        tcp = ctk.CTkFrame(self.root)
        tcp.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(tcp, text="Interface").grid(row=0, column=0)
        self.interface = ctk.CTkEntry(tcp, width=150)
        self.interface.insert(0, "eth0")
        self.interface.grid(row=0, column=1, padx=5)

        ctk.CTkLabel(tcp, text="Filter").grid(row=0, column=2)
        self.filter_entry = ctk.CTkEntry(tcp, width=150)
        self.filter_entry.insert(0, "icmp")
        self.filter_entry.grid(row=0, column=3, padx=5)

        self.packet_label = ctk.CTkLabel(
            tcp, text="Packets: 0", text_color="#38bdf8"
        )
        self.packet_label.grid(row=0, column=4, padx=10)

        ctk.CTkButton(
            tcp, text="▶ START CAPTURE",
            fg_color="#38bdf8",
            command=self.start_capture
        ).grid(row=0, column=5, padx=5)

        ctk.CTkButton(
            tcp, text="■ STOP",
            fg_color="#f97316",
            command=self.stop_capture
        ).grid(row=0, column=6, padx=5)

        # ---------- PING ----------
        ping = ctk.CTkFrame(self.root)
        ping.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(ping, text="Ping Target").grid(row=0, column=0)
        self.ping_target = ctk.CTkEntry(ping, width=200)
        self.ping_target.grid(row=0, column=1, padx=5)

        ctk.CTkButton(
            ping, text="▶ START PING",
            fg_color="#10b981",
            command=self.start_ping
        ).grid(row=0, column=2, padx=5)

        ctk.CTkButton(
            ping, text="■ STOP PING",
            fg_color="#ef4444",
            command=self.stop_ping
        ).grid(row=0, column=3, padx=5)

        # ---------- ACTION BUTTONS ----------
        ctk.CTkButton(
            self.root,
            text="📂 SHOW RESULTS",
            fg_color="#a855f7",
            command=self.show_results
        ).pack(pady=5)

        ctk.CTkButton(
            self.root,
            text="🧠 GENERATE ADVICE",
            fg_color="#0ea5e9",
            command=self.generate_advice
        ).pack(pady=5)

        # ---------- LOG ----------
        self.log_box = tk.Text(
            self.root,
            bg="#020617",
            fg="#e5e7eb",
            font=("JetBrains Mono", 10)
        )
        self.log_box.pack(fill="both", expand=True, padx=20, pady=10)

    # ================= HELPERS =================
    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_box.insert(tk.END, f"[{ts}] {msg}\n")
        self.log_box.see(tk.END)

    # ================= NMAP =================
    def start_nmap(self):
        self.nmap_log.clear()
        target = self.target.get().strip()
        scan = self.scan_type.get()

        cmd = ["nmap"]
        if scan != "Normal":
            cmd.append(scan.split()[0])
        cmd.append(target)

        def run():
            self.log("NMAP → " + " ".join(cmd))
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
            self.nmap_process = p
            for line in p.stdout:
                self.nmap_log.append(line)
                self.log(line.strip())

        threading.Thread(target=run, daemon=True).start()

    def stop_nmap(self):
        if self.nmap_process:
            self.nmap_process.terminate()
            self.log("Nmap stopped")

    # ================= NETDISCOVER =================
    def start_netdiscover(self):
        self.netdiscover_log.clear()
        router_ip = self.router_ip.get().strip()
        cmd = ["netdiscover", "-r", f"{router_ip}/24"]

        def run():
            self.log("NETDISCOVER → " + " ".join(cmd))
            try:
                self.netdiscover_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                for line in self.netdiscover_process.stdout:
                    self.netdiscover_log.append(line)
                    self.log(line.strip())
            except FileNotFoundError:
                self.log("netdiscover not installed or needs sudo")

        threading.Thread(target=run, daemon=True).start()

    def stop_netdiscover(self):
        if self.netdiscover_process:
            self.netdiscover_process.terminate()
            self.log("Netdiscover stopped")

    # ================= TCPDUMP =================
    def start_capture(self):
        self.packet_count = 0
        self.packet_label.configure(text="Packets: 0")
        self.traffic_log.clear()

        cmd = ["tcpdump", "-i", self.interface.get().strip() or "eth0"]
        if self.filter_entry.get().strip():
            cmd.append(self.filter_entry.get().strip())

        self.log("TCPDUMP → " + " ".join(cmd))

        self.tcpdump_process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )

        def read():
            for line in self.tcpdump_process.stdout:
                self.packet_count += 1
                self.packet_label.configure(text=f"Packets: {self.packet_count}")
                self.traffic_log.append(line)
                self.log(line.strip())

        threading.Thread(target=read, daemon=True).start()

    def stop_capture(self):
        if self.tcpdump_process:
            self.tcpdump_process.terminate()
            self.log("TCPDUMP stopped")

    # ================= PING =================
    def start_ping(self):
        target = self.ping_target.get().strip() or self.target.get().strip()
        self.ping_process = subprocess.Popen(
            ["ping", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        def read():
            for line in self.ping_process.stdout:
                self.log(line.strip())

        threading.Thread(target=read, daemon=True).start()

    def stop_ping(self):
        if self.ping_process:
            self.ping_process.terminate()
            self.log("Ping stopped")

    # ================= SHOW RESULTS =================
    def show_results(self):
        self.log_box.delete("1.0", tk.END)

        for title, data in [
            ("NMAP RESULTS", self.nmap_log),
            ("TCPDUMP RESULTS", self.traffic_log),
            ("NETDISCOVER RESULTS", self.netdiscover_log),
        ]:
            self.log_box.insert(tk.END, f"\n===== {title} =====\n")
            for line in data:
                self.log_box.insert(tk.END, line)

    # ================= GENERATE ADVICE =================
    def generate_advice(self):
        self.log_box.insert(tk.END, "\n===== 🧠 SECURITY ADVICE =====\n")
        advice = set()

        for line in self.nmap_log:
            l = line.lower()
            if "open" in l:
                advice.add("⚠ Open ports detected → Close unused ports.")
            if "ssh" in l:
                advice.add("🔐 SSH detected → Use key-based authentication.")
            if "http" in l:
                advice.add("🌐 HTTP detected → Prefer HTTPS.")

        if self.packet_count > 100:
            advice.add("📡 High traffic → Possible network abuse.")

        if len(self.netdiscover_log) > 10:
            advice.add("🖧 Many devices detected → Check for unauthorized devices.")

        if not advice:
            advice.add("✅ No serious security issues detected.")

        for a in advice:
            self.log_box.insert(tk.END, f"- {a}\n")

        self.log_box.see(tk.END)


# ================= RUN =================
if __name__ == "__main__":
    root = ctk.CTk()
    app = CyberMonitor(root)
    root.mainloop()
