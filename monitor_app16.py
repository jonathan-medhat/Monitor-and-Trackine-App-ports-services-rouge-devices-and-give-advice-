import customtkinter as ctk
import tkinter as tk
import subprocess
import threading
from datetime import datetime
import os

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class CyberMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Cybersecurity Monitor (Nmap + TCPDump + Ping)")
        self.root.geometry("1200x950")

        self.nmap_process = None
        self.tcpdump_process = None
        self.ping_process = None

        self.nmap_log = []
        self.traffic_log = []
        self.ping_log = []

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
        self.target = ctk.CTkEntry(nmap, width=150)
        self.target.insert(0, "127.0.0.1")
        self.target.grid(row=0, column=1, padx=5)

        ctk.CTkLabel(nmap, text="Ports").grid(row=0, column=2)
        self.ports = ctk.CTkEntry(nmap, width=120)
        self.ports.grid(row=0, column=3, padx=5)

        self.scan_type = ctk.CTkOptionMenu(
            nmap,
            values=[
                "Normal",
                "-sL List Targets",
                "-sn Host Discovery",
                "-Pn No Ping",
                "-sS TCP SYN",
                "-sT TCP Connect",
                "-sA TCP ACK",
                "-sU UDP Scan",
                "-PR ARP Scan",
                "-n No DNS"
            ],
            width=200
        )
        self.scan_type.set("Normal")
        self.scan_type.grid(row=0, column=4, padx=5)

        ctk.CTkButton(
            nmap, text="▶ START NMAP",
            fg_color="#22c55e",
            command=self.start_nmap
        ).grid(row=0, column=5, padx=5)

        ctk.CTkButton(
            nmap, text="■ STOP NMAP",
            fg_color="#ef4444",
            command=self.stop_nmap
        ).grid(row=0, column=6, padx=5)

        # ---------- TCPDUMP ----------
        tcp = ctk.CTkFrame(self.root)
        tcp.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(tcp, text="Interface").grid(row=0, column=0)
        self.interface = ctk.CTkEntry(tcp, width=120)
        self.interface.insert(0, "eth0")
        self.interface.grid(row=0, column=1, padx=5)

        ctk.CTkLabel(tcp, text="Filter").grid(row=0, column=2)
        self.filter_entry = ctk.CTkEntry(tcp, width=150)
        self.filter_entry.insert(0, "icmp")
        self.filter_entry.grid(row=0, column=3, padx=5)

        self.tcp_mode = ctk.CTkOptionMenu(
            tcp,
            values=[
                "Capture Everything",
                "With Count (10)",
                "No DNS (-n)",
                "Verbose (-v)"
            ],
            width=180
        )
        self.tcp_mode.set("Capture Everything")
        self.tcp_mode.grid(row=0, column=4, padx=5)

        self.packet_label = ctk.CTkLabel(
            tcp, text="Packets: 0", text_color="#38bdf8"
        )
        self.packet_label.grid(row=0, column=5, padx=10)

        ctk.CTkButton(
            tcp, text="▶ START CAPTURE",
            fg_color="#38bdf8",
            command=self.start_capture
        ).grid(row=0, column=6, padx=5)

        ctk.CTkButton(
            tcp, text="■ STOP",
            fg_color="#f97316",
            command=self.stop_capture
        ).grid(row=0, column=7, padx=5)

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

        # ---------- SHOW RESULTS ----------
        ctk.CTkButton(
            self.root,
            text="📂 SHOW RESULTS",
            fg_color="#a855f7",
            command=self.show_results
        ).pack(pady=10)

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
        ports = self.ports.get().strip()
        scan = self.scan_type.get()

        cmd = ["nmap"]
        if scan != "Normal":
            cmd.append(scan.split()[0])
        if ports:
            cmd += ["-p", ports]
        cmd.append(target)

        def run():
            self.log("NMAP → " + " ".join(cmd))
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
            for line in p.stdout:
                self.nmap_log.append(line)
                self.log(line.strip())

        threading.Thread(target=run, daemon=True).start()

    def stop_nmap(self):
        self.log("Nmap stop requested")

    # ================= TCPDUMP =================
    def start_capture(self):
        self.packet_count = 0
        self.packet_label.configure(text="Packets: 0")
        self.traffic_log.clear()

        interface = self.interface.get().strip() or "eth0"
        capture_filter = self.filter_entry.get().strip()
        mode = self.tcp_mode.get()

        cmd = ["tcpdump", "-i", interface]

        if mode == "With Count (10)":
            cmd += ["-c", "10"]
        if mode == "No DNS (-n)":
            cmd.append("-n")
        if mode == "Verbose (-v)":
            cmd.append("-v")

        if capture_filter:
            cmd.append(capture_filter)

        self.log("TCPDUMP → " + " ".join(cmd))

        self.tcpdump_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        def read_packets():
            for line in self.tcpdump_process.stdout:
                self.packet_count += 1
                self.packet_label.configure(text=f"Packets: {self.packet_count}")
                self.traffic_log.append(line)
                self.log(line.strip())

        threading.Thread(target=read_packets, daemon=True).start()

    def stop_capture(self):
        if self.tcpdump_process:
            self.tcpdump_process.terminate()
            self.tcpdump_process = None
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
            ("TCPDUMP RESULTS", self.traffic_log)
        ]:
            self.log_box.insert(tk.END, f"\n===== {title} =====\n")
            for line in data:
                self.log_box.insert(tk.END, line)


# ================= RUN =================
if __name__ == "__main__":
    root = ctk.CTk()
    app = CyberMonitor(root)
    root.mainloop()
