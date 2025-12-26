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
        self.root.title("Cybersecurity Monitor (Nmap + Tshark + Ping)")
        self.root.geometry("1100x900")

        self.nmap_process = None
        self.tshark_process = None
        self.ping_process = None

        self.nmap_log = []
        self.traffic_log = []

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

        ctk.CTkLabel(nmap, text="Target IP").grid(row=0, column=0, padx=5)
        self.target = ctk.CTkEntry(nmap, width=160)
        self.target.insert(0, "127.0.0.1")
        self.target.grid(row=0, column=1, padx=5)

        ctk.CTkLabel(nmap, text="Ports").grid(row=0, column=2, padx=5)
        self.ports = ctk.CTkEntry(nmap, width=120)
        self.ports.grid(row=0, column=3, padx=5)

        ctk.CTkLabel(nmap, text="Scan Type").grid(row=0, column=4, padx=5)
        self.scan_type = ctk.CTkOptionMenu(
            nmap,
            values=[
                "Normal",
                "-sL List Targets",
                "-sn Host Discovery",
                "-Pn Port Scan Only",
                "-PS TCP SYN",
                "-PA TCP ACK",
                "-PU UDP",
                "-PR ARP",
                "-n No DNS"
            ],
            width=220
        )
        self.scan_type.set("Normal")
        self.scan_type.grid(row=0, column=5, padx=5)

        ctk.CTkButton(nmap, text="▶ START NMAP", fg_color="#22c55e",
                      command=self.start_nmap).grid(row=0, column=6, padx=5)

        ctk.CTkButton(nmap, text="■ STOP NMAP", fg_color="#ef4444",
                      command=self.stop_nmap).grid(row=0, column=7, padx=5)

        # ---------- TSHARK ----------
        tcp = ctk.CTkFrame(self.root)
        tcp.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(tcp, text="Interface").grid(row=0, column=0, padx=5)
        self.interface = ctk.CTkEntry(tcp, width=120)
        self.interface.insert(0, "eth0")
        self.interface.grid(row=0, column=1, padx=5)

        ctk.CTkLabel(tcp, text="Capture Filter").grid(row=0, column=2, padx=5)
        self.filter_entry = ctk.CTkEntry(tcp, width=300)
        self.filter_entry.insert(0, "tcp")
        self.filter_entry.grid(row=0, column=3, padx=5)

        ctk.CTkButton(tcp, text="▶ START CAPTURE", fg_color="#38bdf8",
                      command=self.start_capture).grid(row=0, column=4, padx=5)

        ctk.CTkButton(tcp, text="■ STOP & SAVE", fg_color="#f97316",
                      command=self.stop_capture).grid(row=0, column=5, padx=5)

        # ---------- PING ----------
        ping = ctk.CTkFrame(self.root)
        ping.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(ping, text="Ping Target").pack(side="left", padx=5)
        self.ping_target = ctk.CTkEntry(ping, width=200)
        self.ping_target.insert(0, "")  # فاضي = يستخدم Target IP
        self.ping_target.pack(side="left", padx=5)

        ctk.CTkButton(
            ping,
            text="▶ START PING",
            fg_color="#10b981",
            command=self.start_ping
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            ping,
            text="■ STOP PING",
            fg_color="#ef4444",
            command=self.stop_ping
        ).pack(side="left", padx=5)

        # ---------- SHOW FILES ----------
        ctk.CTkButton(
            self.root,
            text="📂 SHOW RESULT FILES",
            fg_color="#a855f7",
            hover_color="#9333ea",
            command=self.show_result_files
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
        if self.nmap_process:
            return
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

        self.log(f"Starting Nmap: {' '.join(cmd)}")

        self.nmap_process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )

        def read():
            for line in self.nmap_process.stdout:
                self.nmap_log.append(line)
                self.log(line.strip())
            self.nmap_process = None
            self.save_results()
            self.generate_advice()

        threading.Thread(target=read, daemon=True).start()

    def stop_nmap(self):
        if self.nmap_process:
            self.nmap_process.terminate()
            self.nmap_process = None
            self.log("Nmap stopped by user")

    # ================= TSHARK =================
    def start_capture(self):
        if self.tshark_process:
            return
        self.traffic_log.clear()
        cmd = [
            "tshark",
            "-i", self.interface.get(),
            "-f", self.filter_entry.get(),
            "-w", "capture.pcap"
        ]
        self.tshark_process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )

        def read():
            for line in self.tshark_process.stdout:
                self.traffic_log.append(line)
                self.log(line.strip())

        threading.Thread(target=read, daemon=True).start()
        self.log("Tshark capture started")

    def stop_capture(self):
        if self.tshark_process:
            self.tshark_process.terminate()
            self.tshark_process = None
            self.save_results()
            self.generate_advice()
            self.log("Capture stopped")

    # ================= PING =================
    def start_ping(self):
        if self.ping_process:
            return

        target = self.ping_target.get().strip()
        if not target:
            target = self.target.get().strip()  # fallback

        self.log(f"Starting Ping to {target}")

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
            self.ping_process = None
            self.log("Ping stopped")

    # ================= FILES =================
    def save_results(self):
        with open("nmap_results.txt", "w", encoding="utf-8") as f:
            f.writelines(self.nmap_log or ["No Nmap data\n"])
        with open("traffic_results.txt", "w", encoding="utf-8") as f:
            f.writelines(self.traffic_log or ["No traffic data\n"])

    def generate_advice(self):
        advice = []
        if any("open" in l.lower() for l in self.nmap_log):
            advice.append("⚠ Open ports detected: secure or firewall them.")
        if len(self.traffic_log) > 100:
            advice.append("⚠ High traffic volume detected.")
        if not advice:
            advice.append("✅ No critical issues detected.")

        with open("security_advice.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(advice))
        self.log("Security advice generated")

    # ================= SHOW FILES AS BUTTONS =================
    def show_result_files(self):
        if hasattr(self, "files_container"):
            self.files_container.destroy()

        self.files_container = ctk.CTkFrame(self.root)
        self.files_container.pack(fill="x", padx=10, pady=5)

        canvas = tk.Canvas(self.files_container, height=90, bg="#020617", highlightthickness=0)
        scrollbar = tk.Scrollbar(self.files_container, orient="horizontal", command=canvas.xview)
        frame = ctk.CTkFrame(canvas)

        frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=frame, anchor="nw")
        canvas.configure(xscrollcommand=scrollbar.set)

        canvas.pack(fill="x")
        scrollbar.pack(fill="x")

        files = [
            "nmap_results.txt",
            "traffic_results.txt",
            "security_advice.txt",
            "capture.pcap"
        ]

        for f in files:
            if os.path.exists(f):
                ctk.CTkButton(
                    frame,
                    text=f,
                    width=200,
                    command=lambda x=f: self.open_file(x)
                ).pack(side="left", padx=5, pady=10)

    def open_file(self, filename):
        self.log_box.delete("1.0", tk.END)

        if filename.endswith(".pcap"):
            if os.path.getsize(filename) == 0:
                self.log("PCAP file is empty")
                return
            result = subprocess.run(
                ["tshark", "-r", filename],
                capture_output=True, text=True
            )
            self.log_box.insert(tk.END, result.stdout)
        else:
            with open(filename, "r", encoding="utf-8") as f:
                self.log_box.insert(tk.END, f.read())


# ================= RUN =================
if __name__ == "__main__":
    root = ctk.CTk()
    app = CyberMonitor(root)
    root.mainloop()
