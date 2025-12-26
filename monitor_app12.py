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
        self.ping_log = []

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

        self.scan_type = ctk.CTkOptionMenu(
            nmap,
            values=["Normal", "-sn Host Discovery", "-Pn Port Scan Only"],
            width=220
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

        # ---------- TSHARK ----------
        tcp = ctk.CTkFrame(self.root)
        tcp.pack(fill="x", padx=20, pady=5)

        self.interface = ctk.CTkEntry(tcp, width=120)
        self.interface.insert(0, "eth0")
        self.interface.grid(row=0, column=0, padx=5)

        self.filter_entry = ctk.CTkEntry(tcp, width=300)
        self.filter_entry.insert(0, "tcp")
        self.filter_entry.grid(row=0, column=1, padx=5)

        ctk.CTkButton(
            tcp, text="▶ START CAPTURE",
            fg_color="#38bdf8",
            command=self.start_capture
        ).grid(row=0, column=2, padx=5)

        ctk.CTkButton(
            tcp, text="■ STOP CAPTURE",
            fg_color="#f97316",
            command=self.stop_capture
        ).grid(row=0, column=3, padx=5)

        # ---------- PING ----------
        ping = ctk.CTkFrame(self.root)
        ping.pack(fill="x", padx=20, pady=5)

        ctk.CTkButton(
            ping, text="▶ START PING",
            fg_color="#10b981",
            command=self.start_ping
        ).grid(row=0, column=0, padx=5)

        ctk.CTkButton(
            ping, text="■ STOP PING",
            fg_color="#ef4444",
            command=self.stop_ping
        ).grid(row=0, column=1, padx=5)

        # ---------- SHOW RESULTS ----------
        ctk.CTkButton(
            self.root,
            text="📂 SHOW RESULTS & ADVICE",
            fg_color="#a855f7",
            hover_color="#9333ea",
            command=self.show_result_files
        ).pack(pady=10)

        # ---------- FILE BUTTONS ----------
        self.file_buttons_frame = ctk.CTkFrame(self.root)
        self.file_buttons_frame.pack(fill="x", padx=20)

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
        cmd = ["nmap", target]

        def run():
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
            for line in p.stdout:
                self.nmap_log.append(line)
                self.log(line.strip())
            self.save_results()

        threading.Thread(target=run, daemon=True).start()

    def stop_nmap(self):
        self.log("Nmap stopped (manual stop not enforced)")

    # ================= TSHARK =================
    def start_capture(self):
        self.traffic_log.clear()
        cmd = ["tshark", "-i", self.interface.get(), "-f", self.filter_entry.get()]

        self.tshark_process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )

        def read():
            for line in self.tshark_process.stdout:
                self.traffic_log.append(line)
                self.log(line.strip())

        threading.Thread(target=read, daemon=True).start()

    def stop_capture(self):
        if self.tshark_process:
            self.tshark_process.terminate()
            self.save_results()
            self.log("Capture stopped")

    # ================= PING =================
    def start_ping(self):
        self.ping_log.clear()
        target = self.target.get().strip()

        self.ping_process = subprocess.Popen(
            ["ping", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        def read():
            for line in self.ping_process.stdout:
                self.ping_log.append(line)
                self.log(line.strip())

        threading.Thread(target=read, daemon=True).start()

    def stop_ping(self):
        if self.ping_process:
            self.ping_process.terminate()
            self.save_results()
            self.log("Ping stopped")

    # ================= SAVE & ANALYZE =================
    def save_results(self):
        with open("nmap_results.txt", "w") as f:
            f.writelines(self.nmap_log or ["No Nmap data\n"])

        with open("traffic_results.txt", "w") as f:
            f.writelines(self.traffic_log or ["No TCP traffic\n"])

        advice = []
        if any("open" in l.lower() for l in self.nmap_log):
            advice.append("⚠ Open ports detected – secure them.")

        if len(self.traffic_log) > 150:
            advice.append("⚠ High TCP traffic detected.")

        if not advice:
            advice.append("✅ No critical issues detected.")

        with open("security_advice.txt", "w") as f:
            f.write("\n".join(advice))

    # ================= SHOW RESULTS =================
    def show_result_files(self):
        for w in self.file_buttons_frame.winfo_children():
            w.destroy()

        for fname in ["nmap_results.txt", "traffic_results.txt", "security_advice.txt"]:
            if os.path.exists(fname):
                ctk.CTkButton(
                    self.file_buttons_frame,
                    text=fname,
                    command=lambda f=fname: self.open_file(f)
                ).pack(side="left", padx=5, pady=5)

    def open_file(self, filename):
        self.log_box.delete("1.0", tk.END)
        with open(filename) as f:
            self.log_box.insert(tk.END, f.read())
        self.log(f"Opened {filename}")


# ================= RUN =================
if __name__ == "__main__":
    root = ctk.CTk()
    app = CyberMonitor(root)
    root.mainloop()
