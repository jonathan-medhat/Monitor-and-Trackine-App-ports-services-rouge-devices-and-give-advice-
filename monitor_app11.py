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
        self.root.title("Cybersecurity Monitor (Nmap + Tshark)")
        self.root.geometry("1100x900")

        self.nmap_process = None
        self.tshark_process = None
        self.nmap_log = []
        self.traffic_log = []

        self.build_ui()

    # ================= UI =================
    def build_ui(self):
        title = ctk.CTkLabel(
            self.root,
            text="🛡 Cybersecurity Monitor",
            font=("Segoe UI", 22, "bold"),
            text_color="#22c55e"
        )
        title.pack(pady=10)

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

        ctk.CTkButton(
            nmap, text="▶ START NMAP",
            fg_color="#22c55e",
            command=self.start_nmap
        ).grid(row=0, column=6, padx=5)

        ctk.CTkButton(
            nmap, text="■ STOP NMAP",
            fg_color="#ef4444",
            command=self.stop_nmap
        ).grid(row=0, column=7, padx=5)

        # ---------- TSHARK ----------
        tcp = ctk.CTkFrame(self.root)
        tcp.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(tcp, text="Interface").grid(row=0, column=0, padx=5)
        self.interface = ctk.CTkEntry(tcp, width=120)
        self.interface.insert(0, "lo")
        self.interface.grid(row=0, column=1, padx=5)

        ctk.CTkLabel(tcp, text="Capture Filter").grid(row=0, column=2, padx=5)
        self.filter_entry = ctk.CTkEntry(tcp, width=300)
        self.filter_entry.insert(0, "icmp")
        self.filter_entry.grid(row=0, column=3, padx=5)

        ctk.CTkButton(
            tcp, text="▶ START CAPTURE",
            fg_color="#38bdf8",
            command=self.start_capture
        ).grid(row=0, column=4, padx=5)

        ctk.CTkButton(
            tcp, text="■ STOP & SAVE",
            fg_color="#f97316",
            command=self.stop_capture
        ).grid(row=0, column=5, padx=5)

        # ---------- SHOW FILES ----------
        ctk.CTkButton(
            self.root,
            text="📂 SHOW RESULT FILES",
            fg_color="#a855f7",
            hover_color="#9333ea",
            command=self.show_result_files
        ).pack(pady=10)

        # ---------- LOG BOX ----------
        self.log_box = tk.Text(
            self.root,
            bg="#020617",
            fg="#e5e7eb",
            font=("JetBrains Mono", 10)
        )
        self.log_box.pack(fill="both", expand=True, padx=20, pady=15)

    # ================= HELPERS =================
    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_box.insert(tk.END, f"[{ts}] {msg}\n")
        self.log_box.see(tk.END)

    # ================= NMAP =================
    def start_nmap(self):
        if self.nmap_process:
            self.log("Nmap already running")
            return

        target = self.target.get().strip()
        ports = self.ports.get().strip()
        scan = self.scan_type.get()

        cmd = ["nmap"]

        if scan.startswith("-"):
            cmd.append(scan.split()[0])
        else:
            if ports:
                cmd += ["-p", ports]
            else:
                cmd += ["-F"]

        cmd.append(target)
        self.log(f"Starting Nmap: {' '.join(cmd)}")

        def run():
            self.nmap_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            for line in self.nmap_process.stdout:
                self.nmap_log.append(line)
                self.log(line.strip())

            self.nmap_process = None
            self.save_results()

        threading.Thread(target=run, daemon=True).start()

    def stop_nmap(self):
        if self.nmap_process:
            self.nmap_process.terminate()
            self.log("Nmap stopped by user")
            self.nmap_process = None
            self.save_results()
        else:
            self.log("No Nmap process running")

    # ================= TSHARK =================
    def start_capture(self):
        if self.tshark_process:
            self.log("Capture already running")
            return

        iface = self.interface.get().strip()
        flt = self.filter_entry.get().strip()

        cmd = ["tshark", "-i", iface]
        if flt:
            cmd += ["-f", flt]

        self.log(f"Starting Tshark on {iface}")

        self.tshark_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        def read():
            for line in self.tshark_process.stdout:
                self.traffic_log.append(line)
                self.log(line.strip())

        threading.Thread(target=read, daemon=True).start()

    def stop_capture(self):
        if self.tshark_process:
            self.tshark_process.terminate()
            self.log("Capture stopped")
            self.tshark_process = None
            self.save_results()
            self.generate_advice()
        else:
            self.log("No capture running")

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

    # ================= SHOW FILES =================
    def show_result_files(self):
        self.log("Listing result files:")

        try:
            result = subprocess.run(["ls"], capture_output=True, text=True)
            files = result.stdout.strip().split("\n")

            # حذف أي فريم قديم
            if hasattr(self, "file_buttons_frame"):
                self.file_buttons_frame.destroy()

            # Scrollable frame
            container = ctk.CTkFrame(self.root)
            container.pack(fill="both", expand=False, pady=5, padx=10)

            canvas = tk.Canvas(container, height=120, bg="#020617", highlightthickness=0)
            scrollbar = tk.Scrollbar(container, orient="horizontal", command=canvas.xview)
            scroll_frame = ctk.CTkFrame(canvas)

            scroll_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )

            canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
            canvas.configure(xscrollcommand=scrollbar.set)

            canvas.pack(fill="both", expand=True, side="top")
            scrollbar.pack(fill="x", side="bottom")

            self.file_buttons_frame = scroll_frame

            for fname in files:
                btn = ctk.CTkButton(
                    scroll_frame,
                    text=fname,
                    width=200,
                    command=lambda f=fname: self.open_file(f)
                )
                btn.pack(side="left", padx=5, pady=5)

        except Exception as e:
            self.log(f"Error: {e}")

    def open_file(self, filename):
        try:
            with open(filename, "r", encoding="utf-8") as f:
                content = f.read()
            self.log_box.delete("1.0", tk.END)
            self.log_box.insert(tk.END, content)
            self.log(f"Opened file: {filename}")
        except Exception as e:
            self.log(f"Cannot open {filename}: {e}")


# ================= RUN =================
if __name__ == "__main__":
    root = ctk.CTk()
    app = CyberMonitor(root)
    root.mainloop()
