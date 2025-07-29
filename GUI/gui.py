import sys
import subprocess
import threading
import glob
import os
import signal
import wifi_pentest
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QTextEdit, QFileDialog, QStackedLayout,
    QListWidget, QListWidgetItem, QComboBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QPalette, QBrush, QPixmap
from wifi_pentest import (
    install_tools, set_monitor_mode, stop_monitor_mode, capture_handshake, crack_handshake,
    perform_wps_attack, perform_pmkid_attack, create_password_list
)

class TerminalThread(QThread):
    output = pyqtSignal(str)

    def __init__(self, command):
        super().__init__()
        self.command = command
        self.process = None
        self.running = True

    def run(self):
        self.running = True
        self.process = subprocess.Popen(
            self.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            text=True,
            preexec_fn=os.setsid
        )
        while self.running:
            line = self.process.stdout.readline()
            if not line:
                break
            self.output.emit(line)

    def stop(self):
        self.running = False
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            except Exception as e:
                print(f"Failed to terminate scan: {e}")

class GUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("⚡ Wi-Fi Pentest Dashboard")
        self.setGeometry(150, 80, 1200, 700)
        self.set_background()
        self.setStyleSheet(self.global_styles())
        self.interface_list = self.get_wireless_interfaces()
        self.init_ui()
        install_tools()
        self.log("Tools installed.")

    def set_background(self):
        palette = QPalette()
        pixmap = QPixmap("bg.jpg")
        palette.setBrush(QPalette.Window, QBrush(pixmap.scaled(1200, 700, Qt.IgnoreAspectRatio, Qt.SmoothTransformation)))
        self.setPalette(palette)

    def get_wireless_interfaces(self):
        try:
            result = subprocess.run("iw dev", shell=True, capture_output=True, text=True)
            lines = result.stdout.splitlines()
            interfaces = [line.split()[-1] for line in lines if line.strip().startswith("Interface")]
            return interfaces if interfaces else ["No Interface Found"]
        except Exception:
            return ["No Interface Found"]

    def global_styles(self):
        return """
        QWidget {
            background-color: rgba(15, 17, 26, 200);
            color: #F0F0F0;
            font-family: 'Segoe UI', sans-serif;
            font-size: 14px;
        }
        QPushButton {
            background-color: #1F1F2E;
            border: 1px solid #03DAC6;
            color: #03DAC6;
            padding: 10px 18px;
            border-radius: 6px;
        }
        QPushButton:hover {
            background-color: #03DAC6;
            color: #000;
        }
        QLineEdit, QComboBox {
            background-color: #1E1E28;
            border: 1px solid #555;
            border-radius: 4px;
            padding: 6px;
            color: #EEE;
        }
        QTextEdit {
            background-color: #1B1D27;
            border: 1px solid #444;
            padding: 8px;
            color: #00FF9C;
        }
        QListWidget {
            background-color: #1A1C24;
            border-right: 1px solid #303030;
            color: #ccc;
            font-size: 16px;
            padding: 10px;
        }
        QListWidget::item {
            margin: 6px;
            padding: 8px;
        }
        QListWidget::item:selected {
            background-color: #03DAC6;
            color: #000;
            border-radius: 6px;
        }
        QLabel {
            font-weight: bold;
        }
        """

    def init_ui(self):
        main_layout = QHBoxLayout()
        self.nav = QListWidget()
        self.nav.setFixedWidth(200)
        for section in ["Dashboard", "Monitor", "Scan", "Attacks", "Password"]:
            QListWidgetItem(section, self.nav)
        self.nav.currentRowChanged.connect(self.display_section)

        self.stack = QStackedLayout()
        self.dashboard_tab()
        self.monitor_tab()
        self.scan_tab()
        self.attack_tab()
        self.wordlist_tab()

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setFixedHeight(160)

        self.right_panel = QVBoxLayout()
        self.stack_container = QWidget()
        self.stack_container.setLayout(self.stack)
        self.right_panel.addWidget(self.stack_container)

        self.logs_label = QLabel("Logs:")
        self.right_panel.addWidget(self.logs_label)
        self.right_panel.addWidget(self.log_box)

        main_layout.addWidget(self.nav)
        main_layout.addLayout(self.right_panel)
        self.setLayout(main_layout)
        self.nav.setCurrentRow(0)

    def dashboard_tab(self):
        w = QWidget()
        layout = QVBoxLayout()
        self.dashboard_status = QLabel("🟡 Interface: Not started\nMonitor Mode: Off")
        layout.addWidget(self.dashboard_status)
        self.dashboard_log_preview = QTextEdit()
        self.dashboard_log_preview.setReadOnly(True)
        self.dashboard_log_preview.setFixedHeight(300)
        layout.addWidget(QLabel("Live Preview:"))
        layout.addWidget(self.dashboard_log_preview)
        layout.addStretch()
        w.setLayout(layout)
        self.stack.addWidget(w)

    def monitor_tab(self):
        w = QWidget()
        layout = QVBoxLayout()
        self.interface_dropdown = QComboBox()
        self.interface_dropdown.addItems(self.interface_list)
        layout.addWidget(QLabel("Select Interface:"))
        layout.addWidget(self.interface_dropdown)
        btn_start = QPushButton("Start Monitor Mode")
        btn_stop = QPushButton("Stop Monitor Mode")
        btn_start.clicked.connect(lambda: self.start_monitor_mode())
        btn_stop.clicked.connect(lambda: self.stop_monitor_mode())
        layout.addWidget(btn_start)
        layout.addWidget(btn_stop)
        layout.addStretch()
        w.setLayout(layout)
        self.stack.addWidget(w)

    def scan_tab(self):
        self.scan_process = None
        w = QWidget()
        layout = QVBoxLayout()

        btn_layout = QHBoxLayout()
        btn = QPushButton("Scan Networks")
        stop_btn = QPushButton("Stop Scan")
        btn_layout.addWidget(btn)
        btn_layout.addWidget(stop_btn)
        layout.addLayout(btn_layout)

        self.scan_output_box = QTextEdit()
        self.scan_output_box.setReadOnly(True)
        self.scan_output_box.setFixedHeight(300)
        layout.addWidget(QLabel("Scan Output:"))
        layout.addWidget(self.scan_output_box)

        btn.clicked.connect(lambda: self.run_scan_command(f"airodump-ng {self.interface_dropdown.currentText()}"))
        stop_btn.clicked.connect(self.stop_scan_command)

        layout.addStretch()
        w.setLayout(layout)
        self.stack.addWidget(w)

    def stop_scan_command(self):
        if hasattr(self, 'thread') and self.thread.isRunning():
            self.thread.stop()
            self.thread.wait()
            self.log("Scan stopped.")

    def run_scan_command(self, command):
        self.thread = TerminalThread(command)
        self.thread.output.connect(self.scan_output_box.append)
        self.thread.start()
        QTimer.singleShot(10000, self.stop_scan_command)  # Auto stop after 10 seconds


    def attack_tab(self):
        w = QWidget()
        layout = QVBoxLayout()
        self.bssid_input = QLineEdit()
        self.channel_input = QLineEdit()
        layout.addWidget(QLabel("Target BSSID:"))
        layout.addWidget(self.bssid_input)
        layout.addWidget(QLabel("Channel:"))
        layout.addWidget(self.channel_input)
        btn_hs = QPushButton("Capture Handshake")
        btn_crack = QPushButton("Crack Handshake")
        btn_wps = QPushButton("WPS Attack")
        btn_pmkid = QPushButton("PMKID Attack")
        btn_hs.clicked.connect(self.capture_handshake_gui)
        btn_crack.clicked.connect(self.crack_handshake_gui)
        btn_wps.clicked.connect(self.wps_attack_gui)
        btn_pmkid.clicked.connect(lambda: self.run_terminal_command(
        f"hcxdumptool -i {self.interface_dropdown.currentText()} -o pmkid.pcapng --enable_status=15"))
        self.handshake_file_input = QLineEdit()
        self.handshake_file_input.setPlaceholderText("Path to handshake file (e.g., handshake-01.cap)")
        self.wordlist_file_input = QLineEdit()
        self.wordlist_file_input.setPlaceholderText("Path to wordlist (e.g., /usr/share/wordlists/rockyou.txt)")
        layout.addWidget(QLabel("Handshake File:"))
        layout.addWidget(self.handshake_file_input)
        layout.addWidget(QLabel("Wordlist File:"))
        layout.addWidget(self.wordlist_file_input)
        layout.addWidget(btn_hs)
        layout.addWidget(btn_crack)
        layout.addWidget(btn_wps)
        layout.addWidget(btn_pmkid)
        layout.addStretch()
        w.setLayout(layout)
        self.stack.addWidget(w)

    def wps_attack_gui(self):
        interface = self.interface_dropdown.currentText()
        bssid = self.bssid_input.text()
        channel = self.channel_input.text()
        if not interface or not bssid or not channel:
            self.log("Please provide interface, BSSID, and channel for WPS attack.")
            return

        self.log("Starting WPS attack...")
        cmd = f"reaver -i {interface} -b {bssid} -c {channel} -vv"
        self.wps_thread = TerminalThread(cmd)
        self.wps_thread.output.connect(self.handle_wps_output)
        self.wps_found = False
        self.wps_pass = None
        self.wps_thread.start()

        # Start a timer to stop after 2 minutes (120000 ms)
        QTimer.singleShot(120000, self.stop_wps_attack)

    def handle_wps_output(self, line):
        self.log(line.strip())
        # Look for passphrase in reaver output
        if "WPS PIN:" in line or "WPA PSK:" in line or "WPA key:" in line:
            self.wps_found = True
            self.wps_pass = line.strip()
            self.log(f"Password found: {self.wps_pass}")
            self.stop_wps_attack()

    def stop_wps_attack(self):
        if hasattr(self, 'wps_thread') and self.wps_thread.isRunning():
            self.wps_thread.stop()
            self.wps_thread.wait()
            if self.wps_found and self.wps_pass:
                self.log(f"WPS attack stopped. Password: {self.wps_pass}")
            else:
                self.log("Unable to find pass (WPS attack stopped after 2 minutes).")

    def wordlist_tab(self):
        w = QWidget()
        layout = QVBoxLayout()
        self.char_input = QLineEdit()
        self.len_input = QLineEdit()
        self.pattern_input = QLineEdit()
        self.output_input = QLineEdit()
        self.output_input.setPlaceholderText("Output file (e.g., wordlist.txt)")
        layout.addWidget(QLabel("Characters:"))
        layout.addWidget(self.char_input)
        layout.addWidget(QLabel("Length:"))
        layout.addWidget(self.len_input)
        layout.addWidget(QLabel("Pattern (Optional):"))
        layout.addWidget(self.pattern_input)
        layout.addWidget(QLabel("Output File:"))
        layout.addWidget(self.output_input)
        btn = QPushButton("Generate Wordlist")
        btn.clicked.connect(
            lambda: self.generate_wordlist_and_log()
        )
        layout.addWidget(btn)
        layout.addStretch()
        w.setLayout(layout)
        self.stack.addWidget(w)

    def generate_wordlist_and_log(self):
        characters = self.char_input.text()
        length = self.len_input.text()
        pattern = self.pattern_input.text()
        output_path = self.output_input.text() or "wordlist.txt"
        if not characters or not length:
            self.log("Please provide characters and length.")
            return
        try:
            create_password_list(characters, length, pattern, output_path)
            self.log(f"Wordlist generated: {output_path}")
        except Exception as e:
            self.log(f"Error generating wordlist: {e}")

    def display_section(self, index):
        self.stack.setCurrentIndex(index)
        if self.nav.item(index).text() == "Dashboard":
            self.logs_label.hide()
            self.log_box.hide()
        else:
            self.logs_label.show()
            self.log_box.show()

    def log(self, text):
        self.log_box.append(f"> {text}")
        self.update_dashboard()

    def run_terminal_command(self, command):
        self.thread = TerminalThread(command)
        self.thread.output.connect(self.log)
        self.thread.start()

    def update_dashboard(self):
        iface = self.interface_dropdown.currentText()
        mode_status = "On" if wifi_pentest.interface else "Off"
        self.dashboard_status.setText(f"🟢 Interface: {iface}\nMonitor Mode: {mode_status}")
        self.dashboard_log_preview.setText(self.log_box.toPlainText()[-500:])


    def capture_handshake_gui(self):
        bssid = self.bssid_input.text()
        channel = self.channel_input.text()
        try:
            result = capture_handshake(bssid, channel)
            self.log(f"Handshake capture started. Output: {result}")
        except Exception as e:
            self.log(f"Error: {e}")

    def start_monitor_mode(self):
        iface = self.interface_dropdown.currentText()
        try:
            result = set_monitor_mode(iface)
            self.log(result)
        except Exception as e:
            self.log(f"Error: {e}")

    def stop_monitor_mode(self):
        try:
            result = stop_monitor_mode()
            self.log(result)
        except Exception as e:
            self.log(f"Error: {e}")
    
    def crack_handshake_gui(self):
        handshake_file = self.handshake_file_input.text()
        wordlist_file = self.wordlist_file_input.text()
        bssid = self.bssid_input.text()
        if not handshake_file or not wordlist_file or not bssid:
            self.log("Please provide handshake file, wordlist, and BSSID.")
            return
        try:
            crack_handshake(handshake_file, wordlist_file)
            self.log(f"Cracking handshake started for {handshake_file} using {wordlist_file}")
        except Exception as e:
            self.log(f"Error: {e}")

    def closeEvent(self, event):
    # On window close, set interface back to managed mode if needed
        try:
            stop_monitor_mode()
            self.log("Monitor mode stopped and interface set to managed.")
        except Exception as e:
            self.log(f"Error while stopping monitor mode: {e}")
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = GUI()
    win.show()
    sys.exit(app.exec_())
