import sys
import os
import hashlib
import re
from PyQt5.QtWidgets import (
    QApplication, QWidget, QFileDialog, QVBoxLayout, QPushButton, QLabel,
    QComboBox, QTextEdit, QMessageBox, QHBoxLayout, QProgressBar
)
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import QProcess, Qt, QThread, pyqtSignal
import math

class ChecksumThread(QThread):
    result = pyqtSignal(str)
    process_error_signal = pyqtSignal(str)

    def __init__(self, path, is_device=False, limit_bytes=None):
        super().__init__()
        self.path = path
        self.is_device = is_device
        self.limit_bytes = limit_bytes
        self._process = None

    def run(self):
        try:
            if not self.is_device:
                hasher = hashlib.sha256()
                read_bytes = 0
                with open(self.path, 'rb') as f:
                    while True:
                        if self.limit_bytes and read_bytes >= self.limit_bytes:
                            break
                        chunk = f.read(4 * 1024 * 1024)
                        if not chunk: break
                        if self.limit_bytes:
                            chunk = chunk[:self.limit_bytes - read_bytes]
                        hasher.update(chunk)
                        read_bytes += len(chunk)
                self.result.emit(hasher.hexdigest())
            else:
                bs = 4 * 1024 * 1024
                count_blocks = math.ceil(self.limit_bytes / bs) if self.limit_bytes else None
                cmd = f"dd if={self.path} bs={bs} count={count_blocks} status=none | sha256sum" if count_blocks else f"dd if={self.path} bs={bs} status=none | sha256sum"
                
                self._process = QProcess()
                self._process.start("pkexec", ["sh", "-c", cmd])
                if not self._process.waitForFinished(-1):
                    self.result.emit("Error: Process failed")
                    return
                output = self._process.readAllStandardOutput().data().decode().strip()
                self.result.emit(output.split(' ')[0] if output else "Error")
        except Exception as e:
            self.result.emit(f"Error: {e}")

class USBIsoWriter(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Helwan USB ISO Writer")
        self.setGeometry(400, 200, 600, 550)
        
        # الهوية البصرية لـ Helwan Linux [cite: 2026-01-26]
        icon_path = "/usr/share/pixmaps/helwan-usb.png"
        
        layout = QVBoxLayout()
        
        # حل مشكلة الأيقونة: التحجيم البرمجي لتجنب خطأ xcb request length
        logo = QLabel()
        if os.path.exists(icon_path):
            pixmap = QPixmap(icon_path)
            # تصغير الأيقونة للنافذة (Taskbar)
            scaled_icon = pixmap.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.setWindowIcon(QIcon(scaled_icon))
            # تصغير الأيقونة للشعار داخل البرنامج
            logo.setPixmap(pixmap.scaledToWidth(80, Qt.SmoothTransformation))
        else:
            logo.setText("💿 Helwan USB Writer")
            logo.setStyleSheet("font-size: 18px; font-weight: bold;")
        
        layout.addWidget(logo, alignment=Qt.AlignCenter)

        # اختيار الـ ISO
        self.iso_label = QLabel("ISO File: Not Selected")
        self.iso_label.setStyleSheet("color: #555;")
        self.choose_iso_button = QPushButton("Select ISO Image")
        self.choose_iso_button.clicked.connect(self.choose_iso)

        # اختيار الجهاز (USB فقط لضمان الأمان) [cite: 2026-01-26]
        self.device_combo = QComboBox()
        self.refresh_button = QPushButton("🔄 Refresh")
        self.refresh_button.clicked.connect(self.refresh_devices)
        
        device_layout = QHBoxLayout()
        device_layout.addWidget(self.device_combo, 4)
        device_layout.addWidget(self.refresh_button, 1)

        # شريط التقدم المرئي
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.hide()

        # الأزرار الرئيسية
        self.write_button = QPushButton("🔥 Write to USB")
        self.write_button.setStyleSheet("background-color: #d32f2f; color: white; font-weight: bold; padding: 10px;")
        self.write_button.clicked.connect(self.write_iso)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(120)

        # ترتيب العناصر
        layout.addWidget(QLabel("<b>1. Select Image:</b>"))
        layout.addWidget(self.iso_label)
        layout.addWidget(self.choose_iso_button)
        layout.addSpacing(10)
        layout.addWidget(QLabel("<b>2. Select USB Drive:</b>"))
        layout.addLayout(device_layout)
        layout.addSpacing(15)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.write_button)
        layout.addWidget(QLabel("<b>Activity Log:</b>"))
        layout.addWidget(self.log)

        self.setLayout(layout)
        self.iso_path = None
        self.refresh_devices()

    def refresh_devices(self):
        self.device_combo.clear()
        # فلترة ذكية لضمان إظهار الفلاشات فقط [cite: 2026-01-26]
        cmd = "lsblk -p -d -n -o NAME,SIZE,MODEL,TRAN | grep 'usb'"
        result = os.popen(cmd).read().strip().split("\n")
        
        if not result or result == ['']:
            self.device_combo.addItem("No USB drives detected")
            self.write_button.setEnabled(False)
        else:
            for line in result:
                self.device_combo.addItem(line.strip())
            self.write_button.setEnabled(True)

    def choose_iso(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select ISO", "", "ISO Files (*.iso)")
        if path:
            self.iso_path = path
            self.iso_label.setText(f"File: {os.path.basename(path)}")

    def write_iso(self):
        if not self.iso_path:
            return QMessageBox.warning(self, "Error", "Please select an ISO first.")
        
        device_info = self.device_combo.currentText()
        if "No USB" in device_info: return
        
        device_path = device_info.split()[0]
        
        confirm = QMessageBox.critical(
            self, "Final Warning",
            f"Are you sure?\n\nThis will PERMANENTLY ERASE everything on:\n{device_info}\n\nProceed?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if confirm == QMessageBox.Yes:
            self.start_writing(device_path)

    def start_writing(self, device):
        self.log.append(f"[!] Starting write to {device}...")
        self.write_button.setEnabled(False)
        self.progress_bar.show()
        self.progress_bar.setValue(0)
        
        # استخدام dd مع ميزة تتبع التقدم
        cmd = ["pkexec", "dd", f"if={self.iso_path}", f"of={device}", "bs=4M", "status=progress", "oflag=sync"]
        
        self.process = QProcess(self)
        self.process.readyReadStandardError.connect(self.update_progress)
        self.process.finished.connect(self.finish_write)
        self.process.start(cmd[0], cmd[1:])

    def update_progress(self):
        data = self.process.readAllStandardError().data().decode()
        match = re.search(r'(\d+) bytes', data)
        if match and self.iso_path:
            written = int(match.group(1))
            total = os.path.getsize(self.iso_path)
            percent = int((written / total) * 100)
            self.progress_bar.setValue(percent)

    def finish_write(self, exit_code, exit_status):
        self.write_button.setEnabled(True)
        if exit_code == 0:
            self.progress_bar.setValue(100)
            self.log.append("[✔] Success! You can safely remove the USB.")
            QMessageBox.information(self, "Done", "ISO has been successfully written!")
        else:
            self.log.append("[❌] Error: Operation failed or cancelled.")
            self.progress_bar.hide()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    writer = USBIsoWriter()
    writer.show()
    sys.exit(app.exec_())
