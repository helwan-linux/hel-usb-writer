import sys
import os
import hashlib
from PyQt5.QtWidgets import (
    QApplication, QWidget, QFileDialog, QVBoxLayout, QPushButton, QLabel,
    QComboBox, QTextEdit, QMessageBox, QHBoxLayout
)
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import QProcess, Qt, QThread, pyqtSignal
import math

class ChecksumThread(QThread):
    result = pyqtSignal(str)

    def __init__(self, path, is_device=False, limit_bytes=None):
        super().__init__()
        self.path = path
        self.is_device = is_device
        self.limit_bytes = limit_bytes
        self._process = None

    def run(self):
        if not self.is_device:
            try:
                hasher = hashlib.sha256()
                read_bytes = 0
                with open(self.path, 'rb') as f:
                    while True:
                        if self.limit_bytes and read_bytes >= self.limit_bytes:
                            break
                        chunk = f.read(4 * 1024 * 1024)
                        if not chunk:
                            break
                        if self.limit_bytes:
                            chunk = chunk[:self.limit_bytes - read_bytes]
                        hasher.update(chunk)
                        read_bytes += len(chunk)
                self.result.emit(hasher.hexdigest())
            except Exception as e:
                self.result.emit(f"Error: {e}")
        else:
            try:
                bs = 4 * 1024 * 1024
                count_blocks = math.ceil(self.limit_bytes / bs) if self.limit_bytes else None

                if count_blocks:
                    command_string = f"dd if={self.path} bs={bs} count={count_blocks} status=none 2>/dev/null | sha256sum"
                else:
                    command_string = f"dd if={self.path} bs={bs} status=none 2>/dev/null | sha256sum"

                command_parts = ["pkexec", "sh", "-c", command_string]

                self._process = QProcess()
                self._process.start(command_parts[0], command_parts[1:])
                self._process.waitForFinished(-1)

                output = self._process.readAllStandardOutput().data().decode().strip()
                exit_code = self._process.exitCode()
                exit_status = self._process.exitStatus()

                if exit_code == 0 and exit_status == QProcess.NormalExit:
                    checksum = output.split(' ')[0]
                    self.result.emit(checksum)
                else:
                    self.result.emit(f"Error executing command: {output}. Exit code: {exit_code}")

            except Exception as e:
                self.result.emit(f"Error: {e}")

    def stop(self):
        if self._process and self._process.state() == QProcess.Running:
            self._process.terminate()
            self._process.waitForFinished(1000)
            if self._process.state() == QProcess.Running:
                self._process.kill()


class USBIsoWriter(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Helwan USB ISO Writer")
        self.setGeometry(400, 200, 600, 500)
        # تحديد المسار المطلق للأيقونة بعد التثبيت بواسطة PKGBUILD
        # يجب أن تكون الأيقونة مثبتة في /usr/share/pixmaps/helwan-usb.png
        icon_path = "/usr/share/pixmaps/helwan-usb.png"
        
        # التأكد من وجود ملف الأيقونة قبل محاولة استخدامه
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            # يمكن وضع أيقونة احتياطية أو رسالة خطأ في السجل إذا لم يتم العثور على الأيقونة
            print(f"Warning: Icon file not found at {icon_path}. Using default icon.")

        layout = QVBoxLayout()

        logo = QLabel()
        # تحديد المسار المطلق للأيقونة للشعار داخل النافذة
        if os.path.exists(icon_path):
            pixmap = QPixmap(icon_path)
            logo.setPixmap(pixmap.scaledToWidth(64))
        else:
            # يمكن وضع صورة رمزية أو نص بديل إذا لم يتم العثور على الأيقونة
            logo.setText("Helwan USB")
            logo.setAlignment(Qt.AlignCenter)

        layout.addWidget(logo, alignment=Qt.AlignCenter)

        self.iso_label = QLabel("Selected ISO: None")
        self.choose_iso_button = QPushButton("Choose ISO File")
        self.choose_iso_button.clicked.connect(self.choose_iso)

        self.device_label = QLabel("Selected USB Device:")
        self.device_combo = QComboBox()
        self.refresh_devices_button = QPushButton("Refresh USB Devices")
        self.refresh_devices_button.clicked.connect(self.refresh_devices)

        device_selection_layout = QHBoxLayout()
        device_selection_layout.addWidget(self.device_combo)
        device_selection_layout.addWidget(self.refresh_devices_button)

        self.iso_checksum_button = QPushButton("Checksum ISO")
        self.iso_checksum_button.clicked.connect(self.checksum_iso)

        self.usb_checksum_button = QPushButton("Checksum USB")
        self.usb_checksum_button.clicked.connect(self.checksum_usb)

        self.write_button = QPushButton("Write ISO to USB")
        self.write_button.clicked.connect(self.write_iso)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self.iso_checksum_button)
        buttons_layout.addWidget(self.usb_checksum_button)
        buttons_layout.addWidget(self.write_button)

        self.log = QTextEdit()
        self.log.setReadOnly(True)

        layout.addWidget(self.iso_label)
        layout.addWidget(self.choose_iso_button)
        layout.addWidget(self.device_label)
        layout.addLayout(device_selection_layout)
        layout.addLayout(buttons_layout)
        layout.addWidget(self.log)

        self.setLayout(layout)
        self.iso_path = None
        self.iso_checksum = None
        self.usb_checksum = None
        self.process = None

        self.refresh_devices()

    def choose_iso(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose ISO File", "", "ISO Files (*.iso)")
        if path:
            self.iso_path = path
            self.iso_label.setText(f"Selected ISO: {os.path.basename(path)}")

    def refresh_devices(self):
        self.log.append("[🔍] Refreshing USB devices...")
        self.device_combo.clear()
        result = os.popen("lsblk -o NAME,SIZE,MODEL,TRAN,TYPE -dn").read().strip().split("\n")
        found_devices = False
        for line in result:
            if "disk" in line:
                parts = line.split()
                if len(parts) >= 4:
                    name, size, model, tran = parts[:4]
                    device_path = f"/dev/{name}"
                    self.device_combo.addItem(f"{device_path} ({size} - {model})")
                    found_devices = True
        if not found_devices:
            self.log.append("[💡] No USB devices found. Please ensure they are connected.")
        else:
            self.log.append("[✔] USB devices refreshed.")

    def checksum_iso(self):
        if not self.iso_path:
            QMessageBox.warning(self, "Error", "Please select an ISO file.")
            return
        self.log.append("[🔍] Calculating ISO checksum...")
        self.iso_checksum_thread = ChecksumThread(self.iso_path)
        self.iso_checksum_thread.result.connect(self.handle_iso_checksum)
        self.iso_checksum_thread.start()

    def handle_iso_checksum(self, result):
        self.iso_checksum = result
        self.log.append(f"[✔] ISO Checksum: {result}")

    def checksum_usb(self):
        if not self.iso_path:
            QMessageBox.warning(self, "Error", "Please select an ISO first.")
            return
        device_entry = self.device_combo.currentText()
        if not device_entry:
            QMessageBox.warning(self, "Error", "Please select a USB device.")
            return
        device = device_entry.split()[0]
        size = os.path.getsize(self.iso_path)
        self.log.append("[🔍] Calculating USB checksum (same size as ISO)...")
        self.usb_checksum_thread = ChecksumThread(device, is_device=True, limit_bytes=size)
        self.usb_checksum_thread.result.connect(self.handle_usb_checksum)
        self.usb_checksum_thread.start()

    def handle_usb_checksum(self, result):
        self.usb_checksum = result
        self.log.append(f"[✔] USB Checksum: {result}")
        if self.iso_checksum and self.usb_checksum:
            if self.iso_checksum == self.usb_checksum:
                self.log.append("[✅] MATCH: ISO and USB checksums match.")
            else:
                self.log.append("[❌] MISMATCH: ISO and USB checksums differ.")
                self.log.append("[💡] ملاحظة: قد يختلف مجموع التحقق للـ USB عن ملف ISO بسبب البيانات الوصفية أو التعبئة على الجهاز الخام. إذا كانت الفلاشة تعمل وتُقلع بشكل صحيح (كما في اختبار QEMU أو الإقلاع الفعلي)، فمن المرجح أنها سليمة وقابلة للاستخدام.")

    def write_iso(self):
        if not self.iso_path:
            QMessageBox.warning(self, "Error", "Please select an ISO file.")
            return
        device_entry = self.device_combo.currentText()
        if not device_entry:
            QMessageBox.warning(self, "Error", "Please select a USB device.")
            return
        device = device_entry.split()[0]
        confirm = QMessageBox.question(
            self,
            "Confirm Write",
            f"Are you sure you want to write:\n\n{self.iso_path}\n\nto\n{device} ?\n\nAll data on the USB will be lost!",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm != QMessageBox.Yes:
            return

        self.log.append(f"[INFO] Writing {self.iso_path} to {device}...")
        command = ["pkexec", "dd", f"if={self.iso_path}", f"of={device}", "bs=4M", "status=progress", "oflag=sync"]
        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.finished.connect(self.process_finished)
        self.process.start(command[0], command[1:])

    def handle_stdout(self):
        data = self.process.readAllStandardOutput().data().decode()
        self.log.append(data)

    def handle_stderr(self):
        data = self.process.readAllStandardError().data().decode()
        self.log.append(data)

    def process_finished(self):
        self.log.append("[✔] Done writing ISO.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    writer = USBIsoWriter()
    writer.show()
    sys.exit(app.exec_())
