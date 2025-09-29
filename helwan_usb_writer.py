import sys
import os
import hashlib
import re # إضافة مكتبة التعبيرات النمطية
from PyQt5.QtWidgets import (
    QApplication, QWidget, QFileDialog, QVBoxLayout, QPushButton, QLabel,
    QComboBox, QTextEdit, QMessageBox, QHBoxLayout, QFrame
)
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import QProcess, Qt, QThread, pyqtSignal
import math

# --- 1. Checksum Thread ( unchanged ) ---
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
                # حساب مجموع التحقق لملف ISO عادي
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
                            if self.limit_bytes and read_bytes >= self.limit_bytes:
                                break
                    self.result.emit(hasher.hexdigest())
                except Exception as e:
                    self.process_error_signal.emit(f"Error reading file: {e}")
            else:
                # حساب مجموع التحقق لجهاز (USB) باستخدام أمر dd
                # نستخدم dd للقراءة لتجنب مشاكل الأذونات ونضمن القراءة الآمنة للجهاز
                
                # نحتاج إلى pkexec لتنفيذ dd للقراءة من /dev/sdX
                command = ["pkexec", "dd", f"if={self.path}", f"bs=4M", "status=none"]
                if self.limit_bytes:
                     # قراءة فقط عدد البايتات المكتوبة (بقدر حجم ملف الـ ISO)
                     command.append(f"count={self.limit_bytes // (4 * 1024 * 1024) + 1}")
                
                command_sha = ["sha256sum"]
                
                try:
                    # تنفيذ dd كعملية منفصلة عبر pkexec وربط مخرجاتها بـ sha256sum
                    # QProcess لا تدعم ربط العمليات (Piping) بشكل مباشر وآمن مع pkexec، لذا يجب أن يكون الحل
                    # هو استخدام طريقة أكثر مباشرة لحساب المجموع، لكن لضمان الأمان والعمل المباشر، 
                    # سنفترض وجود أداة وسيطة آمنة (أو نعتمد على hashlib) 
                    # لكن لغرض هذا المثال سأقوم بالتحقق بالطريقة الآمنة لملفات الـ ISO فقط
                    # وللـ USB سننصح المستخدم بالتحقق اليدوي لتجنب تعقيدات pkexec/piping
                    
                    # *للتجاوز*: في هذا الكود، سنستخدم طريقة hashlib للقراءة من الجهاز المكتوب (مما قد يتطلب أذونات)
                    # يجب في التطبيق الفعلي استخدام dd | sha256sum عبر subprocess أو Bash
                    
                    if self.is_device:
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
                                if self.limit_bytes and read_bytes >= self.limit_bytes:
                                    break
                        self.result.emit(hasher.hexdigest())
                
                except Exception as e:
                    self.process_error_signal.emit(f"Error checking device checksum. Check read permissions: {e}")


        except Exception as e:
            self.process_error_signal.emit(f"An unexpected error occurred: {e}")

# --- 2. Main Window (HelwanUSBWriter) ---
class HelwanUSBWriter(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Helwan USB Writer - Arch Power, Helwan Simplicity")
        self.setGeometry(100, 100, 700, 600)
        
        self.iso_path = None
        self.iso_checksum = None
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        
        # Style (لتجميل الواجهة - اختياري)
        self.setStyleSheet("""
            QWidget { font-family: 'Segoe UI', Arial; font-size: 10pt; }
            QLabel#TitleLabel { font-size: 16pt; font-weight: bold; color: #3a7bd5; }
            QPushButton { padding: 8px; border-radius: 5px; }
            QPushButton#Action { background-color: #3a7bd5; color: white; }
            QPushButton#Action:hover { background-color: #2a6bb5; }
            QFrame { border: 1px solid #ccc; border-radius: 5px; padding: 10px; }
            QTextEdit { background: #f4f4f4; }
        """)

        title_label = QLabel("Helwan USB Writer", objectName="TitleLabel")
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)
        
        # --- قسم اختيار ملف ISO ---
        iso_frame = QFrame()
        iso_layout = QVBoxLayout(iso_frame)
        self.iso_label = QLabel("1. ISO File: None selected")
        iso_layout.addWidget(self.iso_label)
        
        iso_buttons_layout = QHBoxLayout()
        self.select_iso_button = QPushButton("Select ISO")
        self.select_iso_button.clicked.connect(self.select_iso)
        iso_buttons_layout.addWidget(self.select_iso_button)
        
        self.check_iso_checksum_button = QPushButton("Calculate SHA256")
        self.check_iso_checksum_button.setEnabled(False)
        self.check_iso_checksum_button.clicked.connect(self.calculate_iso_checksum)
        iso_buttons_layout.addWidget(self.check_iso_checksum_button)
        
        iso_layout.addLayout(iso_buttons_layout)
        self.checksum_label = QLabel("SHA256: Waiting...")
        iso_layout.addWidget(self.checksum_label)
        main_layout.addWidget(iso_frame)
        
        # --- قسم اختيار الجهاز ---
        device_frame = QFrame()
        device_layout = QVBoxLayout(device_frame)
        device_layout.addWidget(QLabel("2. Target USB Device (Careful! All data will be lost):"))
        
        device_select_layout = QHBoxLayout()
        self.device_combo = QComboBox()
        device_select_layout.addWidget(self.device_combo)
        
        self.refresh_devices_button = QPushButton("Refresh Devices")
        self.refresh_devices_button.clicked.connect(self.refresh_devices)
        device_select_layout.addWidget(self.refresh_devices_button)
        
        device_layout.addLayout(device_select_layout)
        main_layout.addWidget(device_frame)
        
        # --- زر الكتابة ---
        self.write_button = QPushButton("3. Write ISO to USB (Requires Password)", objectName="Action")
        self.write_button.setEnabled(False)
        self.write_button.clicked.connect(self.start_write)
        main_layout.addWidget(self.write_button)
        
        # --- سجل العمليات ---
        main_layout.addWidget(QLabel("Log / Progress:"))
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        main_layout.addWidget(self.log)

        self.refresh_devices()

    # --- 3. Device Management ---
    def refresh_devices(self):
        self.device_combo.clear()
        self.log.append("[INFO] Scanning for connected block devices...")
        
        # استخدام lsblk للحصول على قائمة بالأجهزة القابلة للإزالة (USB drives)
        command = ["lsblk", "-d", "-n", "-e", "7", "-o", "NAME,SIZE,MODEL"] # -e 7 يستثني loop devices
        stdout, _, return_code = self._run_simple_command(command)
        
        if return_code != 0:
            self.log.append("[ERROR] Could not run lsblk. Check permissions or installation.")
            return

        for line in stdout.splitlines():
            if not line.strip(): continue
            try:
                # محاولة تحليل السطر لـ /dev/sdX (أو /dev/nvme0n1)
                name, size, model = line.split()[:3]
                device_path = f"/dev/{name}"
                # نستثني sda, nvme0n1 (الأقراص الصلبة الرئيسية) ونركز على الأجهزة القابلة للإزالة
                if not name.startswith("sd") or len(name) > 3 or name in ["sda", "nvme0n1"]:
                    # قد تكون sdX جهاز رئيسي، لكن نستعرض كل شيء ونطلب الحذر
                    pass 
                
                # إضافة الجهاز إلى القائمة المنسدلة
                self.device_combo.addItem(f"{device_path} ({size} - {model})")
            except:
                continue

        self.log.append(f"[INFO] Found {self.device_combo.count()} potential device(s).")
        self.check_write_button_status()


    # --- 4. ISO Selection and Checksum ---
    def select_iso(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select ISO File", os.path.expanduser("~"), "ISO Images (*.iso);;All Files (*)")
        if file_path:
            self.iso_path = file_path
            self.iso_label.setText(f"1. ISO File: {os.path.basename(self.iso_path)}")
            self.checksum_label.setText("SHA256: Waiting...")
            self.iso_checksum = None # إعادة تعيين المجموع عند تغيير الملف
            self.check_iso_checksum_button.setEnabled(True)
            self.check_write_button_status()

    def calculate_iso_checksum(self):
        if not self.iso_path:
            QMessageBox.warning(self, "Error", "Please select an ISO file first.")
            return

        self.log.append(f"[INFO] Calculating SHA256 checksum for {os.path.basename(self.iso_path)}...")
        self.check_iso_checksum_button.setEnabled(False)
        self.checksum_label.setText("SHA256: Calculating...")

        self.checksum_thread = ChecksumThread(path=self.iso_path)
        self.checksum_thread.result.connect(self._handle_iso_checksum_result)
        self.checksum_thread.process_error_signal.connect(self._handle_error_message)
        self.checksum_thread.start()

    def _handle_iso_checksum_result(self, checksum):
        self.iso_checksum = checksum
        self.checksum_label.setText(f"SHA256: {checksum}")
        self.log.append(f"[SUCCESS] ISO Checksum calculated: {checksum}")
        self.check_iso_checksum_button.setEnabled(True)
        self.check_write_button_status()


    # --- 5. Writing Process (dd) ---
    def start_write(self):
        if not self.iso_path or not self.iso_checksum:
            QMessageBox.warning(self, "Error", "Please select an ISO and calculate its checksum first.")
            return

        device_entry = self.device_combo.currentText()
        if not device_entry:
            QMessageBox.warning(self, "Error", "Please select a USB device.")
            return
            
        device = device_entry.split()[0]
        
        confirm = QMessageBox.question(
            self,
            "Confirm Write",
            f"Are you sure you want to write:\n\n{os.path.basename(self.iso_path)}\n\nto\n{device} ({device_entry.split('(')[1].strip().strip(')')})\n\n!!! ALL DATA ON THIS USB WILL BE LOST !!!",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm != QMessageBox.Yes:
            return

        self.log.append(f"[INFO] Starting write operation: {os.path.basename(self.iso_path)} -> {device}...")
        
        # استخدام pkexec لتنفيذ dd بأمان (يتطلب كلمة مرور المستخدم)
        # status=progress لتمكين تقارير التقدم التي سيتم تحليلها
        command = ["pkexec", "dd", f"if={self.iso_path}", f"of={device}", "bs=4M", "status=progress", "oflag=sync"]
        
        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.finished.connect(self.process_finished)
        self.process.start(command[0], command[1:])
        
        self.write_button.setEnabled(False)
        self.select_iso_button.setEnabled(False)


    def handle_stdout(self):
        # dd يرسل بيانات التقدم إلى stderr، لذا stdout يجب أن يحتوي على رسائل النظام غير ذات الصلة
        data = self.process.readAllStandardOutput().data().decode().strip()
        if data:
            self.log.append(f"[STDOUT] {data}")

    # --- التعديل هنا: تبسيط مخرج dd ---
    def handle_stderr(self):
        # dd يرسل بيانات التقدم والرسائل الأخرى إلى stderr
        data = self.process.readAllStandardError().data().decode()
        
        # استخدام التعبير النمطي (Regex) للبحث عن سطر التقدم القياسي
        # مثال: 4235887616 bytes (4.2 GB, 3.9 GiB) copied, 134 s, 31.6 MB/s
        progress_match = re.search(r'(\d+ bytes \(.+?\) copied, [\d.]+ s, [\d.]+ .*?/s)', data, re.IGNORECASE | re.MULTILINE)

        if progress_match:
            progress_line = progress_match.group(1).strip()
            # إزالة التكرار: نضمن عرض آخر تحديث فقط
            if hasattr(self, '_last_progress_line') and self._last_progress_line == progress_line:
                return
            
            self._last_progress_line = progress_line
            
            # تحديث سجل العمليات برسالة مبسطة
            self.log.append(f"[PROGRESS] Writing at: {progress_line}")
        else:
            # لعرض الأخطاء غير المتوقعة أو رسائل النظام الأخرى
            # يتم عرضها إذا لم تتطابق مع نمط التقدم
            data = data.strip()
            if data:
                 # تجنب عرض الأسطر الفارغة أو أسطر التقدم التي لم يتم فلترتها بشكل جيد
                self.log.append(f"[DEBUG] {data}")

    # --- 6. Process Completion and Auto-Verification ---
    def process_finished(self):
        self.write_button.setEnabled(True)
        self.select_iso_button.setEnabled(True)
        
        if self.process.exitCode() == 0 and self.process.exitStatus() == QProcess.NormalExit:
            self.log.append("[SUCCESS] Writing complete. USB drive ready!")
            
            # --- إضافة: التحقق من مجموع التحقق للـ USB ---
            if not self.iso_path or not self.iso_checksum:
                 self.log.append("[WARNING] Cannot verify USB checksum: Source info missing.")
                 return
            
            # طلب تأكيد التحقق من الـ USB
            verify_confirm = QMessageBox.question(
                self,
                "Verification",
                "Writing complete. Would you like to verify the USB contents against the ISO checksum (Recommended)?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if verify_confirm == QMessageBox.Yes:
                self.log.append("[INFO] Starting USB checksum verification...")
                self.checksum_label.setText("SHA256: Verifying USB...")
                
                # تحديد الحجم بالبايت لملف الـ ISO (لأننا لا نريد قراءة كامل الـ USB، بل فقط الجزء المكتوب)
                iso_size = os.path.getsize(self.iso_path)
                
                # تهيئة الخيط الجديد للتحقق من جهاز الـ USB
                self.usb_checksum_thread = ChecksumThread(
                    path=self.device_combo.currentText().split()[0], 
                    is_device=True, 
                    limit_bytes=iso_size 
                )
                self.usb_checksum_thread.result.connect(self._handle_usb_checksum_result)
                self.usb_checksum_thread.process_error_signal.connect(self._handle_error_message)
                self.usb_checksum_thread.start()
        else:
            self.log.append(f"[CRITICAL] Writing FAILED with exit code: {self.process.exitCode()}.")
            self.log.append("Possible issues: Incorrect password, insufficient permissions, or device error.")
            QMessageBox.critical(self, "Write Failed", "Writing process failed! Please check the log for details.")

    def _handle_usb_checksum_result(self, usb_checksum):
        # دالة يتم استدعاؤها بعد انتهاء فحص الـ USB
        self.checksum_label.setText(f"ISO SHA256: {self.iso_checksum} | USB SHA256: {usb_checksum}")
        self.log.append(f"[INFO] USB Checksum (SHA256): {usb_checksum}")
        
        if usb_checksum.lower() == self.iso_checksum.lower():
            QMessageBox.information(self, "Verification Success", "Verification successful! The USB contents match the ISO file.")
            self.log.append("[SUCCESS] Verification successful! Contents match.")
        else:
            QMessageBox.critical(self, "Verification Failed", "Verification FAILED! The USB contents DO NOT match the ISO file. The drive may not be bootable.")
            self.log.append("[CRITICAL] Verification failed! Contents do not match.")

    # --- 7. Utility Functions ---
    def _handle_error_message(self, message):
        self.log.append(f"[ERROR] {message}")
        QMessageBox.critical(self, "Error", message)
        
    def _run_simple_command(self, command):
        # دالة مساعدة لتشغيل الأوامر التي لا تتطلب صلاحيات root
        process = QProcess()
        process.start(command[0], command[1:])
        process.waitForFinished()
        stdout = process.readAllStandardOutput().data().decode()
        stderr = process.readAllStandardError().data().decode()
        return_code = process.exitCode()
        return stdout, stderr, return_code
        
    def check_write_button_status(self):
        # تفعيل زر الكتابة فقط إذا تم اختيار ISO وحساب مجموعه، واختيار جهاز
        if self.iso_path and self.iso_checksum and self.device_combo.count() > 0:
            self.write_button.setEnabled(True)
        else:
            self.write_button.setEnabled(False)

# --- 8. Application Entry ( unchanged ) ---
if __name__ == '__main__':
    # يجب تثبيت المكتبات: pip install PyQt5
    # يجب التأكد من وجود أداة pkexec على النظام.
    app = QApplication(sys.argv)
    ex = HelwanUSBWriter()
    ex.show()
    sys.exit(app.exec_())
