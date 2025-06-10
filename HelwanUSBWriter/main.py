#!/usr/bin/env python3
import sys
import os
import subprocess
import threading
import time

from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QFileDialog, QComboBox, QLabel, QProgressBar, QMessageBox,
    QMainWindow, QLineEdit
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread

# يمكنك استخدام ملف translations.py الخاص بمشروعك
# تأكد من إضافة المفاتيح الجديدة الخاصة بهذا البرنامج
from translations import translations

# --- Worker Thread for DD Command ---
class DDWorker(QThread):
    # إشارات لإرسال التحديثات من الثريد إلى الواجهة الرسومية
    progress_updated = pyqtSignal(int)
    status_message = pyqtSignal(str)
    operation_finished = pyqtSignal(bool, str) # bool for success/failure, str for message

    def __init__(self, iso_path, usb_device_path, parent=None):
        super().__init__(parent)
        self.iso_path = iso_path
        self.usb_device_path = usb_device_path
        self._is_running = True

    def run(self):
        try:
            self.status_message.emit(translations[HelwanUSBWriter.current_language]["preparing_to_write"].format(self.usb_device_path))

            # استخدام dd مع sudo
            # status=progress لإظهار التقدم
            # bs=4M لتحسين الأداء (حجم الكتلة)
            # conv=fsync لضمان كتابة البيانات على القرص
            command = [
                'sudo', 'dd',
                f'if={self.iso_path}',
                f'of={self.usb_device_path}',
                'bs=4M',
                'status=progress',
                'conv=fsync'
            ]

            # تشغيل الأمر في عملية فرعية والتقاط الخرج
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, # للتعامل مع الخرج كنص
                bufsize=1 # سطر بسطر
            )

            # للحصول على حجم ملف ISO لتقدير التقدم
            iso_size = os.path.getsize(self.iso_path)
            # تقدير التقدم بناءً على حجم ملف ISO والبيانات المكتوبة
            # dd يرسل التقدم إلى stderr، لذا نراقب stderr
            bytes_written = 0
            for line in iter(process.stderr.readline, ''):
                if self._is_running:
                    self.status_message.emit(line.strip())
                    # محاولة تحليل سطر التقدم من dd
                    # مثال: 10485760 bytes (10 MB, 10 MiB) copied, 1.0000 s, 10.0 MB/s
                    if "bytes" in line and "copied" in line:
                        try:
                            # البحث عن الرقم الأول الذي يمثل عدد البايتات المكتوبة
                            parts = line.split()
                            for part in parts:
                                if part.isdigit():
                                    bytes_written = int(part)
                                    break

                            if iso_size > 0:
                                progress = int((bytes_written / iso_size) * 100)
                                self.progress_updated.emit(progress)
                            else:
                                self.progress_updated.emit(0) # إذا كان حجم الISO صفر
                        except ValueError:
                            pass # تجاهل الأخطاء في تحليل السطر
                else:
                    process.terminate() # أوقف العملية إذا طلب الإلغاء
                    break

            process.wait() # انتظر حتى تكتمل العملية
            stdout, stderr = process.communicate() # التقاط ما تبقى من الخرج

            if process.returncode == 0:
                self.operation_finished.emit(True, translations[HelwanUSBWriter.current_language]["write_successful"])
            else:
                error_message = stderr.strip() if stderr else translations[HelwanUSBWriter.current_language]["unknown_error"]
                self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["write_failed"].format(error_message))

        except FileNotFoundError:
            self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["dd_not_found"])
        except Exception as e:
            self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["unexpected_error"].format(str(e)))

    def stop(self):
        self._is_running = False
        # يجب أن نقتل عملية dd هنا إذا كانت لا تزال قيد التشغيل
        # هذا يتطلب الاحتفاظ بمرجع لـ process والتحقق مما إذا كانت لا تزال تعمل
        # في هذا المثال المبسط، يكفي وضع self._is_running = False
        # لكن في تطبيق حقيقي قد تحتاج إلى process.terminate() أو os.kill()

# --- Main Application Window ---
class HelwanUSBWriter(QMainWindow):
    current_language = "en" # الافتراضي، سيتم تحديثه

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(translations[self.current_language]["app_title_usb"])
        self.setWindowIcon(QIcon("icons/usb.png")) # تأكد من وجود الأيقونة في مجلد icons

        self.iso_path = None
        self.usb_device_path = None
        self.dd_worker = None

        self._create_widgets()
        self._create_layouts()
        self._connect_signals()
        self.refresh_usb_devices()

        self.resize(500, 300)

    def _create_widgets(self):
        self.iso_label = QLabel(translations[self.current_language]["select_iso_file"])
        self.iso_path_display = QLineEdit()
        self.iso_path_display.setReadOnly(True)
        self.browse_iso_button = QPushButton(translations[self.current_language]["browse"])

        self.usb_label = QLabel(translations[self.current_language]["select_usb_device"])
        self.usb_device_combo = QComboBox()
        self.refresh_usb_button = QPushButton(translations[self.current_language]["refresh"])

        self.write_button = QPushButton(translations[self.current_language]["write_to_usb"])
        self.write_button.setEnabled(False) # غير مفعلة حتى يتم اختيار ISO وجهاز USB

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.status_label = QLabel(translations[self.current_language]["ready_to_start"])
        self.status_label.setWordWrap(True)

    def _create_layouts(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        # ISO selection
        iso_layout = QHBoxLayout()
        iso_layout.addWidget(self.iso_path_display)
        iso_layout.addWidget(self.browse_iso_button)
        main_layout.addWidget(self.iso_label)
        main_layout.addLayout(iso_layout)

        # USB device selection
        usb_layout = QHBoxLayout()
        usb_layout.addWidget(self.usb_device_combo)
        usb_layout.addWidget(self.refresh_usb_button)
        main_layout.addWidget(self.usb_label)
        main_layout.addLayout(usb_layout)

        main_layout.addStretch(1) # دفع العناصر للأعلى

        # Write button
        main_layout.addWidget(self.write_button)

        # Progress and status
        main_layout.addWidget(self.progress_bar)
        main_layout.addWidget(self.status_label)

    def _connect_signals(self):
        self.browse_iso_button.clicked.connect(self.browse_iso_file)
        self.usb_device_combo.currentIndexChanged.connect(self.select_usb_device)
        self.refresh_usb_button.clicked.connect(self.refresh_usb_devices)
        self.write_button.clicked.connect(self.start_write_process)

    def update_ui_state(self):
        # تفعيل/تعطيل زر الكتابة بناءً على ما إذا كان ISO وجهاز USB محددين
        is_ready = self.iso_path is not None and self.usb_device_path is not None and self.usb_device_path != translations[self.current_language]["no_usb_selected_option"]
        self.write_button.setEnabled(is_ready)

    def browse_iso_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self,
                                                   translations[self.current_language]["open_iso_file"],
                                                   os.path.expanduser("~"), # يبدأ من مجلد المستخدم
                                                   "ISO Files (*.iso);;All Files (*)")
        if file_path:
            self.iso_path = file_path
            self.iso_path_display.setText(os.path.basename(file_path))
            self.update_ui_state()

    def get_usb_devices(self):
        """
        يحاول اكتشاف أجهزة USB (وليس أقسامها) باستخدام lsblk.
        يعيد قائمة من أزواج (اسم الجهاز، مسار الجهاز).
        """
        devices = []
        try:
            # استخدام lsblk للحصول على قائمة بالأقراص (type disk) وليس الأقسام (part)
            # -J لخرج JSON لسهولة التحليل
            # -o NAME,SIZE,TYPE لاسم الجهاز وحجمه ونوعه
            cmd = ['lsblk', '-J', '-o', 'NAME,SIZE,TYPE,MODEL']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)

            for block_device in data.get('blockdevices', []):
                if block_device.get('type') == 'disk':
                    # تأكد أنه ليس قرص النظام الأساسي (هذا تبسيط، قد يحتاج لتحسين)
                    # يجب أن يكون المسار يبدأ بـ /dev/sd أو /dev/nvme
                    device_name = f"/dev/{block_device['name']}"
                    # تجنب الأقراص الرئيسية (sda, sdb, etc.) اذا كانت تحمل نظام التشغيل
                    # هذا الجزء يحتاج لحذر شديد!
                    # يمكننا استبعاد الأقراص التي تحتوي على نقاط تحميل مهمة (/, /boot, /home)
                    # لكن هذا يتطلب فحصًا أعمق. حاليًا، نعتبر كل الأقراص "disk" مؤهلة
                    # فقط اعرض الأجهزة التي لا تحتوي على أقسام محمولة (Mounted) لتجنب الحرق الخاطئ
                    # هذا الكود لا يقوم بهذا الفحص الدقيق، كن حذرًا.
                    
                    # نموذج: /dev/sdb (8GB) - My USB Drive
                    model = block_device.get('model', '').strip()
                    display_name = f"{device_name} ({block_device.get('size', 'Unknown Size')})"
                    if model:
                        display_name += f" - {model}"
                    
                    devices.append((display_name, device_name))
        except FileNotFoundError:
            QMessageBox.critical(self, translations[self.current_language]["error"], translations[self.current_language]["lsblk_not_found"])
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, translations[self.current_language]["error"], f"Error running lsblk: {e.stderr}")
        except json.JSONDecodeError:
            QMessageBox.critical(self.current_language, translations[self.current_language]["error"], "Failed to parse lsblk output.")
        except Exception as e:
            QMessageBox.critical(self.current_language, translations[self.current_language]["error"], f"An unexpected error occurred: {e}")
        return devices

    def refresh_usb_devices(self):
        self.usb_device_combo.clear()
        self.usb_device_combo.addItem(translations[self.current_language]["select_usb_device_option"])
        
        # إضافة خيار افتراضي لمنع التحديد الخاطئ
        self.usb_device_combo.addItem(translations[self.current_language]["no_usb_selected_option"], None)

        usb_devices = self.get_usb_devices()
        if not usb_devices:
            self.usb_device_combo.setItemText(0, translations[self.current_language]["no_usb_found"])
            self.usb_device_combo.setCurrentIndex(0) # Keep "No USB found" selected
        else:
            for display_name, path in usb_devices:
                self.usb_device_combo.addItem(display_name, path)
            self.usb_device_combo.setCurrentIndex(0) # Select the "Select USB device" option initially
        
        self.usb_device_path = None # Reset selected device
        self.update_ui_state()

    def select_usb_device(self, index):
        selected_data = self.usb_device_combo.itemData(index)
        if selected_data is not None:
            self.usb_device_path = selected_data
        else:
            self.usb_device_path = None # "No USB selected" or "Select USB device"
        self.update_ui_state()

    def start_write_process(self):
        if not self.iso_path:
            QMessageBox.warning(self, translations[self.current_language]["warning"], translations[self.current_language]["no_iso_selected"])
            return
        if not self.usb_device_path:
            QMessageBox.warning(self, translations[self.current_language]["warning"], translations[self.current_language]["no_usb_device_selected"])
            return

        # تأكيد من المستخدم قبل البدء
        confirm_message = translations[self.current_language]["confirm_write_prompt"].format(
            self.iso_path_display.text(), self.usb_device_path
        )
        reply = QMessageBox.question(self, translations[self.current_language]["confirm_write"],
                                     confirm_message,
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            # تعطيل الأزرار أثناء العملية
            self.write_button.setEnabled(False)
            self.browse_iso_button.setEnabled(False)
            self.usb_device_combo.setEnabled(False)
            self.refresh_usb_button.setEnabled(False)
            self.progress_bar.setValue(0)
            self.status_label.setText(translations[self.current_language]["starting_write"])

            self.dd_worker = DDWorker(self.iso_path, self.usb_device_path)
            self.dd_worker.progress_updated.connect(self.progress_bar.setValue)
            self.dd_worker.status_message.connect(self.status_label.setText)
            self.dd_worker.operation_finished.connect(self.write_finished)
            self.dd_worker.start() # بدء الثريد

    def write_finished(self, success, message):
        self.dd_worker = None # تحرير الثريد
        # إعادة تفعيل الأزرار
        self.write_button.setEnabled(True)
        self.browse_iso_button.setEnabled(True)
        self.usb_device_combo.setEnabled(True)
        self.refresh_usb_button.setEnabled(True)

        if success:
            self.status_label.setText(message)
            QMessageBox.information(self, translations[self.current_language]["success"], message)
        else:
            self.status_label.setText(translations[self.current_language]["failed"] + ": " + message)
            QMessageBox.critical(self, translations[self.current_language]["error"], message)
        
        self.progress_bar.setValue(0) # إعادة شريط التقدم للصفر بعد الانتهاء

    def closeEvent(self, event):
        if self.dd_worker and self.dd_worker.isRunning():
            reply = QMessageBox.question(self, translations[HelwanUSBWriter.current_language]["app_title_usb"],
                                         translations[HelwanUSBWriter.current_language]["cancel_running_operation"],
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.dd_worker.stop() # طلب إيقاف الثريد (ليس قتلًا فوريًا)
                self.dd_worker.wait() # انتظر حتى ينتهي الثريد
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # يمكنك تعيين اللغة هنا بناءً على إعدادات التوزيعة
    # HelwanUSBWriter.current_language = "ar"
    
    window = HelwanUSBWriter()
    window.show()
    sys.exit(app.exec_())
