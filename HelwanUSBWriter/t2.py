#!/usr/bin/env python3
import sys
import os
import subprocess
import threading
import time
import json
import hashlib

from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QFileDialog, QComboBox, QLabel, QProgressBar, QMessageBox,
    QMainWindow, QLineEdit, QAction
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread, QTimer

# استيراد قاموس الترجمات
from translations import translations # تأكد من أن هذا الملف موجود في نفس المجلد

# --- Worker Thread for DD Command ---
class DDWorker(QThread):
    progress_updated = pyqtSignal(int)
    status_message = pyqtSignal(str)
    operation_finished = pyqtSignal(bool, str)

    def __init__(self, iso_path, usb_device_path, iso_size, parent=None):
        super().__init__(parent)
        self.iso_path = iso_path
        self.usb_device_path = usb_device_path
        self.iso_size = iso_size
        self._is_running = True
        self.process = None

    def run(self):
        try:
            # استخدام HelwanUSBWriter.current_language للوصول إلى اللغة
            self.status_message.emit(translations[HelwanUSBWriter.current_language]["preparing_to_write"].format(self.usb_device_path))

            command = [
                'sudo', 'dd',
                f'if={self.iso_path}',
                f'of={self.usb_device_path}',
                'bs=4M',
                'status=progress',
                'conv=fsync'
            ]

            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            bytes_written = 0
            while self._is_running:
                line = self.process.stderr.readline()
                if not line:
                    break
                
                self.status_message.emit(line.strip())

                if "bytes (" in line and ") copied," in line:
                    try:
                        parts = line.split('bytes (')
                        if len(parts) > 1:
                            bytes_str = parts[0].strip()
                            if bytes_str.isdigit():
                                bytes_written = int(bytes_str)
                                if self.iso_size > 0:
                                    progress = int((bytes_written / self.iso_size) * 100)
                                    self.progress_updated.emit(progress)
                                else:
                                    self.progress_updated.emit(0)
                        
                    except ValueError:
                        pass

            self.process.wait()
            stdout, stderr = self.process.communicate()

            if self.process.returncode == 0:
                self.progress_updated.emit(100)
                self.operation_finished.emit(True, translations[HelwanUSBWriter.current_language]["write_successful"])
            else:
                error_message = stderr.strip() if stderr else translations[HelwanUSBWriter.current_language]["unknown_error"]
                self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["write_failed"].format(error_message))

        except FileNotFoundError:
            self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["dd_not_found"])
        except Exception as e:
            self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["unexpected_error"].format(str(e)))
        finally:
            self.process = None

    def stop(self):
        self._is_running = False
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.status_message.emit(translations[HelwanUSBWriter.current_language]["operation_cancelled"])


# --- Main Application Window ---
class HelwanUSBWriter(QMainWindow):
    # استخدام خاصية الفئة هنا لتكون متاحة لـ DDWorker و SHA256Worker
    current_language = "en" 

    def __init__(self, parent=None):
        super().__init__(parent)
        # لا تقم بتعيين self.current_language هنا إذا أردت استخدام خاصية الفئة
        # ولكن بما أنني أريدك أن تجرب هذا الكود، سأبقيها هنا مؤقتاً للتأكد
        # إذا استمرت المشكلة، يمكننا إزالتها والاعتماد فقط على HelwanUSBWriter.current_language
        self.current_language = HelwanUSBWriter.current_language # تأكد من أن المثيل يستخدم نفس اللغة
        
        self.setWindowTitle(translations[self.current_language]["app_title_usb"])
        self.setWindowIcon(QIcon("icons/usb.png"))

        self.iso_path = None
        self.usb_device_path = None
        self.iso_size = 0
        self.dd_worker = None

        self._create_widgets()
        self._create_layouts()
        self._connect_signals()
        self.refresh_usb_devices()

        self.resize(500, 350)

    def _create_widgets(self):
        self.iso_label = QLabel(translations[self.current_language]["select_iso_file"])
        self.iso_path_display = QLineEdit()
        self.iso_path_display.setReadOnly(True)
        self.browse_iso_button = QPushButton(translations[self.current_language]["browse"])
        
        self.sha256_button = QPushButton(translations[self.current_language]["calculate_sha256"])
        self.sha256_button.setEnabled(False)
        self.sha256_display = QLineEdit()
        self.sha256_display.setReadOnly(True)
        self.sha256_display.setPlaceholderText(translations[self.current_language]["sha256_placeholder"])

        self.usb_label = QLabel(translations[self.current_language]["select_usb_device"])
        self.usb_device_combo = QComboBox()
        self.refresh_usb_button = QPushButton(translations[self.current_language]["refresh"])

        self.write_button = QPushButton(translations[self.current_language]["write_to_usb"])
        self.write_button.setEnabled(False)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.status_label = QLabel(translations[self.current_language]["ready_to_start"])
        self.status_label.setWordWrap(True)

    def _create_layouts(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        iso_layout = QHBoxLayout()
        iso_layout.addWidget(self.iso_path_display)
        iso_layout.addWidget(self.browse_iso_button)
        main_layout.addWidget(self.iso_label)
        main_layout.addLayout(iso_layout)

        sha256_layout = QHBoxLayout()
        sha256_layout.addWidget(self.sha256_display)
        sha256_layout.addWidget(self.sha256_button)
        main_layout.addLayout(sha256_layout)

        usb_layout = QHBoxLayout()
        usb_layout.addWidget(self.usb_device_combo)
        usb_layout.addWidget(self.refresh_usb_button)
        main_layout.addWidget(self.usb_label)
        main_layout.addLayout(usb_layout)

        main_layout.addStretch(1)

        main_layout.addWidget(self.write_button)

        main_layout.addWidget(self.progress_bar)
        main_layout.addWidget(self.status_label)

    def _connect_signals(self):
        self.browse_iso_button.clicked.connect(self.browse_iso_file)
        self.sha256_button.clicked.connect(self.calculate_iso_sha256)
        self.usb_device_combo.currentIndexChanged.connect(self.select_usb_device)
        self.refresh_usb_button.clicked.connect(self.refresh_usb_devices)
        self.write_button.clicked.connect(self.start_write_process)

    def update_ui_state(self):
        is_ready = self.iso_path is not None and \
                   self.usb_device_path is not None and \
                   self.usb_device_path != translations[self.current_language]["no_usb_selected_option"] and \
                   self.iso_size > 0
        self.write_button.setEnabled(is_ready)
        self.sha256_button.setEnabled(self.iso_path is not None)

    def browse_iso_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self,
                                                   translations[self.current_language]["open_iso_file"],
                                                   os.path.expanduser("~"),
                                                   "ISO Files (*.iso);;All Files (*)")
        if file_path:
            self.iso_path = file_path
            self.iso_path_display.setText(os.path.basename(file_path))
            self.iso_size = os.path.getsize(self.iso_path)
            self.sha256_display.clear()
            self.update_ui_state()
        else:
            self.iso_path = None
            self.iso_path_display.clear()
            self.iso_size = 0
            self.update_ui_state()

    def calculate_iso_sha256(self):
        if not self.iso_path:
            QMessageBox.warning(self, translations[self.current_language]["warning"], translations[self.current_language]["no_iso_selected_sha256"])
            return

        self.sha256_display.setText(translations[self.current_language]["calculating_sha256"])
        self.sha256_button.setEnabled(False)
        
        self.sha_worker = SHA256Worker(self.iso_path)
        self.sha_worker.sha256_calculated.connect(self._display_sha256_result)
        self.sha_worker.start()

    def _display_sha256_result(self, sha256_hash, error_message):
        if sha256_hash:
            self.sha256_display.setText(sha256_hash)
            self.status_label.setText(translations[self.current_language]["sha256_calculated_success"])
        else:
            self.sha256_display.setText(translations[self.current_language]["sha256_calculation_failed"])
            QMessageBox.critical(self, translations[self.current_language]["error"], error_message)
        self.sha256_button.setEnabled(True)

    def get_usb_devices(self):
        devices = []
        try:
            # هذا الأمر خاص بلينكس ولن يعمل على ويندوز
            cmd = ['lsblk', '-J', '-o', 'NAME,SIZE,TYPE,MODEL,MOUNTPOINT']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)

            for block_device in data.get('blockdevices', []):
                if block_device.get('type') == 'disk':
                    device_name = f"/dev/{block_device['name']}"
                    
                    is_mounted_disk_or_partition = False
                    if block_device.get('mountpoint'):
                        is_mounted_disk_or_partition = True
                    elif 'children' in block_device:
                        for child in block_device['children']:
                            if child.get('mountpoint'):
                                is_mounted_disk_or_partition = True
                                break
                    
                    if not is_mounted_disk_or_partition:
                        model = block_device.get('model', '').strip()
                        display_name = f"{device_name} ({block_device.get('size', 'Unknown Size')})"
                        if model:
                            display_name += f" - {model}"
                        
                        devices.append((display_name, device_name))
        except FileNotFoundError:
            # سيظهر هذا الخطأ على ويندوز لأن lsblk غير موجود
            QMessageBox.critical(self, translations[self.current_language]["error"], translations[self.current_language]["lsblk_not_found"])
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, translations[self.current_language]["error"], f"Error running lsblk: {e.stderr}")
        except json.JSONDecodeError:
            QMessageBox.critical(self, translations[self.current_language]["error"], translations[self.current_language]["lsblk_parse_error"])
        except Exception as e:
            QMessageBox.critical(self.current_language, translations[self.current_language]["error"], f"An unexpected error occurred: {e}")
        return devices

    def refresh_usb_devices(self):
        self.usb_device_combo.clear()
        
        self.usb_device_combo.addItem(translations[self.current_language]["select_usb_device_option"], None)
        self.usb_device_combo.addItem(translations[self.current_language]["no_usb_selected_option"], None)

        usb_devices = self.get_usb_devices()
        if not usb_devices:
            self.usb_device_combo.setItemText(0, translations[self.current_language]["no_usb_found"])
            self.usb_device_combo.setCurrentIndex(0)
        else:
            for display_name, path in usb_devices:
                self.usb_device_combo.addItem(display_name, path)
            self.usb_device_combo.setCurrentIndex(0)
        
        self.usb_device_path = None
        self.update_ui_state()

    def select_usb_device(self, index):
        selected_data = self.usb_device_combo.itemData(index)
        if selected_data is not None:
            self.usb_device_path = selected_data
        else:
            self.usb_device_path = None
        self.update_ui_state()

    def start_write_process(self):
        if not self.iso_path:
            QMessageBox.warning(self, translations[self.current_language]["warning"], translations[self.current_language]["no_iso_selected"])
            return
        if not self.usb_device_path:
            QMessageBox.warning(self.current_language, translations[self.current_language]["warning"], translations[self.current_language]["no_usb_device_selected"])
            return
        if self.iso_size == 0:
            QMessageBox.warning(self, translations[self.current_language]["warning"], translations[self.current_language]["iso_size_zero"])
            return

        confirm_message = translations[self.current_language]["confirm_write_prompt"].format(
            os.path.basename(self.iso_path), self.usb_device_path
        )
        reply = QMessageBox.question(self, translations[self.current_language]["confirm_write"],
                                     confirm_message,
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.write_button.setEnabled(False)
            self.browse_iso_button.setEnabled(False)
            self.sha256_button.setEnabled(False)
            self.usb_device_combo.setEnabled(False)
            self.refresh_usb_button.setEnabled(False)
            self.progress_bar.setValue(0)
            self.status_label.setText(translations[self.current_language]["starting_write"])

            self.dd_worker = DDWorker(self.iso_path, self.usb_device_path, self.iso_size)
            self.dd_worker.progress_updated.connect(self.progress_bar.setValue)
            self.dd_worker.status_message.connect(self.status_label.setText)
            self.dd_worker.operation_finished.connect(self.write_finished)
            self.dd_worker.start()

    def write_finished(self, success, message):
        if self.dd_worker:
            self.dd_worker.wait()
            self.dd_worker = None
        
        self.write_button.setEnabled(True)
        self.browse_iso_button.setEnabled(True)
        self.sha256_button.setEnabled(True)
        self.usb_device_combo.setEnabled(True)
        self.refresh_usb_button.setEnabled(True)

        if success:
            self.status_label.setText(message)
            QMessageBox.information(self, translations[self.current_language]["success"], message)
        else:
            self.status_label.setText(translations[self.current_language]["failed"] + ": " + message)
            QMessageBox.critical(self, translations[self.current_language]["error"], message)
        
        self.progress_bar.setValue(0)

    def closeEvent(self, event):
        if self.dd_worker and self.dd_worker.isRunning():
            reply = QMessageBox.question(self, translations[self.current_language]["app_title_usb"],
                                         translations[self.current_language]["cancel_running_operation"],
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.dd_worker.stop()
                self.dd_worker.wait()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

# --- Worker Thread for SHA256 Calculation ---
class SHA256Worker(QThread):
    sha256_calculated = pyqtSignal(str, str)

    def __init__(self, file_path, parent=None):
        super().__init__(parent)
        self.file_path = file_path

    def run(self):
        try:
            sha256_hash = hashlib.sha256()
            with open(self.file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            self.sha256_calculated.emit(sha256_hash.hexdigest(), "")
        except FileNotFoundError:
            self.sha256_calculated.emit("", translations[HelwanUSBWriter.current_language]["iso_not_found_sha256"])
        except Exception as e:
            self.sha256_calculated.emit("", translations[HelwanUSBWriter.current_language]["sha256_calc_error"].format(str(e)))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    window = HelwanUSBWriter()
    window.show()
    sys.exit(app.exec_())
