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
    QMainWindow, QLineEdit, QAction, QFormLayout, QCheckBox
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread, QTimer

# استيراد قاموس الترجمات
from translations import translations

# --- Worker Thread for DD Command ---
class DDWorker(QThread):
    progress_updated = pyqtSignal(int)
    status_message = pyqtSignal(str)
    operation_finished = pyqtSignal(bool, str)
    current_action = pyqtSignal(str) # للإشارة إلى الخطوة الحالية (كتابة، تحقق، تهيئة)

    def __init__(self, iso_path, usb_device_path, iso_size, format_usb_full, parent=None):
        super().__init__(parent)
        self.iso_path = iso_path
        self.usb_device_path = usb_device_path
        self.iso_size = iso_size
        self.format_usb_full = format_usb_full
        self._is_running = True
        self.process = None

    def run(self):
        try:
            # 1. Formatting USB if requested
            if self.format_usb_full:
                self.current_action.emit(translations[HelwanUSBWriter.current_language]["action_formatting"])
                self.status_message.emit(translations[HelwanUSBWriter.current_language]["formatting_usb"].format(self.usb_device_path))
                self.progress_updated.emit(0)

                try:
                    # Unmount any mounted partitions of the USB device
                    self._unmount_usb_partitions(self.usb_device_path)
                    
                    # Wipe file system signatures (wipefs)
                    wipefs_cmd = ['sudo', 'wipefs', '--all', '--force', self.usb_device_path]
                    subprocess.run(wipefs_cmd, check=True, capture_output=True)

                    # Create a new GPT partition table (parted)
                    parted_mklabel_cmd = ['sudo', 'parted', '-s', self.usb_device_path, 'mklabel', 'gpt']
                    subprocess.run(parted_mklabel_cmd, check=True, capture_output=True)
                    
                    # Create a new partition (parted) - example: fat32
                    # Note: For booting ISOs, partitioning might interfere depending on ISO.
                    # Best practice for DD is to wipe, then DD directly to device, not partition.
                    # However, if creating a blank FAT32 for other uses, this is fine.
                    # For ISO writing, simply wiping is enough. We'll skip mkfs after wiping for direct DD.
                    # parted_mkpart_cmd = ['sudo', 'parted', '-s', '-a', 'opt', self.usb_device_path, 'mkpart', 'primary', 'fat32', '0%', '100%']
                    # subprocess.run(parted_mkpart_cmd, check=True, capture_output=True)

                    # Sleep briefly to allow kernel to recognize changes
                    time.sleep(2)

                    self.status_message.emit(translations[HelwanUSBWriter.current_language]["usb_formatted_success"])
                    self.progress_updated.emit(10) # Small progress for formatting
                except subprocess.CalledProcessError as e:
                    self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["format_failed"].format(e.stderr.strip()))
                    return
                except Exception as e:
                    self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["format_failed_unexpected"].format(str(e)))
                    return

            # 2. Writing ISO
            self.current_action.emit(translations[HelwanUSBWriter.current_language]["action_writing"])
            self.status_message.emit(translations[HelwanUSBWriter.current_language]["preparing_to_write"].format(self.usb_device_path))
            self.progress_updated.emit(0)

            # تفريغ المخازن المؤقتة للجهاز قبل الكتابة
            subprocess.run(['sudo', 'sync'], check=True, capture_output=True)

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
                
                # تحديث رسالة الحالة من إخراج dd
                if "bytes (" in line and ") copied," in line:
                    try:
                        # Extract bytes written from dd status output
                        parts = line.split('bytes (')
                        if len(parts) > 1:
                            bytes_str = parts[0].strip()
                            if bytes_str.isdigit():
                                bytes_written = int(bytes_str)
                                if self.iso_size > 0:
                                    progress = int((bytes_written / self.iso_size) * 100)
                                    self.progress_updated.emit(progress)
                                    self.status_message.emit(translations[HelwanUSBWriter.current_language]["writing_progress"].format(
                                        HelwanUSBWriter._format_size(bytes_written),
                                        HelwanUSBWriter._format_size(self.iso_size),
                                        progress
                                    ))
                                else:
                                    self.progress_updated.emit(0)
                                    self.status_message.emit(line.strip())
                        
                    except ValueError:
                        self.status_message.emit(line.strip())
                else:
                    self.status_message.emit(line.strip())


            self.process.wait()
            stdout, stderr = self.process.communicate()

            if self.process.returncode != 0:
                error_message = stderr.strip() if stderr else translations[HelwanUSBWriter.current_language]["unknown_error"]
                self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["write_failed"].format(error_message))
                return

            self.progress_updated.emit(100)
            subprocess.run(['sudo', 'sync'], check=True, capture_output=True) # Final sync

            # 3. Verify SHA256 after writing
            self.current_action.emit(translations[HelwanUSBWriter.current_language]["action_verifying"])
            self.status_message.emit(translations[HelwanUSBWriter.current_language]["verifying_sha256_post_write"])
            self.progress_updated.emit(0)

            # Get the original ISO SHA256 hash
            original_iso_hash_result = subprocess.run(
                ['sha256sum', self.iso_path],
                capture_output=True, text=True, check=True
            )
            original_iso_sha256 = original_iso_hash_result.stdout.split(' ')[0].strip()

            # Calculate SHA256 of the written USB device
            calculated_usb_sha256 = self._calculate_device_sha256(self.usb_device_path, self.iso_size)

            if calculated_usb_sha256 == original_iso_sha256:
                self.operation_finished.emit(True, translations[HelwanUSBWriter.current_language]["write_and_verify_successful"])
            else:
                self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["write_successful_verify_failed"].format(
                    original_iso_sha256, calculated_usb_sha256
                ))

        except FileNotFoundError as e:
            if "dd" in str(e) or "wipefs" in str(e) or "parted" in str(e) or "mkfs" in str(e) or "sha256sum" in str(e):
                self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["command_not_found"].format(str(e).split("'")[1]))
            else:
                self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["unexpected_error"].format(str(e)))
        except subprocess.CalledProcessError as e:
            self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["subprocess_error"].format(e.cmd, e.returncode, e.stderr))
        except Exception as e:
            self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["unexpected_error"].format(str(e)))
        finally:
            self.process = None

    def _unmount_usb_partitions(self, device_path):
        # Dismount any mounted partitions on the USB device
        try:
            cmd = ['lsblk', '-J', '-o', 'NAME,MOUNTPOINT', device_path]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            
            # Find children (partitions) of the device
            device_info = next((bd for bd in data.get('blockdevices', []) if f"/dev/{bd['name']}" == device_path), None)
            
            if device_info and 'children' in device_info:
                for child in device_info['children']:
                    if child.get('mountpoint'):
                        mount_point = child['mountpoint']
                        self.status_message.emit(translations[HelwanUSBWriter.current_language]["unmounting_partition"].format(mount_point))
                        subprocess.run(['sudo', 'umount', mount_point], check=True, capture_output=True)
                        time.sleep(1) # Give system a moment

        except subprocess.CalledProcessError as e:
            self.status_message.emit(translations[HelwanUSBWriter.current_language]["unmount_error"].format(e.stderr.strip()))
            # Don't fail the whole operation, just log/report umount issue
        except json.JSONDecodeError:
            self.status_message.emit(translations[HelwanUSBWriter.current_language]["lsblk_parse_error"])
        except Exception as e:
            self.status_message.emit(translations[HelwanUSBWriter.current_language]["unmount_unexpected_error"].format(str(e)))

    def _calculate_device_sha256(self, device_path, size_to_read):
        """Calculates SHA256 of the specified device, reading only up to size_to_read bytes."""
        sha256_hash = hashlib.sha256()
        bytes_read = 0
        block_size = 4096 # Read in 4KB blocks

        try:
            # Use dd to read from the device, limiting the size
            command = ['sudo', 'dd', f'if={device_path}', f'bs={block_size}', f'count={size_to_read // block_size + (1 if size_to_read % block_size else 0)}']
            
            # Use Popen to get real-time progress for SHA256 calculation
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=block_size)

            while True:
                data = proc.stdout.read(block_size)
                if not data:
                    break
                sha256_hash.update(data)
                bytes_read += len(data)
                if self._is_running: # Check if operation is cancelled
                    progress = int((bytes_read / size_to_read) * 100)
                    self.progress_updated.emit(progress)
                    self.status_message.emit(translations[HelwanUSBWriter.current_language]["verifying_progress"].format(
                        HelwanUSBWriter._format_size(bytes_read),
                        HelwanUSBWriter._format_size(size_to_read),
                        progress
                    ))
                else:
                    break # Stop if cancelled

            proc.wait()
            if proc.returncode != 0:
                raise subprocess.CalledProcessError(proc.returncode, command, stderr=proc.stderr.read())

            return sha256_hash.hexdigest()

        except subprocess.CalledProcessError as e:
            self.status_message.emit(translations[HelwanUSBWriter.current_language]["read_usb_error"].format(e.stderr.strip()))
            return None
        except Exception as e:
            self.status_message.emit(translations[HelwanUSBWriter.current_language]["sha256_calc_device_error"].format(str(e)))
            return None

    def stop(self):
        self._is_running = False
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.status_message.emit(translations[HelwanUSBWriter.current_language]["operation_cancelled"])
        # If sha256 calculation is running
        if hasattr(self, 'proc') and self.proc and self.proc.poll() is None:
            self.proc.terminate()


# --- Main Application Window ---
class HelwanUSBWriter(QMainWindow):
    current_language = "en" # اللغة الافتراضية

    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.setWindowTitle(translations[self.current_language]["app_title_usb"])
        self.setWindowIcon(QIcon("icons/usb.png")) 

        self.iso_path = None
        self.usb_device_path = None
        self.iso_size = 0
        self.usb_device_size = 0 # حجم جهاز USB
        self.dd_worker = None

        self._create_widgets()
        self._create_layouts()
        self._connect_signals()
        self.refresh_usb_devices()

        self.setAcceptDrops(True) # تمكين سحب وإفلات الملفات
        self.resize(650, 500) # حجم أكبر قليلاً لاستيعاب المعلومات الإضافية وتخطيط أفضل

    def _create_widgets(self):
        self.iso_label = QLabel(translations[self.current_language]["selected_iso_file"])
        self.iso_path_display = QLineEdit()
        self.iso_path_display.setReadOnly(True)
        self.browse_iso_button = QPushButton(translations[self.current_language]["browse"])
        
        self.iso_info_label = QLabel(translations[self.current_language]["iso_details_placeholder"])
        self.iso_info_label.setWordWrap(True)

        self.sha256_label = QLabel(translations[self.current_language]["expected_sha256_label"])
        self.expected_sha256_input = QLineEdit()
        self.expected_sha256_input.setPlaceholderText(translations[self.current_language]["expected_sha256_placeholder"])
        self.calculate_iso_sha256_button = QPushButton(translations[self.current_language]["calculate_sha256"])
        self.calculate_iso_sha256_button.setEnabled(False)
        self.calculated_sha256_display = QLineEdit()
        self.calculated_sha256_display.setReadOnly(True)
        self.calculated_sha256_display.setPlaceholderText(translations[self.current_language]["calculated_sha256_placeholder"])
        self.sha256_status_label = QLabel("") # لعرض حالة التحقق

        self.usb_label = QLabel(translations[self.current_language]["select_usb_device"])
        self.usb_device_combo = QComboBox()
        self.refresh_usb_button = QPushButton(translations[self.current_language]["refresh"])
        
        self.usb_info_label = QLabel(translations[self.current_language]["usb_details_placeholder"])
        self.usb_info_label.setWordWrap(True)

        # خيار تهيئة كاملة
        self.format_usb_checkbox = QCheckBox(translations[self.current_language]["format_usb_full_option"])
        self.format_usb_checkbox.setStyleSheet("color: red; font-weight: bold;") # تمييز بصري للتحذير

        self.write_button = QPushButton(translations[self.current_language]["write_to_usb"])
        self.write_button.setEnabled(False)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.status_label = QLabel(translations[self.current_language]["ready_to_start"])
        self.status_label.setWordWrap(True)

        self.current_action_label = QLabel(translations[self.current_language]["current_action_idle"]) # لعرض الخطوة الحالية
        self.current_action_label.setStyleSheet("font-weight: bold; color: blue;")


    def _create_layouts(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        # قسم ملف ISO
        iso_selection_layout = QHBoxLayout()
        iso_selection_layout.addWidget(self.iso_path_display)
        iso_selection_layout.addWidget(self.browse_iso_button)
        
        main_layout.addWidget(self.iso_label)
        main_layout.addLayout(iso_selection_layout)
        main_layout.addWidget(self.iso_info_label)

        # قسم SHA256
        sha256_form_layout = QFormLayout()
        sha256_form_layout.addRow(self.sha256_label, self.expected_sha256_input)
        
        sha256_calc_layout = QHBoxLayout()
        sha256_calc_layout.addWidget(self.calculated_sha256_display)
        sha256_calc_layout.addWidget(self.calculate_iso_sha256_button)
        sha256_form_layout.addRow(translations[self.current_language]["calculated_sha256_label"], sha256_calc_layout)
        
        main_layout.addLayout(sha256_form_layout)
        main_layout.addWidget(self.sha256_status_label) # لعرض حالة التحقق

        # قسم USB
        usb_selection_layout = QHBoxLayout()
        usb_selection_layout.addWidget(self.usb_device_combo)
        usb_selection_layout.addWidget(self.refresh_usb_button)
        
        main_layout.addWidget(self.usb_label)
        main_layout.addLayout(usb_selection_layout)
        main_layout.addWidget(self.usb_info_label)
        main_layout.addWidget(self.format_usb_checkbox) # إضافة خيار التهيئة

        main_layout.addStretch(1)

        main_layout.addWidget(self.write_button)
        main_layout.addWidget(self.current_action_label) # عرض الخطوة الحالية
        main_layout.addWidget(self.progress_bar)
        main_layout.addWidget(self.status_label)

    def _connect_signals(self):
        self.browse_iso_button.clicked.connect(self.browse_iso_file)
        self.calculate_iso_sha256_button.clicked.connect(self.calculate_iso_sha256)
        self.usb_device_combo.currentIndexChanged.connect(self.select_usb_device)
        self.refresh_usb_button.clicked.connect(self.refresh_usb_devices)
        self.write_button.clicked.connect(self.start_write_process)
        self.expected_sha256_input.textChanged.connect(self._check_sha256_match)
        self.format_usb_checkbox.stateChanged.connect(self._handle_format_checkbox_state)


    def update_ui_state(self):
        is_iso_selected = self.iso_path is not None and self.iso_size > 0
        is_usb_selected = self.usb_device_path is not None and self.usb_device_size > 0 and \
                          self.usb_device_path != translations[self.current_language]["no_usb_selected_option"]

        # التحقق من مساحة USB كافية
        is_space_sufficient = False
        if is_iso_selected and is_usb_selected:
            if self.usb_device_size >= self.iso_size:
                is_space_sufficient = True
            else:
                self.status_label.setText(translations[self.current_language]["insufficient_usb_space"].format(
                    self._format_size(self.iso_size), self._format_size(self.usb_device_size)
                ))
        
        self.write_button.setEnabled(is_iso_selected and is_usb_selected and is_space_sufficient)
        self.calculate_iso_sha256_button.setEnabled(is_iso_selected)
        
        self._check_sha256_match() # تحديث حالة مطابقة SHA256

        # تحديث معلومات الـ USB إذا كان هناك جهاز محدد
        if is_usb_selected:
             index = self.usb_device_combo.currentIndex()
             selected_text = self.usb_device_combo.itemText(index)
             self.usb_info_label.setText(selected_text)
        else:
            self.usb_info_label.setText(translations[self.current_language]["usb_details_placeholder"])

    def _handle_format_checkbox_state(self, state):
        if state == Qt.Checked:
            reply = QMessageBox.warning(self, translations[self.current_language]["warning"],
                                        translations[self.current_language]["format_usb_warning"],
                                        QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.No:
                self.format_usb_checkbox.setChecked(False) # إلغاء التحديد إذا رفض المستخدم


    @staticmethod
    def _format_size(size_in_bytes):
        # دالة مساعدة لتحويل البايت إلى تنسيق مقروء (KB, MB, GB)
        if size_in_bytes is None:
            return "N/A"
        
        if size_in_bytes < 1024:
            return f"{size_in_bytes} B"
        elif size_in_bytes < 1024**2:
            return f"{size_in_bytes / 1024:.2f} KB"
        elif size_in_bytes < 1024**3:
            return f"{size_in_bytes / (1024**2):.2f} MB"
        else:
            return f"{size_in_bytes / (1024**3):.2f} GB"

    def browse_iso_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self,
                                                   translations[self.current_language]["open_iso_file"],
                                                   os.path.expanduser("~"),
                                                   "ISO Files (*.iso);;All Files (*)")
        self.load_iso_file(file_path)

    def load_iso_file(self, file_path):
        if file_path and os.path.exists(file_path) and os.path.isfile(file_path):
            self.iso_path = file_path
            self.iso_path_display.setText(os.path.basename(file_path))
            self.iso_size = os.path.getsize(self.iso_path)
            self.iso_info_label.setText(translations[self.current_language]["iso_details"].format(
                os.path.basename(self.iso_path), self._format_size(self.iso_size)
            ))
            self.calculated_sha256_display.clear()
            self.sha256_status_label.clear()
            self.update_ui_state()
        else:
            self.iso_path = None
            self.iso_path_display.clear()
            self.iso_size = 0
            self.iso_info_label.setText(translations[self.current_language]["iso_details_placeholder"])
            self.calculated_sha256_display.clear()
            self.sha256_status_label.clear()
            self.update_ui_state()

    def _check_sha256_match(self):
        expected_hash = self.expected_sha256_input.text().strip().lower()
        calculated_hash = self.calculated_sha256_display.text().strip().lower()

        if expected_hash and calculated_hash and expected_hash == calculated_hash:
            self.sha256_status_label.setText(translations[self.current_language]["sha256_match"])
            self.sha256_status_label.setStyleSheet("color: green;")
        elif expected_hash and calculated_hash and expected_hash != calculated_hash:
            self.sha256_status_label.setText(translations[self.current_language]["sha256_mismatch"])
            self.sha256_status_label.setStyleSheet("color: red;")
        else:
            self.sha256_status_label.clear()
            self.sha256_status_label.setStyleSheet("") # مسح التلوين

    def calculate_iso_sha256(self):
        if not self.iso_path:
            QMessageBox.warning(self, translations[self.current_language]["warning"], translations[self.current_language]["no_iso_selected_sha256"])
            return

        self.calculated_sha256_display.setText(translations[self.current_language]["calculating_sha256_short"])
        self.calculate_iso_sha256_button.setEnabled(False)
        self.sha256_status_label.setText(translations[self.current_language]["calculating_sha256_status"])
        self.sha256_status_label.setStyleSheet("color: orange;")
        
        self.sha_worker = SHA256Worker(self.iso_path, self.iso_size) # تمرير iso_size
        self.sha_worker.sha256_calculated.connect(self._display_sha256_result)
        self.sha_worker.sha256_progress.connect(self._update_sha256_progress) # لتحديث التقدم
        self.sha_worker.start()

    def _update_sha256_progress(self, progress):
        self.sha256_status_label.setText(translations[self.current_language]["calculating_progress"].format(progress))

    def _display_sha256_result(self, sha256_hash, error_message):
        if sha256_hash:
            self.calculated_sha256_display.setText(sha256_hash)
            self.status_label.setText(translations[self.current_language]["sha256_calculated_success"])
            self._check_sha256_match() # تحقق من التطابق بعد الحساب
        else:
            self.calculated_sha256_display.setText(translations[self.current_language]["sha256_calculation_failed"])
            self.sha256_status_label.setText(translations[self.current_language]["sha256_calculation_failed_status"])
            self.sha256_status_label.setStyleSheet("color: red;")
            QMessageBox.critical(self, translations[self.current_language]["error"], error_message)
        self.calculate_iso_sha256_button.setEnabled(True)

    def get_usb_devices(self):
        devices = []
        try:
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
                    
                    # Also check for removable property, to filter out internal disks that might be unmounted
                    if block_device.get('removable') is True and not is_mounted_disk_or_partition:
                        model = block_device.get('model', '').strip()
                        size_raw = block_device.get('size', '0B')
                        
                        # تحويل حجم lsblk إلى بايت لسهولة المقارنة
                        size_in_bytes = self._parse_lsblk_size_to_bytes(size_raw)

                        display_name = f"{device_name} ({self._format_size(size_in_bytes)})"
                        if model:
                            display_name += f" - {model}"
                        
                        devices.append((display_name, device_name, size_in_bytes))
        except FileNotFoundError:
            QMessageBox.critical(self, translations[self.current_language]["error"], translations[self.current_language]["lsblk_not_found"])
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, translations[self.current_language]["error"], translations[self.current_language]["subprocess_error"].format(e.cmd, e.returncode, e.stderr))
        except json.JSONDecodeError:
            QMessageBox.critical(self, translations[self.current_language]["error"], translations[self.current_language]["lsblk_parse_error"])
        except Exception as e:
            QMessageBox.critical(self.current_language, translations[self.current_language]["error"], translations[self.current_language]["unexpected_error"].format(str(e)))
        return devices

    def _parse_lsblk_size_to_bytes(self, size_str):
        size_str = size_str.strip().upper()
        if not size_str:
            return 0
        
        # وحدات القياس الشائعة من lsblk
        units = {
            'B': 1, 'K': 1024, 'KB': 1024,
            'M': 1024**2, 'MB': 1024**2,
            'G': 1024**3, 'GB': 1024**3,
            'T': 1024**4, 'TB': 1024**4
        }
        
        for unit, multiplier in units.items():
            if size_str.endswith(unit):
                try:
                    value = float(size_str[:-len(unit)])
                    return int(value * multiplier)
                except ValueError:
                    return 0
        return 0 # إذا لم يتم العثور على وحدة قياس معروفة

    def refresh_usb_devices(self):
        self.usb_device_combo.clear()
        
        self.usb_device_combo.addItem(translations[self.current_language]["select_usb_device_option"], (None, 0))
        self.usb_device_combo.addItem(translations[self.current_language]["no_usb_selected_option"], (None, 0))

        usb_devices = self.get_usb_devices()
        if not usb_devices:
            self.usb_device_combo.setItemText(0, translations[self.current_language]["no_usb_found"])
            self.usb_device_combo.setCurrentIndex(0)
        else:
            for display_name, path, size in usb_devices:
                self.usb_device_combo.addItem(display_name, (path, size))
            self.usb_device_combo.setCurrentIndex(0)
        
        self.usb_device_path = None
        self.usb_device_size = 0
        self.update_ui_state()

    def select_usb_device(self, index):
        selected_data = self.usb_device_combo.itemData(index)
        if selected_data:
            self.usb_device_path = selected_data[0]
            self.usb_device_size = selected_data[1]
        else:
            self.usb_device_path = None
            self.usb_device_size = 0
        
        self.update_ui_state()

    def start_write_process(self):
        if not self.iso_path:
            QMessageBox.warning(self, translations[self.current_language]["warning"], translations[self.current_language]["no_iso_selected"])
            return
        if not self.usb_device_path or self.usb_device_path == translations[self.current_language]["no_usb_selected_option"]:
            QMessageBox.warning(self, translations[self.current_language]["warning"], translations[self.current_language]["no_usb_device_selected"])
            return
        if self.iso_size == 0:
            QMessageBox.warning(self, translations[self.current_language]["warning"], translations[self.current_language]["iso_size_zero"])
            return
        if self.usb_device_size < self.iso_size:
             QMessageBox.critical(self, translations[self.current_language]["error"], translations[self.current_language]["insufficient_usb_space_critical"].format(
                 self._format_size(self.iso_size), self._format_size(self.usb_device_size)
             ))
             return

        # تحقق إضافي من مطابقة SHA256 إذا تم إدخال توقع
        expected_hash = self.expected_sha256_input.text().strip()
        calculated_hash = self.calculated_sha256_display.text().strip()
        if expected_hash and expected_hash.lower() != calculated_hash.lower():
            reply = QMessageBox.question(self, translations[self.current_language]["warning"],
                                         translations[self.current_language]["sha256_mismatch_proceed_prompt"],
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.No:
                return

        confirm_message = translations[self.current_language]["confirm_write_prompt"].format(
            os.path.basename(self.iso_path), self._format_size(self.iso_size), self.usb_device_path, self._format_size(self.usb_device_size)
        )
        if self.format_usb_checkbox.isChecked():
            confirm_message += "\n\n" + translations[self.current_language]["confirm_format_warning"]
        
        reply = QMessageBox.question(self, translations[self.current_language]["confirm_write"],
                                     confirm_message,
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.write_button.setEnabled(False)
            self.browse_iso_button.setEnabled(False)
            self.calculate_iso_sha256_button.setEnabled(False)
            self.usb_device_combo.setEnabled(False)
            self.refresh_usb_button.setEnabled(False)
            self.expected_sha256_input.setEnabled(False)
            self.format_usb_checkbox.setEnabled(False)

            self.progress_bar.setValue(0)
            self.status_label.setText(translations[self.current_language]["starting_write"])
            self.current_action_label.setText(translations[self.current_language]["current_action_idle"])


            self.dd_worker = DDWorker(self.iso_path, self.usb_device_path, self.iso_size, self.format_usb_checkbox.isChecked())
            self.dd_worker.progress_updated.connect(self.progress_bar.setValue)
            self.dd_worker.status_message.connect(self.status_label.setText)
            self.dd_worker.current_action.connect(self.current_action_label.setText) # تحديث الخطوة الحالية
            self.dd_worker.operation_finished.connect(self.write_finished)
            self.dd_worker.start()

    def write_finished(self, success, message):
        if self.dd_worker:
            self.dd_worker.wait()
            self.dd_worker = None
        
        self.write_button.setEnabled(True)
        self.browse_iso_button.setEnabled(True)
        self.calculate_iso_sha256_button.setEnabled(True)
        self.usb_device_combo.setEnabled(True)
        self.refresh_usb_button.setEnabled(True)
        self.expected_sha256_input.setEnabled(True)
        self.format_usb_checkbox.setEnabled(True)
        self.current_action_label.setText(translations[self.current_language]["current_action_idle"])


        if success:
            self.status_label.setText(message)
            QMessageBox.information(self, translations[self.current_language]["success"], message)
        else:
            self.status_label.setText(translations[self.current_language]["failed"] + ": " + message)
            QMessageBox.critical(self, translations[self.current_language]["error"], message)
        
        self.progress_bar.setValue(0)
        self.update_ui_state() # تحديث الحالة بعد انتهاء العملية

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

    # --- Drag and Drop functionality ---
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                file_path = url.toLocalFile()
                if os.path.isfile(file_path) and file_path.lower().endswith(".iso"):
                    self.load_iso_file(file_path)
                    event.acceptProposedAction()
                    return
            QMessageBox.warning(self, translations[self.current_language]["warning"], translations[self.current_language]["drop_invalid_file"])
            event.ignore()
        else:
            event.ignore()


# --- Worker Thread for SHA256 Calculation (for ISO file) ---
class SHA256Worker(QThread):
    sha256_calculated = pyqtSignal(str, str)
    sha256_progress = pyqtSignal(int)

    def __init__(self, file_path, file_size, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.file_size = file_size

    def run(self):
        try:
            sha256_hash = hashlib.sha256()
            bytes_read = 0
            with open(self.file_path, "rb") as f:
                while True:
                    byte_block = f.read(4096)
                    if not byte_block:
                        break
                    sha256_hash.update(byte_block)
                    bytes_read += len(byte_block)
                    if self.file_size > 0:
                        progress = int((bytes_read / self.file_size) * 100)
                        self.sha256_progress.emit(progress)
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
