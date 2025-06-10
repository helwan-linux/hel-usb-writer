#!/usr/bin/env python3
import sys
import os
import subprocess
import threading
import hashlib
import time
import shutil

from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QComboBox, QFileDialog, QLineEdit, QMessageBox, QCheckBox, QProgressBar
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread

from translations import translations # Import translations dictionary

class Worker(QThread):
    progress_updated = pyqtSignal(int, str)
    operation_finished = pyqtSignal(bool, str, str) # success, message, type (write/format/sha_iso/sha_usb)
    sha_calculated = pyqtSignal(str, str) # sha_value, type (iso/usb)
    error_occurred = pyqtSignal(str)

    def __init__(self, operation_type, iso_path=None, usb_device=None, full_format=False):
        super().__init__()
        self.operation_type = operation_type
        self.iso_path = iso_path
        self.usb_device = usb_device
        self.full_format = full_format
        self._is_cancelled = False

    def run(self):
        try:
            if self.operation_type == "write":
                self._write_iso()
            elif self.operation_type == "format":
                self._format_usb()
            elif self.operation_type == "calculate_sha_iso":
                self._calculate_sha_iso()
            elif self.operation_type == "calculate_sha_usb":
                self._calculate_sha_usb()
        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            self.operation_finished.emit(False, "", self.operation_type) # Ensure signal is always emitted if not already

    def cancel(self):
        self._is_cancelled = True
        # For dd, it might be possible to send a signal, but a simple kill is safer.
        # However, for safe shutdown, rely on thread termination.

    def _execute_command(self, command, shell=False, check_return=True, custom_error_msg="", timeout=None):
        process = None
        try:
            # Use preexec_fn to set a new process group on Linux to kill children
            preexec_fn = None
            if sys.platform.startswith('linux'):
                preexec_fn = os.setsid

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=shell,
                preexec_fn=preexec_fn
            )

            stdout, stderr = process.communicate(timeout=timeout)
            if check_return and process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, command, stdout=stdout, stderr=stderr)
            return stdout, stderr
        except subprocess.CalledProcessError as e:
            error_msg = custom_error_msg if custom_error_msg else translations[HelwanUSBWriter.current_language]["subprocess_error"].format(e.cmd, e.returncode, e.stderr.strip())
            self.operation_finished.emit(False, error_msg, self.operation_type)
            raise
        except FileNotFoundError:
            command_name = command[0] if isinstance(command, list) else command.split(' ')[0]
            error_msg = translations[HelwanUSBWriter.current_language]["command_not_found"].format(command_name)
            self.operation_finished.emit(False, error_msg, self.operation_type)
            raise
        except subprocess.TimeoutExpired:
            if process:
                # Use os.killpg for robust termination of process group on Linux
                if sys.platform.startswith('linux') and preexec_fn:
                    os.killpg(os.getpgid(process.pid), 9) # SIGKILL
                else:
                    process.kill()
                process.wait()
            error_msg = translations[HelwanUSBWriter.current_language]["subprocess_error"].format(command, "Timeout", "Operation timed out")
            self.operation_finished.emit(False, error_msg, self.operation_type)
            raise
        except Exception as e:
            error_msg = translations[HelwanUSBWriter.current_language]["unexpected_error"].format(str(e))
            self.operation_finished.emit(False, error_msg, self.operation_type)
            raise

    def _unmount_partitions(self, device_path):
        if not sys.platform.startswith('linux'):
            # On Windows, PyQt should handle this via diskpart or similar, but our dd is Linux-centric.
            # We're specifically targeting Linux here for dd operations.
            return True

        try:
            # Get partitions of the device
            stdout, _ = self._execute_command(["lsblk", "-n", "-p", "-o", "NAME", device_path], custom_error_msg="Failed to list partitions.")
            partitions = stdout.strip().split('\n')
            partitions = [p for p in partitions if p.startswith(device_path) and p != device_path]

            if not partitions:
                return True # No partitions to unmount

            for part in partitions:
                self.progress_updated.emit(0, translations[HelwanUSBWriter.current_language]["unmounting_partition"].format(part))
                try:
                    self._execute_command(["sudo", "umount", part], check_return=False, custom_error_msg=translations[HelwanUSBWriter.current_language]["unmount_error"].format(part))
                    # Check if unmount was successful (sometimes umount returns 0 even if it didn't unmount all)
                    # We can try to remount and catch failure, or just move on. For this purpose, assuming umount does its best.
                except subprocess.CalledProcessError as e:
                    # Log or handle specific unmount errors, but try to continue
                    self.error_occurred.emit(translations[HelwanUSBWriter.current_language]["unmount_error"].format(part) + f": {e.stderr.strip()}")
                except Exception as e:
                    self.error_occurred.emit(translations[HelwanUSBWriter.current_language]["unmount_unexpected_error"].format(str(e)))
                    # Non-critical for overall operation if a single unmount fails
            return True
        except Exception as e:
            self.operation_finished.emit(False, f"Error during unmount preparation: {str(e)}", self.operation_type)
            return False

    def _format_usb(self):
        if not sys.platform.startswith('linux'):
            self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["format_failed"].format("Unsupported OS for full format."), "format")
            return

        usb_device = self.usb_device
        self.progress_updated.emit(0, translations[HelwanUSBWriter.current_language]["action_formatting"])

        if not self._unmount_partitions(usb_device):
            return # Unmount failed, operation stopped

        try:
            # Step 1: Wipe filesystem signatures (critical for clean slate)
            self.progress_updated.emit(0, translations[HelwanUSBWriter.current_language]["formatting_usb"].format(usb_device))
            self._execute_command(["sudo", "wipefs", "--all", "--force", usb_device], custom_error_msg="Failed to wipe USB device signatures.")

            # Step 2: Create a new partition table (e.g., MBR/msdos)
            # This will erase all existing partitions
            self._execute_command(["sudo", "parted", "-s", usb_device, "mklabel", "msdos"], custom_error_msg="Failed to create new partition table.")

            # Step 3: Create a single FAT32 partition spanning the entire device
            # This is a common requirement for bootable USBs, though not strictly for ISO writing with dd.
            # For a clean slate, a single partition is good.
            # Get device size for partition creation
            stdout, _ = self._execute_command(["lsblk", "-b", "-n", "-d", "-o", "SIZE", usb_device], custom_error_msg="Failed to get USB device size.")
            device_size_bytes = int(stdout.strip())
            # parted works with human readable or percentages. Using '0%' '100%' for simplicity.
            self._execute_command(["sudo", "parted", "-s", usb_device, "mkpart", "primary", "fat32", "0%", "100%"], custom_error_msg="Failed to create new FAT32 partition.")

            # Step 4: Format the newly created partition (assuming it's usb_device + 1 or similar)
            # Find the new partition name
            stdout, _ = self._execute_command(["lsblk", "-n", "-p", "-o", "NAME", usb_device], custom_error_msg="Failed to find new partition name.")
            # Filter for partitions directly on the device
            new_partitions = [p for p in stdout.strip().split('\n') if p.startswith(usb_device) and p != usb_device]

            if not new_partitions:
                raise Exception("Failed to find newly created partition for formatting.")

            # Assuming the first new partition is the one we just created
            target_partition = new_partitions[0]
            self.progress_updated.emit(0, f"{translations[HelwanUSBWriter.current_language]['formatting_usb'].format(target_partition)} (FAT32)...")
            self._execute_command(["sudo", "mkfs.fat", "-F", "32", target_partition], custom_error_msg="Failed to format new partition to FAT32.")

            self.operation_finished.emit(True, translations[HelwanUSBWriter.current_language]["usb_formatted_success"], "format")

        except subprocess.CalledProcessError as e:
            error_msg = translations[HelwanUSBWriter.current_language]["format_failed"].format(e.stderr.strip())
            self.operation_finished.emit(False, error_msg, "format")
        except Exception as e:
            error_msg = translations[HelwanUSBWriter.current_language]["format_failed_unexpected"].format(str(e))
            self.operation_finished.emit(False, error_msg, "format")

    def _write_iso(self):
        if not sys.platform.startswith('linux'):
            self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["write_failed"].format("Unsupported OS for writing."), "write")
            return

        iso_path = self.iso_path
        usb_device = self.usb_device
        self.progress_updated.emit(0, translations[HelwanUSBWriter.current_language]["action_writing"])

        if not self._unmount_partitions(usb_device):
            return # Unmount failed, operation stopped

        try:
            iso_size = os.path.getsize(iso_path)
            # Use 'bs=4M' for better performance, and 'status=progress' for dd to show progress
            command = ["sudo", "dd", f"if={iso_path}", f"of={usb_device}", "bs=4M", "status=progress"]
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid # For Linux, to kill all child processes on terminate
            )

            # Monitor stderr for progress updates from dd
            written_bytes = 0
            while True:
                line = process.stderr.readline()
                if not line:
                    break
                if self._is_cancelled:
                    os.killpg(os.getpgid(process.pid), 9) # SIGKILL
                    self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["operation_cancelled"], "write")
                    return

                # dd progress line example: "123456789 bytes (123 MB, 117 MiB) copied, 10.123 s, 12.3 MB/s"
                if "bytes" in line and "(" in line and "copied" in line:
                    parts = line.split("bytes")[0].strip().split()
                    if parts:
                        try:
                            written_bytes = int(parts[0])
                            progress_percent = int((written_bytes / iso_size) * 100)
                            self.progress_updated.emit(
                                progress_percent,
                                translations[HelwanUSBWriter.current_language]["writing_progress"].format(
                                    self._bytes_to_human_readable(written_bytes),
                                    self._bytes_to_human_readable(iso_size),
                                    progress_percent
                                )
                            )
                        except ValueError:
                            pass # Ignore lines that don't parse as progress

            process.wait()
            if process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, command, stdout=process.stdout.read(), stderr=process.stderr.read())

            self.operation_finished.emit(True, translations[HelwanUSBWriter.current_language]["write_successful"], "write")

        except subprocess.CalledProcessError as e:
            error_msg = translations[HelwanUSBWriter.current_language]["write_failed"].format(e.stderr.strip())
            self.operation_finished.emit(False, error_msg, "write")
        except FileNotFoundError:
            self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["dd_not_found"], "write")
        except Exception as e:
            self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["unexpected_error"].format(str(e)), "write")


    def _calculate_sha_iso(self):
        if not self.iso_path or not os.path.exists(self.iso_path):
            self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["iso_not_found_sha256"], "sha_iso")
            return

        self.progress_updated.emit(0, translations[HelwanUSBWriter.current_language]["action_verifying"])

        try:
            hasher = hashlib.sha256()
            file_size = os.path.getsize(self.iso_path)
            read_bytes = 0
            with open(self.iso_path, 'rb') as f:
                while True:
                    chunk = f.read(4096) # Read in 4KB chunks
                    if not chunk:
                        break
                    if self._is_cancelled:
                        self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["operation_cancelled"], "sha_iso")
                        return
                    hasher.update(chunk)
                    read_bytes += len(chunk)
                    progress = int((read_bytes / file_size) * 100)
                    self.progress_updated.emit(progress, translations[HelwanUSBWriter.current_language]["calculating_progress"].format(progress))
            self.sha_calculated.emit(hasher.hexdigest(), "iso")
            self.operation_finished.emit(True, translations[HelwanUSBWriter.current_language]["sha256_calculated_success"], "sha_iso")
        except Exception as e:
            self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["sha256_calc_error"].format(str(e)), "sha_iso")


    def _calculate_sha_usb(self):
        if not sys.platform.startswith('linux'):
            self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["sha256_calc_device_error"].format("Unsupported OS"), "sha_usb")
            return

        if not self.usb_device:
            self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["no_usb_device_selected"], "sha_usb")
            return

        self.progress_updated.emit(0, translations[HelwanUSBWriter.current_language]["action_verifying"])

        try:
            # Use dd to read from the device and pipe to sha256sum
            # We need to know the size of the written ISO to read exactly that much.
            # If we don't know, we'll read the whole device.
            # For post-write verification, we should compare against the original ISO's SHA256.
            # So, read only the size of the ISO that was written.
            iso_size_bytes = os.path.getsize(self.iso_path) if self.iso_path and os.path.exists(self.iso_path) else None

            if not iso_size_bytes:
                self.operation_finished.emit(False, "ISO size not available for USB SHA256 calculation.", "sha_usb")
                return

            command = ["sudo", "dd", f"if={self.usb_device}", f"bs=4M", f"count={iso_size_bytes // (4 * 1024 * 1024)}"]
            # Add remaining bytes as a separate smaller count to ensure exact size if not multiple of 4M
            remaining_bytes = iso_size_bytes % (4 * 1024 * 1024)
            if remaining_bytes > 0:
                command += ["&&", "sudo", "dd", f"if={self.usb_device}", f"bs=1", f"skip={iso_size_bytes - remaining_bytes}", f"count={remaining_bytes}"]

            # Pipe dd output to sha256sum
            dd_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
            sha_process = subprocess.Popen(["sha256sum"], stdin=dd_process.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            dd_process.stdout.close() # Allow dd_process to receive SIGPIPE

            # Monitor progress from dd's stderr
            read_bytes = 0
            while True:
                line = dd_process.stderr.readline()
                if not line:
                    break
                if self._is_cancelled:
                    os.killpg(os.getpgid(dd_process.pid), 9) # SIGKILL
                    if sha_process.poll() is None: sha_process.kill()
                    self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["operation_cancelled"], "sha_usb")
                    return

                if "bytes" in line and "copied" in line:
                    parts = line.split("bytes")[0].strip().split()
                    if parts:
                        try:
                            read_bytes = int(parts[0])
                            progress_percent = int((read_bytes / iso_size_bytes) * 100)
                            self.progress_updated.emit(
                                progress_percent,
                                translations[HelwanUSBWriter.current_language]["verifying_progress"].format(
                                    self._bytes_to_human_readable(read_bytes),
                                    self._bytes_to_human_readable(iso_size_bytes),
                                    progress_percent
                                )
                            )
                        except ValueError:
                            pass # Ignore lines that don't parse as progress

            dd_process.wait()
            sha_output, sha_error = sha_process.communicate()

            if dd_process.returncode != 0:
                raise subprocess.CalledProcessError(dd_process.returncode, command, stdout=dd_process.stdout.read(), stderr=dd_process.stderr.read())
            if sha_process.returncode != 0:
                raise subprocess.CalledProcessError(sha_process.returncode, "sha256sum", stdout=sha_output, stderr=sha_error)

            calculated_sha = sha_output.split(' ')[0]
            self.sha_calculated.emit(calculated_sha, "usb")
            self.operation_finished.emit(True, translations[HelwanUSBWriter.current_language]["sha256_calculated_success"], "sha_usb")

        except subprocess.CalledProcessError as e:
            error_msg = translations[HelwanUSBWriter.current_language]["sha256_calc_device_error"].format(e.stderr.strip())
            self.operation_finished.emit(False, error_msg, "sha_usb")
        except FileNotFoundError:
            self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["read_usb_error"].format("dd or sha256sum not found."), "sha_usb")
        except Exception as e:
            self.operation_finished.emit(False, translations[HelwanUSBWriter.current_language]["unexpected_error"].format(str(e)), "sha_usb")


    def _bytes_to_human_readable(self, num_bytes):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if num_bytes < 1024.0:
                return f"{num_bytes:.2f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.2f} PB"


class HelwanUSBWriter(QWidget):
    def __init__(self):
        super().__init__()
        self.current_language = "ar" # Default language
        self.iso_path = None
        self.usb_devices = {} # {description: path}
        self.selected_usb_device_path = None
        self.worker_thread = None
        self.is_operation_in_progress = False

        self.setWindowIcon(QIcon("icons/halwanmark.png")) # Make sure 'icons' folder and 'halwanmark.png' exist
        self.setWindowTitle(translations[self.current_language]["app_title_usb"])
        self.setGeometry(100, 100, 800, 600)

        self._create_widgets()
        self._create_layouts()
        self._connect_signals()
        self._detect_usb_devices()

    def _create_widgets(self):
        # Language selection
        self.language_combo = QComboBox()
        self.language_combo.addItem("English", "en")
        self.language_combo.addItem("العربية", "ar")
        self.language_combo.setCurrentText("العربية") # Set default to Arabic visually
        self.language_combo.currentIndexChanged.connect(self._change_language)

        # ISO Selection
        self.iso_label = QLabel(translations[self.current_language]["selected_iso_file"])
        self.iso_path_display = QLineEdit(translations[self.current_language]["iso_details_placeholder"])
        self.iso_path_display.setReadOnly(True)
        self.browse_iso_button = QPushButton(translations[self.current_language]["browse"])
        self.browse_iso_button.setFixedSize(100, 30)

        # SHA256 Calculation for ISO
        self.calculate_sha256_button = QPushButton(translations[self.current_language]["calculate_sha256"])
        self.expected_sha256_label = QLabel(translations[self.current_language]["expected_sha256_label"])
        self.expected_sha256_input = QLineEdit()
        self.expected_sha256_input.setPlaceholderText(translations[self.current_language]["expected_sha256_placeholder"])
        self.calculated_sha256_label = QLabel(translations[self.current_language]["calculated_sha256_label"])
        self.calculated_sha256_display = QLineEdit(translations[self.current_language]["calculated_sha256_placeholder"])
        self.calculated_sha256_display.setReadOnly(True)

        # USB Device Selection
        self.usb_label = QLabel(translations[self.current_language]["select_usb_device"])
        self.usb_combo = QComboBox()
        self.usb_combo.setPlaceholderText(translations[self.current_language]["select_usb_device_option"])
        self.usb_refresh_button = QPushButton(translations[self.current_language]["refresh"])
        self.usb_refresh_button.setFixedSize(100, 30)
        self.usb_details_display = QLineEdit(translations[self.current_language]["usb_details_placeholder"])
        self.usb_details_display.setReadOnly(True)

        # Full Format Option
        self.full_format_checkbox = QCheckBox(translations[self.current_language]["format_usb_full_option"])

        # Write Button
        self.write_button = QPushButton(translations[self.current_language]["write_to_usb"])
        self.write_button.setFixedSize(150, 40)
        self.write_button.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        self.write_button.setEnabled(False) # Disabled until ISO and USB selected

        # Status and Progress
        self.status_label = QLabel(translations[self.current_language]["ready_to_start"])
        self.status_label.setStyleSheet("font-weight: bold;")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)

        # Current Action Label (to display what's happening)
        self.current_action_label = QLabel(translations[self.current_language]["action_idle"]) # لعرض الخطوة الحالية
        self.current_action_label.setStyleSheet("font-weight: bold; color: blue;")


    def _create_layouts(self):
        main_layout = QVBoxLayout()

        # Language selection layout
        lang_layout = QHBoxLayout()
        lang_layout.addStretch()
        lang_layout.addWidget(self.language_combo)
        main_layout.addLayout(lang_layout)

        # ISO selection layout
        iso_layout = QHBoxLayout()
        iso_layout.addWidget(self.iso_label)
        iso_layout.addWidget(self.iso_path_display)
        iso_layout.addWidget(self.browse_iso_button)
        main_layout.addLayout(iso_layout)

        # SHA256 layout
        sha_input_layout = QHBoxLayout()
        sha_input_layout.addWidget(self.expected_sha256_label)
        sha_input_layout.addWidget(self.expected_sha256_input)
        sha_input_layout.addWidget(self.calculate_sha256_button)
        main_layout.addLayout(sha_input_layout)

        sha_display_layout = QHBoxLayout()
        sha_display_layout.addWidget(self.calculated_sha256_label)
        sha_display_layout.addWidget(self.calculated_sha256_display)
        main_layout.addLayout(sha_display_layout)

        main_layout.addSpacing(20)

        # USB selection layout
        usb_layout = QHBoxLayout()
        usb_layout.addWidget(self.usb_label)
        usb_layout.addWidget(self.usb_combo)
        usb_layout.addWidget(self.usb_refresh_button)
        main_layout.addLayout(usb_layout)

        main_layout.addWidget(self.usb_details_display)

        main_layout.addSpacing(10)

        # Full format checkbox layout
        format_layout = QHBoxLayout()
        format_layout.addStretch()
        format_layout.addWidget(self.full_format_checkbox)
        format_layout.addStretch()
        main_layout.addLayout(format_layout)

        main_layout.addSpacing(20)

        # Write button layout
        write_button_layout = QHBoxLayout()
        write_button_layout.addStretch()
        write_button_layout.addWidget(self.write_button)
        write_button_layout.addStretch()
        main_layout.addLayout(write_button_layout)

        main_layout.addSpacing(20)

        # Status and Progress layout
        status_progress_layout = QVBoxLayout()
        status_progress_layout.addWidget(self.current_action_label)
        status_progress_layout.addWidget(self.status_label)
        status_progress_layout.addWidget(self.progress_bar)
        main_layout.addLayout(status_progress_layout)

        self.setLayout(main_layout)

    def _connect_signals(self):
        self.browse_iso_button.clicked.connect(self._browse_iso_file)
        self.calculate_sha256_button.clicked.connect(self._calculate_iso_sha256)
        self.usb_refresh_button.clicked.connect(self._detect_usb_devices)
        self.usb_combo.currentIndexChanged.connect(self._usb_selection_changed)
        self.write_button.clicked.connect(self._start_write_process)
        self.setAcceptDrops(True) # Enable drag and drop for the main window

    def _change_language(self):
        lang = self.language_combo.currentData()
        if lang:
            self.current_language = lang
            self._update_ui_texts()

    def _update_ui_texts(self):
        self.setWindowTitle(translations[self.current_language]["app_title_usb"])
        self.iso_label.setText(translations[self.current_language]["selected_iso_file"])
        if not self.iso_path: # Update placeholder if no ISO selected
            self.iso_path_display.setText(translations[self.current_language]["iso_details_placeholder"])
        self.browse_iso_button.setText(translations[self.current_language]["browse"])
        self.calculate_sha256_button.setText(translations[self.current_language]["calculate_sha256"])
        self.expected_sha256_label.setText(translations[self.current_language]["expected_sha256_label"])
        self.expected_sha256_input.setPlaceholderText(translations[self.current_language]["expected_sha256_placeholder"])
        self.calculated_sha256_label.setText(translations[self.current_language]["calculated_sha256_label"])
        self.calculated_sha256_display.setPlaceholderText(translations[self.current_language]["calculated_sha256_placeholder"])
        self.usb_label.setText(translations[self.current_language]["select_usb_device"])
        self.usb_refresh_button.setText(translations[self.current_language]["refresh"])
        if not self.selected_usb_device_path: # Update placeholder if no USB selected
            self.usb_details_display.setText(translations[self.current_language]["usb_details_placeholder"])
            self.usb_combo.setPlaceholderText(translations[self.current_language]["select_usb_device_option"])
        else:
            # Re-populate USB combo to update display strings
            current_selected_text = self.usb_combo.currentText()
            self._detect_usb_devices() # This will refresh and re-select
            idx = self.usb_combo.findText(current_selected_text)
            if idx >= 0:
                self.usb_combo.setCurrentIndex(idx)

        self.full_format_checkbox.setText(translations[self.current_language]["format_usb_full_option"])
        self.write_button.setText(translations[self.current_language]["write_to_usb"])
        # Status and current action labels are updated by signals, but set default idle
        if not self.is_operation_in_progress:
            self.status_label.setText(translations[self.current_language]["ready_to_start"])
            self.current_action_label.setText(translations[self.current_language]["action_idle"])
        
        self.set_direction()


    def set_direction(self):
        # Set layout direction based on language
        if self.current_language == "ar":
            self.layout().setContentsMargins(20, 20, 20, 20)
            self.layout().setSpacing(10)
            self.setLayoutDirection(Qt.RightToLeft)
        else:
            self.layout().setContentsMargins(20, 20, 20, 20)
            self.layout().setSpacing(10)
            self.setLayoutDirection(Qt.LeftToRight)


    def _check_write_button_state(self):
        iso_selected = self.iso_path is not None and os.path.exists(self.iso_path) and os.path.getsize(self.iso_path) > 0
        usb_selected = self.selected_usb_device_path is not None

        if iso_selected and usb_selected and not self.is_operation_in_progress:
            # Basic size check
            iso_size = os.path.getsize(self.iso_path)
            usb_size_str = self.usb_details_display.text().split('(')[-1].replace(')', '').strip()
            # Extract numerical size from human-readable string (e.g., "7.50 GB")
            try:
                usb_size_bytes = self._parse_human_readable_size(usb_size_str)
                if iso_size > usb_size_bytes:
                    self._show_message(translations[self.current_language]["error"], translations[self.current_language]["insufficient_usb_space_critical"].format(self._bytes_to_human_readable(iso_size), self._bytes_to_human_readable(usb_size_bytes)), "error")
                    self.write_button.setEnabled(False)
                    return
            except ValueError:
                # If USB size parsing fails, proceed but keep button disabled if needed
                self.write_button.setEnabled(False)
                return

            self.write_button.setEnabled(True)
            self.status_label.setText(translations[self.current_language]["ready_to_start"])
        else:
            self.write_button.setEnabled(False)
            if not self.is_operation_in_progress:
                self.status_label.setText(translations[self.current_language]["ready_to_start"])


    def _browse_iso_file(self):
        if self.is_operation_in_progress: return

        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, translations[self.current_language]["open_iso_file"], "", "ISO Files (*.iso);;All Files (*)", options=options)
        if file_path:
            self.iso_path = file_path
            try:
                iso_size = os.path.getsize(self.iso_path)
                if iso_size == 0:
                    self._show_message(translations[self.current_language]["warning"], translations[self.current_language]["iso_size_zero"], "warning")
                    self.iso_path = None # Invalidate
                    self.iso_path_display.setText(translations[self.current_language]["iso_details_placeholder"])
                else:
                    self.iso_path_display.setText(translations[self.current_language]["iso_details"].format(os.path.basename(file_path), self._bytes_to_human_readable(iso_size)))
                    self.calculated_sha256_display.clear() # Clear old SHA256 if ISO changes
            except FileNotFoundError:
                self._show_message(translations[self.current_language]["error"], translations[self.current_language]["iso_not_found_sha256"], "error")
                self.iso_path = None
                self.iso_path_display.setText(translations[self.current_language]["iso_details_placeholder"])
            except Exception as e:
                self._show_message(translations[self.current_language]["error"], translations[self.current_language]["unexpected_error"].format(str(e)), "error")
                self.iso_path = None
                self.iso_path_display.setText(translations[self.current_language]["iso_details_placeholder"])

        self._check_write_button_state()

    def _calculate_iso_sha256(self):
        if self.is_operation_in_progress: return
        if not self.iso_path:
            self._show_message(translations[self.current_language]["warning"], translations[self.current_language]["no_iso_selected_sha256"], "warning")
            return
        if not os.path.exists(self.iso_path):
            self._show_message(translations[self.current_language]["error"], translations[self.current_language]["iso_not_found_sha256"], "error")
            self.iso_path = None
            self.iso_path_display.setText(translations[self.current_language]["iso_details_placeholder"])
            return

        self._set_ui_busy(True, "calculate_sha_iso")
        self.calculated_sha256_display.setText(translations[self.current_language]["calculating_sha256_short"])
        self.worker_thread = Worker(operation_type="calculate_sha_iso", iso_path=self.iso_path)
        self.worker_thread.progress_updated.connect(self._update_progress_sha)
        self.worker_thread.sha_calculated.connect(lambda sha, type: self.calculated_sha256_display.setText(sha))
        self.worker_thread.operation_finished.connect(self._sha_calculation_finished)
        self.worker_thread.error_occurred.connect(self._handle_error)
        self.worker_thread.start()


    def _detect_usb_devices(self):
        if self.is_operation_in_progress: return
        self.usb_combo.clear()
        self.usb_devices.clear()
        self.selected_usb_device_path = None
        self.usb_details_display.setText(translations[self.current_language]["usb_details_placeholder"])
        self.write_button.setEnabled(False)

        if not sys.platform.startswith('linux'):
            self.usb_combo.addItem(translations[self.current_language]["no_usb_found"] + " (Linux only)", None)
            return

        try:
            # Use lsblk to list block devices, excluding loop devices (squashfs) and showing path, size, model
            # -b: bytes, -n: no headers, -p: full path, -d: devices only, -o: output columns
            stdout, _ = subprocess.Popen(
                ["lsblk", "-b", "-n", "-p", "-d", "-o", "NAME,SIZE,MODEL"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            ).communicate()

            lines = stdout.strip().split('\n')
            found_usb = False
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 3:
                    device_path = parts[0]
                    device_size = int(parts[1]) if parts[1].isdigit() else 0
                    device_model = " ".join(parts[2:])

                    # Heuristic to identify USB devices (e.g., sda, sdb, not loop, not mmcblk, etc.)
                    # Refine this based on common Linux device naming conventions for USBs.
                    # This is a simplification; a more robust solution might check /sys/block/*/removable.
                    if device_path.startswith("/dev/sd") and not device_path.endswith('boot') and device_size > 0: # Exclude partitions like sda1
                        # Check if it's a removable device (more reliable)
                        if os.path.exists(f"/sys/block/{os.path.basename(device_path)}/removable"):
                            with open(f"/sys/block/{os.path.basename(device_path)}/removable", 'r') as f:
                                if f.read().strip() == '1':
                                    description = f"{device_model} ({self._bytes_to_human_readable(device_size)}) - {device_path}"
                                    self.usb_devices[description] = device_path
                                    self.usb_combo.addItem(description, device_path)
                                    found_usb = True
            if not found_usb:
                self.usb_combo.addItem(translations[self.current_language]["no_usb_found"], None)
                self.usb_combo.setEnabled(False)
            else:
                self.usb_combo.setEnabled(True)
                self.usb_combo.insertItem(0, translations[self.current_language]["select_usb_device_option"], None)
                self.usb_combo.setCurrentIndex(0) # Select the placeholder

        except FileNotFoundError:
            self._show_message(translations[self.current_language]["error"], translations[self.current_language]["lsblk_not_found"], "error")
            self.usb_combo.addItem(translations[self.current_language]["no_usb_found"], None)
        except Exception as e:
            self._show_message(translations[self.current_language]["error"], translations[self.current_language]["lsblk_parse_error"].format(str(e)), "error")
            self.usb_combo.addItem(translations[self.current_language]["no_usb_found"], None)

        self._check_write_button_state()

    def _usb_selection_changed(self):
        selected_data = self.usb_combo.currentData()
        if selected_data:
            self.selected_usb_device_path = selected_data
            self.usb_details_display.setText(self.usb_combo.currentText())
        else:
            self.selected_usb_device_path = None
            self.usb_details_display.setText(translations[self.current_language]["usb_details_placeholder"])
        self._check_write_button_state()

    def _start_write_process(self):
        if self.is_operation_in_progress: return

        if not self.iso_path or not os.path.exists(self.iso_path):
            self._show_message(translations[self.current_language]["warning"], translations[self.current_language]["no_iso_selected"], "warning")
            return
        if not self.selected_usb_device_path:
            self._show_message(translations[self.current_language]["warning"], translations[self.current_language]["no_usb_device_selected"], "warning")
            return

        iso_basename = os.path.basename(self.iso_path)
        usb_desc = self.usb_combo.currentText()

        # Confirm before writing
        confirm_msg = translations[self.current_language]["confirm_write_prompt"].format(
            iso_basename, self._bytes_to_human_readable(os.path.getsize(self.iso_path)),
            usb_desc, self._parse_human_readable_size_display(usb_desc)
        )
        if self.full_format_checkbox.isChecked():
            confirm_msg += "\n\n" + translations[self.current_language]["confirm_format_warning"].format(usb_desc)

        reply = QMessageBox.question(self, translations[self.current_language]["confirm_write"], confirm_msg,
                                     QMessageBox.Yes | QMessageBox.No)

        if reply == QMessageBox.Yes:
            # Check SHA256 if expected is provided
            expected_sha = self.expected_sha256_input.text().strip()
            calculated_sha = self.calculated_sha256_display.text().strip()

            if expected_sha and calculated_sha and expected_sha != calculated_sha:
                mismatch_reply = QMessageBox.question(self, translations[self.current_language]["warning"],
                                                     translations[self.current_language]["sha256_mismatch_proceed_prompt"],
                                                     QMessageBox.Yes | QMessageBox.No)
                if mismatch_reply == QMessageBox.No:
                    self._show_message(translations[self.current_language]["info"], translations[self.current_language]["operation_cancelled"], "info")
                    return

            self._set_ui_busy(True, "write")
            self.worker_thread = Worker(
                operation_type="write",
                iso_path=self.iso_path,
                usb_device=self.selected_usb_device_path
            )
            self.worker_thread.progress_updated.connect(self._update_progress)
            self.worker_thread.operation_finished.connect(self._write_finished)
            self.worker_thread.error_occurred.connect(self._handle_error)
            self.worker_thread.start()
        else:
            self._show_message(translations[self.current_language]["info"], translations[self.current_language]["operation_cancelled"], "info")

    def _format_then_write_or_verify(self):
        if self.full_format_checkbox.isChecked():
            # Start format process
            self._set_ui_busy(True, "format")
            self.worker_thread = Worker(
                operation_type="format",
                usb_device=self.selected_usb_device_path
            )
            self.worker_thread.progress_updated.connect(self._update_progress)
            self.worker_thread.operation_finished.connect(self._format_finished)
            self.worker_thread.error_occurred.connect(self._handle_error)
            self.worker_thread.start()
        else:
            # Skip format, directly start write process (or verification if it's a separate step)
            self._start_write_process_actual() # Now directly call the actual write


    def _set_ui_busy(self, busy, operation_type="idle"):
        self.is_operation_in_progress = busy
        self.browse_iso_button.setEnabled(not busy)
        self.calculate_sha256_button.setEnabled(not busy)
        self.usb_refresh_button.setEnabled(not busy)
        self.usb_combo.setEnabled(not busy)
        self.full_format_checkbox.setEnabled(not busy)
        self.expected_sha256_input.setReadOnly(busy)

        # Write button behavior changes:
        if busy:
            self.write_button.setEnabled(False)
            if operation_type == "write":
                self.current_action_label.setText(translations[self.current_language]["action_writing"])
            elif operation_type == "format":
                self.current_action_label.setText(translations[self.current_language]["action_formatting"])
            elif operation_type == "calculate_sha_iso" or operation_type == "calculate_sha_usb":
                self.current_action_label.setText(translations[self.current_language]["action_verifying"])
        else:
            self.current_action_label.setText(translations[self.current_language]["action_idle"])
            self._check_write_button_state() # Re-enable if conditions met

        self.progress_bar.setValue(0)
        self.status_label.setText(translations[self.current_language]["ready_to_start"])

    def _update_progress(self, value, message):
        self.progress_bar.setValue(value)
        self.status_label.setText(message)

    def _update_progress_sha(self, value, message):
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
        self.calculated_sha256_display.setText(translations[self.current_language]["calculating_sha256_status"])


    def _sha_calculation_finished(self, success, message, op_type):
        self._set_ui_busy(False)
        if success:
            self.status_label.setText(translations[self.current_language]["sha256_calculated_success"])
            # SHA value is emitted via sha_calculated signal already
        else:
            self.status_label.setText(translations[self.current_language]["sha256_calculation_failed_status"])
            self.calculated_sha256_display.setText(translations[self.current_language]["sha256_calculation_failed_status"])
            if message:
                self._show_message(translations[self.current_language]["error"], message, "error")

        # Compare calculated with expected if both are present
        expected_sha = self.expected_sha256_input.text().strip().lower()
        calculated_sha = self.calculated_sha256_display.text().strip().lower()

        if expected_sha and calculated_sha and calculated_sha != translations[self.current_language]["sha256_calculation_failed_status"].lower():
            if expected_sha == calculated_sha:
                self.status_label.setText(translations[self.current_language]["sha256_match"])
                self.calculated_sha256_display.setStyleSheet("color: green; font-weight: bold;")
            else:
                self.status_label.setText(translations[self.current_language]["sha256_mismatch"])
                self.calculated_sha256_display.setStyleSheet("color: red; font-weight: bold;")
        else:
            self.calculated_sha256_display.setStyleSheet("") # Reset style


    def _format_finished(self, success, message, op_type):
        if success:
            self._show_message(translations[self.current_language]["success"], message, "success")
            # After formatting, proceed to write the ISO
            self._start_write_process_actual()
        else:
            self._set_ui_busy(False)
            self._show_message(translations[self.current_language]["error"], message, "error")


    def _write_finished(self, success, message, op_type):
        if success:
            # After successful write, start SHA256 verification of the USB
            self.status_label.setText(translations[self.current_language]["verifying_sha256_post_write"])
            self._set_ui_busy(True, "calculate_sha_usb")
            self.worker_thread = Worker(
                operation_type="calculate_sha_usb",
                iso_path=self.iso_path, # Need ISO size for comparison
                usb_device=self.selected_usb_device_path
            )
            self.worker_thread.progress_updated.connect(self._update_progress)
            self.worker_thread.sha_calculated.connect(self._usb_sha_calculated)
            self.worker_thread.operation_finished.connect(self._usb_sha_verification_finished)
            self.worker_thread.error_occurred.connect(self._handle_error)
            self.worker_thread.start()
        else:
            self._set_ui_busy(False)
            self._show_message(translations[self.current_language]["error"], message, "error")

    def _usb_sha_calculated(self, sha_value, type):
        # Store the calculated SHA for the USB device
        self._usb_calculated_sha = sha_value

    def _usb_sha_verification_finished(self, success, message, op_type):
        self._set_ui_busy(False)
        original_iso_sha = self.calculated_sha256_display.text().strip().lower()
        
        if success:
            if original_iso_sha and self._usb_calculated_sha:
                if original_iso_sha == self._usb_calculated_sha:
                    self._show_message(translations[self.current_language]["success"], translations[self.current_language]["write_and_verify_successful"], "success")
                else:
                    self._show_message(translations[self.current_language]["warning"], translations[self.current_language]["write_successful_verify_failed"].format(original_iso_sha, self._usb_calculated_sha), "warning")
            else:
                 # If original ISO SHA was not calculated or something went wrong
                self._show_message(translations[self.current_language]["success"], translations[self.current_language]["write_successful"], "success")
        else:
            self._show_message(translations[self.current_language]["error"], message, "error")

        self._usb_calculated_sha = None # Reset for next operation


    def _handle_error(self, message):
        self._set_ui_busy(False)
        self._show_message(translations[self.current_language]["error"], message, "error")

    def _show_message(self, title, message, msg_type="info"):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        if msg_type == "error":
            msg_box.setIcon(QMessageBox.Critical)
        elif msg_type == "warning":
            msg_box.setIcon(QMessageBox.Warning)
        else:
            msg_box.setIcon(QMessageBox.Information)
        msg_box.exec_()

    def _bytes_to_human_readable(self, num_bytes):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if num_bytes < 1024.0:
                return f"{num_bytes:.2f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.2f} PB"

    def _parse_human_readable_size(self, size_str):
        # Parses a string like "7.50 GB" into bytes
        if not size_str:
            return 0
        
        size_str = size_str.upper().replace(",", ".") # Handle comma decimal separators
        parts = size_str.split()
        if len(parts) != 2:
            raise ValueError(f"Invalid size string format: {size_str}")
        
        value = float(parts[0])
        unit = parts[1]

        if unit == 'B': return int(value)
        elif unit == 'KB': return int(value * (1024**1))
        elif unit == 'MB': return int(value * (1024**2))
        elif unit == 'GB': return int(value * (1024**3))
        elif unit == 'TB': return int(value * (1024**4))
        elif unit == 'PB': return int(value * (1024**5))
        else: raise ValueError(f"Unknown unit: {unit}")

    def _parse_human_readable_size_display(self, display_str):
        # Extracts and parses size from display string like "Model (7.50 GB) - /dev/sdx"
        try:
            start_index = display_str.find('(')
            end_index = display_str.find(')')
            if start_index != -1 and end_index != -1:
                size_part = display_str[start_index + 1 : end_index].strip()
                return self._bytes_to_human_readable(self._parse_human_readable_size(size_part))
            return ""
        except Exception:
            return ""

    # Drag and Drop functionality
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                file_path = url.toLocalFile()
                if file_path.lower().endswith(".iso"):
                    self.iso_path = file_path
                    try:
                        iso_size = os.path.getsize(self.iso_path)
                        if iso_size == 0:
                            self._show_message(translations[self.current_language]["warning"], translations[self.current_language]["iso_size_zero"], "warning")
                            self.iso_path = None
                            self.iso_path_display.setText(translations[self.current_language]["iso_details_placeholder"])
                        else:
                            self.iso_path_display.setText(translations[self.current_language]["iso_details"].format(os.path.basename(file_path), self._bytes_to_human_readable(iso_size)))
                            self.calculated_sha256_display.clear()
                    except FileNotFoundError:
                        self._show_message(translations[self.current_language]["error"], translations[self.current_language]["iso_not_found_sha256"], "error")
                        self.iso_path = None
                        self.iso_path_display.setText(translations[self.current_language]["iso_details_placeholder"])
                    except Exception as e:
                        self._show_message(translations[self.current_language]["error"], translations[self.current_language]["unexpected_error"].format(str(e)), "error")
                        self.iso_path = None
                        self.iso_path_display.setText(translations[self.current_language]["iso_details_placeholder"])
                    self._check_write_button_state()
                    break # Only process the first valid ISO
                else:
                    self._show_message(translations[self.current_language]["warning"], translations[self.current_language]["drop_invalid_file"], "warning")
            event.accept()
        else:
            event.ignore()

    def closeEvent(self, event):
        if self.is_operation_in_progress:
            reply = QMessageBox.question(self, translations[self.current_language]["warning"],
                                         translations[self.current_language]["cancel_running_operation"],
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                if self.worker_thread and self.worker_thread.isRunning():
                    self.worker_thread.cancel()
                    self.worker_thread.wait(5000) # Give it a chance to terminate gracefully
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = HelwanUSBWriter()
    window.show()
    sys.exit(app.exec_())
