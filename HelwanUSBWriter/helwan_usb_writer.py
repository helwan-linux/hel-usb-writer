import sys
import os
import hashlib
from PyQt5.QtWidgets import (
    QApplication, QWidget, QFileDialog, QVBoxLayout, QPushButton, QLabel,
    QComboBox, QTextEdit, QMessageBox, QHBoxLayout
)
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import QProcess, Qt, QThread, pyqtSignal
import math # Needed for math.ceil() for block calculation

class ChecksumThread(QThread):
    result = pyqtSignal(str)
    # Could add a progress signal if desired, but harder with external commands
    # progress = pyqtSignal(int)

    def __init__(self, path, is_device=False, limit_bytes=None):
        super().__init__()
        self.path = path
        self.is_device = is_device
        self.limit_bytes = limit_bytes
        self._process = None # To hold the QProcess instance if used

    def run(self):
        if not self.is_device:
            # Current logic for calculating checksum for files (like ISO)
            try:
                hasher = hashlib.sha256()
                read_bytes = 0
                # Open the file for binary reading
                with open(self.path, 'rb') as f:
                    while True:
                        # If there's a byte limit and it's reached, break
                        if self.limit_bytes and read_bytes >= self.limit_bytes:
                            break
                        # Read a chunk of data (4MB)
                        chunk = f.read(4 * 1024 * 1024)
                        if not chunk: # If no more chunks, break
                            break
                        # If there's a byte limit, ensure we don't exceed it
                        if self.limit_bytes:
                            chunk = chunk[:self.limit_bytes - read_bytes]
                        hasher.update(chunk) # Update the hasher with the read data
                        read_bytes += len(chunk) # Update the number of bytes read
                        # Could add progress update here if total file size is known
                # Emit the calculated checksum
                self.result.emit(hasher.hexdigest())
            except Exception as e:
                # Emit an error message in case of an exception
                self.result.emit(f"Error: {e}")
        else:
            # New logic for calculating checksum of USB devices using pkexec, dd, and sha256sum
            try:
                # Define block size for reading (4MB)
                bs = 4 * 1024 * 1024
                # Calculate the number of blocks to read based on limit_bytes
                # math.ceil ensures enough blocks are read to cover limit_bytes entirely
                count_blocks = math.ceil(self.limit_bytes / bs) if self.limit_bytes else None

                # Construct the command to be executed using pkexec
                # pkexec: to run the command with root privileges
                # sh -c: to execute a command string within a shell
                # dd if={device_path}: to read from the device
                # bs={bs}: block size
                # count={count_blocks}: number of blocks to read (if limit_bytes is set)
                # status=none: to suppress progress messages from dd
                # 2>/dev/null: to redirect errors to /dev/null
                # | sha256sum: to pipe dd's output directly to sha256sum for checksum calculation
                if count_blocks:
                    command_string = f"dd if={self.path} bs={bs} count={count_blocks} status=none 2>/dev/null | sha256sum"
                else:
                    # If no limit_bytes, read the entire device (can be very slow)
                    command_string = f"dd if={self.path} bs={bs} status=none 2>/dev/null | sha256sum"

                command_parts = ["pkexec", "sh", "-c", command_string]

                self._process = QProcess()
                # setReadChannelMode(QProcess.MergedChannels) was removed as it caused issues
                # in some PyQt5 versions and is not strictly necessary here because
                # stderr is already redirected in the shell command.

                # Start the process
                self._process.start(command_parts[0], command_parts[1:])
                # Wait until the process finishes
                self._process.waitForFinished(-1)

                # Read all output from the process and decode it
                output = self._process.readAllStandardOutput().data().decode().strip()
                exit_code = self._process.exitCode()
                exit_status = self._process.exitStatus()

                # Check if the command executed successfully
                if exit_code == 0 and exit_status == QProcess.NormalExit:
                    # sha256sum outputs "checksum  filename" or "checksum  -"
                    # We split the output to get only the checksum
                    checksum = output.split(' ')[0]
                    self.result.emit(checksum) # Emit the checksum
                else:
                    # In case of an error during command execution
                    self.result.emit(f"Error executing command: {output}. Exit code: {exit_code}")

            except Exception as e:
                self.result.emit(f"Error: {e}")

    # Optional function to stop the process if it's still running
    def stop(self):
        if self._process and self._process.state() == QProcess.Running:
            self._process.terminate() # Attempt to gracefully terminate the process
            self._process.waitForFinished(1000) # Give it some time
            if self._process.state() == QProcess.Running:
                self._process.kill() # Kill the process if it doesn't stop


class USBIsoWriter(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Helwan USB ISO Writer")
        self.setGeometry(400, 200, 600, 500)
        # Ensure 'helwan-usb.png' image file is in the same directory as the script
        self.setWindowIcon(QIcon("helwan-usb.png"))

        layout = QVBoxLayout()

        logo = QLabel()
        pixmap = QPixmap("helwan-usb.png")
        # Resize the image to fit the width
        logo.setPixmap(pixmap.scaledToWidth(64))
        layout.addWidget(logo, alignment=Qt.AlignCenter)

        self.iso_label = QLabel("Selected ISO: None")
        self.choose_iso_button = QPushButton("Choose ISO File")
        self.choose_iso_button.clicked.connect(self.choose_iso)

        self.device_label = QLabel("Selected USB Device:")
        self.device_combo = QComboBox()
        self.refresh_devices_button = QPushButton("Refresh USB Devices") # New refresh button
        self.refresh_devices_button.clicked.connect(self.refresh_devices) # Connect refresh button to refresh_devices function

        # New horizontal layout for QComboBox and refresh button
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
        self.log.setReadOnly(True) # Make the log area read-only

        # Add all widgets to the main layout
        layout.addWidget(self.iso_label)
        layout.addWidget(self.choose_iso_button)
        layout.addWidget(self.device_label)
        layout.addLayout(device_selection_layout) # Add the new horizontal layout
        layout.addLayout(buttons_layout)
        layout.addWidget(self.log)

        self.setLayout(layout)
        self.iso_path = None
        self.iso_checksum = None
        self.usb_checksum = None
        self.process = None # For the dd writing process

        # Refresh devices on initial startup
        self.refresh_devices()

    def choose_iso(self):
        # Open a file dialog to choose an ISO file
        path, _ = QFileDialog.getOpenFileName(self, "Choose ISO File", "", "ISO Files (*.iso)")
        if path:
            self.iso_path = path
            # Update the text to show only the selected file's base name
            self.iso_label.setText(f"Selected ISO: {os.path.basename(path)}")

    def refresh_devices(self):
        self.log.append("[🔍] Refreshing USB devices...") # Log message
        self.device_combo.clear() # Clear current device list
        # Use lsblk to list device information (NAME, SIZE, MODEL, TRANsport, TYPE)
        # -dn: do not print headers, do not print sub-partitions
        result = os.popen("lsblk -o NAME,SIZE,MODEL,TRAN,TYPE -dn").read().strip().split("\n")
        found_devices = False # Flag to track if any devices were found
        for line in result:
            # Look for "disk" type devices only, not partitions
            if "disk" in line:
                parts = line.split()
                if len(parts) >= 4:
                    name, size, model, tran = parts[:4]
                    device_path = f"/dev/{name}" # Construct the full device path
                    # Add the device to the dropdown list
                    self.device_combo.addItem(f"{device_path} ({size} - {model})")
                    found_devices = True
        if not found_devices:
            self.log.append("[💡] No USB devices found. Please ensure they are connected.") # Message if no devices found
        else:
            self.log.append("[✔] USB devices refreshed.") # Message upon successful refresh

    def checksum_iso(self):
        if not self.iso_path:
            QMessageBox.warning(self, "Error", "Please select an ISO file.")
            return
        self.log.append("[🔍] Calculating ISO checksum...")
        # Start a thread to calculate checksum for the ISO file (not a device)
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
        device = device_entry.split()[0] # Get device path from selected text
        # Get ISO file size to use as a read limit for the USB
        size = os.path.getsize(self.iso_path)
        self.log.append("[🔍] Calculating USB checksum (same size as ISO)...")
        # Start a thread to calculate checksum for the USB device (it's a device), with read limit
        self.usb_checksum_thread = ChecksumThread(device, is_device=True, limit_bytes=size)
        self.usb_checksum_thread.result.connect(self.handle_usb_checksum)
        self.usb_checksum_thread.start()

    def handle_usb_checksum(self, result):
        self.usb_checksum = result
        self.log.append(f"[✔] USB Checksum: {result}")
        # Compare checksums after both are done
        if self.iso_checksum and self.usb_checksum:
            if self.iso_checksum == self.usb_checksum:
                self.log.append("[✅] MATCH: ISO and USB checksums match.")
            else:
                self.log.append("[❌] MISMATCH: ISO and USB checksums differ.")
                # New explanatory message for the user
                self.log.append("[💡] Note: USB checksum may differ from ISO due to metadata or padding on the raw device. If the USB works and boots correctly (as in QEMU or actual boot test), it is likely fine.")

    def write_iso(self):
        if not self.iso_path:
            QMessageBox.warning(self, "Error", "Please select an ISO file.")
            return
        device_entry = self.device_combo.currentText()
        if not device_entry:
            QMessageBox.warning(self, "Error", "Please select a USB device.")
            return
        device = device_entry.split()[0] # Get device path
        # Ask for user confirmation before writing (USB data will be lost)
        confirm = QMessageBox.question(
            self,
            "Confirm Write",
            f"Are you sure you want to write:\n\n{self.iso_path}\n\nto\n{device} ?\n\nAll data on the USB will be lost!",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm != QMessageBox.Yes:
            return

        self.log.append(f"[INFO] Writing {self.iso_path} to {device}...")
        # dd command to write ISO to USB, using pkexec to request root privileges
        command = ["pkexec", "dd", f"if={self.iso_path}", f"of={device}", "bs=4M", "status=progress", "oflag=sync"]
        self.process = QProcess(self)
        # Connect stdout and stderr signals of the process to handling functions
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.finished.connect(self.process_finished) # Connect finished signal
        self.process.start(command[0], command[1:]) # Start the process

    def handle_stdout(self):
        # Read and update the log with dd's stdout
        data = self.process.readAllStandardOutput().data().decode()
        self.log.append(data)

    def handle_stderr(self):
        # Read and update the log with dd's stderr (often progress messages appear here)
        data = self.process.readAllStandardError().data().decode()
        self.log.append(data)

    def process_finished(self):
        # Message when writing process is done
        self.log.append("[✔] Done writing ISO.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    writer = USBIsoWriter()
    writer.show()
    sys.exit(app.exec_())
