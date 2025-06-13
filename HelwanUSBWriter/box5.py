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
    """
    Worker thread for performing long-running operations (like writing, formatting, SHA256 calculation)
    to keep the main GUI responsive.

    Signals:
        progress_updated (int, str): Emitted to update the progress bar and status message.
        operation_finished (bool, str, str): Emitted when an operation completes.
                                            Args: success (bool), message (str), type (str - "write"/"format"/"sha_iso"/"sha_usb").
        sha_calculated (str, str): Emitted when SHA256 is calculated.
                                   Args: sha_value (str), type (str - "iso"/"usb").
        error_occurred (str): Emitted when an unhandled error occurs in the worker.
    """
    progress_updated = pyqtSignal(int, str)
    operation_finished = pyqtSignal(bool, str, str) # success, message, type (write/format/sha_iso/sha_usb)
    sha_calculated = pyqtSignal(str, str) # sha_value, type (iso/usb)
    error_occurred = pyqtSignal(str)

    def __init__(self, operation_type, iso_path=None, usb_device=None, full_format=False, current_language="en"):
        """
        Initializes the Worker thread.

        Args:
            operation_type (str): The type of operation to perform ("write", "format", "calculate_sha_iso", "calculate_sha_usb").
            iso_path (str, optional): Path to the ISO file, required for "write" and "calculate_sha_iso". Defaults to None.
            usb_device (str, optional): Path to the USB device, required for "write", "format", and "calculate_sha_usb". Defaults to None.
            full_format (bool, optional): Whether to perform a full format during the "format" operation. Defaults to False.
            current_language (str, optional): The current language for translation. Defaults to "en".
        """
        super().__init__()
        self.operation_type = operation_type
        self.iso_path = iso_path
        self.usb_device = usb_device
        self.full_format = full_format
        self.current_language = current_language
        self._is_cancelled = False # Flag to allow cancellation of long operations

    def run(self):
        """
        Executes the specified operation based on self.operation_type.
        """
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
            # Catch any unexpected exceptions and emit an error signal
            self.error_occurred.emit(str(e))
        finally:
            # Ensure operation_finished is always emitted if not already by a specific success/failure path.
            # This handles cases where an error might occur before explicit completion is signaled.
            pass # The specific operation methods should emit operation_finished.

    def cancel(self):
        """
        Sets the cancellation flag to True. Long-running operations should check this flag
         periodically and terminate gracefully.
        """
        self._is_cancelled = True

    def _execute_command(self, command, shell=False, check_return=True, custom_error_msg="", timeout=None, input_data=None):
        """
        Executes a shell command and handles its output and errors.

        Args:
            command (list or str): The command to execute (list for Popen, str for shell=True).
            shell (bool): Whether to execute the command via the shell. Defaults to False.
            check_return (bool): If True, raises subprocess.CalledProcessError if return code is non-zero. Defaults to True.
            custom_error_msg (str): Custom error message to use if an error occurs.
            timeout (int, optional): Timeout in seconds for the command. Defaults to None.
            input_data (str, optional): String data to pass to stdin of the command.

        Returns:
            tuple: (stdout, stderr) as strings.

        Raises:
            subprocess.CalledProcessError: If check_return is True and the command fails.
            FileNotFoundError: If the command itself is not found.
            subprocess.TimeoutExpired: If the command times out.
            Exception: For other unexpected errors.
        """
        process = None
        try:
            preexec_fn = None
            if sys.platform.startswith('linux'):
                preexec_fn = os.setsid

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if input_data else None,
                text=True, # Decode stdout/stderr as text using default encoding
                shell=shell,
                preexec_fn=preexec_fn
            )

            stdout, stderr = process.communicate(input=input_data, timeout=timeout)
            
            if check_return and process.returncode != 0:
                # Store full stdout and stderr for later use in error message
                e = subprocess.CalledProcessError(process.returncode, command)
                e.stdout = stdout # Attach stdout/stderr attributes
                e.stderr = stderr
                raise e # Re-raise the error with attached output

            return stdout, stderr
        except subprocess.CalledProcessError as e:
            # We now reliably have e.stdout and e.stderr because we attached them
            full_stderr = e.stderr.strip() if e.stderr else ""
            full_stdout = e.stdout.strip() if e.stdout else ""

            # Combine output for clearer error details
            error_details_parts = []
            if full_stderr:
                error_details_parts.append(f"STDERR:\n{full_stderr}")
            if full_stdout: # stdout might contain useful info even if stderr is empty
                error_details_parts.append(f"STDOUT:\n{full_stdout}")

            if not error_details_parts:
                error_details = translations[self.current_language]["no_error_details_found"]
            else:
                error_details = "\n".join(error_details_parts)

            error_msg = custom_error_msg if custom_error_msg else translations[self.current_language]["subprocess_error"].format(e.cmd, e.returncode, error_details)
            # If check_return is False, we just return the error message in stderr and let the caller handle it.
            # If check_return is True, we already raised, so this path is not reached for successful error raising.
            # For this context, we return the error in stderr if check_return is False.
            if not check_return:
                return "", f"Error: {error_msg}"
            else: # If check_return was True, this exception is re-raised and handled by the caller or outer try-except.
                raise # Re-raise the original exception if check_return was True.
        except FileNotFoundError:
            command_name = command[0] if isinstance(command, list) else command.split(' ')[0]
            error_msg = translations[self.current_language]["command_not_found"].format(command_name)
            self.operation_finished.emit(False, error_msg, self.operation_type)
            return "", f"Error: {error_msg}"
        except subprocess.TimeoutExpired:
            if process:
                if sys.platform.startswith('linux') and preexec_fn:
                    os.killpg(os.getpgid(process.pid), 9) # SIGKILL
                else:
                    process.kill()
                process.wait()
            error_msg = translations[self.current_language]["subprocess_error"].format(command, "Timeout", "Operation timed out")
            self.operation_finished.emit(False, error_msg, self.operation_type)
            return "", f"Error: {error_msg}"
        except Exception as e:
            error_msg = translations[self.current_language]["unexpected_error"].format(str(e))
            self.operation_finished.emit(False, error_msg, self.operation_type)
            return "", f"Error: {error_msg}"

    def _unmount_partitions(self, device_path):
        """
        Unmounts all partitions associated with a given USB device path on Linux.

        Args:
            device_path (str): The path to the main USB device (e.g., /dev/sdb).

        Returns:
            bool: True if unmounting was successful or no partitions found, False otherwise.
        """
        if not sys.platform.startswith('linux'):
            return True

        self.progress_updated.emit(0, translations[self.current_language]["unmounting_usb"].format(device_path))

        try:
            # List partitions of the device using lsblk
            # We explicitly set check_return=False here, so we can handle errors gracefully
            stdout, stderr = self._execute_command(
                ["lsblk", "-n", "-p", "-o", "NAME", device_path],
                check_return=False, # Do not raise exception for lsblk failure here
                custom_error_msg=translations[self.current_language]["unmount_lsblk_error"]
            )

            # Check for specific error message indicating lsblk itself failed (not just no partitions)
            if "Error:" in stderr:
                full_error_msg = stderr.replace("Error: ", "").strip()
                # If lsblk couldn't even list the device (e.g., device removed), consider it a critical error
                if "No such device or directory" in full_error_msg or "Permission denied" in full_error_msg:
                    self.operation_finished.emit(False, translations[self.current_language]["unmount_lsblk_critical_error"].format(full_error_msg), self.operation_type)
                    return False
                else:
                    # For other lsblk errors, warn but attempt to proceed, maybe there are no mounted partitions anyway.
                    # Or we could emit a warning but still return True if no partitions were found in stdout.
                    # For now, let's treat any lsblk error that produces "Error:" in stderr as a failure to get partitions.
                    self.operation_finished.emit(False, translations[self.current_language]["unmount_lsblk_error"].format(full_error_msg), self.operation_type)
                    return False


            partitions = stdout.strip().split('\n')
            # Filter for actual partitions belonging to the device (e.g., /dev/sdb1, /dev/sdb2)
            partitions = [p for p in partitions if p.startswith(device_path) and p != device_path and p != ''] # Ensure no empty strings

            if not partitions:
                self.progress_updated.emit(0, translations[self.current_language]["no_partitions_to_unmount"])
                return True # No partitions to unmount, consider it successful

            all_unmounted_successfully = True
            failed_partitions = []
            for part in partitions:
                if self._is_cancelled:
                    self.operation_finished.emit(False, translations[self.current_language]["operation_cancelled"], self.operation_type)
                    return False

                self.progress_updated.emit(0, translations[self.current_language]["unmounting_partition"].format(part))
                # Attempt to unmount the partition, using -l for lazy unmount
                # Check return=False to handle errors gracefully, as umount often returns non-zero for busy/already unmounted
                umount_stdout, umount_stderr = self._execute_command(
                    ["sudo", "umount", "-l", part],
                    check_return=False,
                    custom_error_msg=translations[self.current_language]["unmount_error"].format(part)
                )

                if "Error:" in umount_stderr:
                    # If umount explicitly returned an error (e.g., device not found, permission denied, not mounted)
                    # We log it and mark it as a failure for this specific partition
                    self.error_occurred.emit(translations[self.current_language]["unmount_error"].format(part) + f": {umount_stderr.replace('Error: ', '')}")
                    all_unmounted_successfully = False
                    failed_partitions.append(part)
                elif umount_stderr: # Some non-critical warnings from umount might appear in stderr but not "Error:"
                    self.progress_updated.emit(0, translations[self.current_language]["unmount_warning"].format(part, umount_stderr.strip()))

            if not all_unmounted_successfully:
                self.operation_finished.emit(False, translations[self.current_language]["some_partitions_failed_unmount"].format(", ".join(failed_partitions)), self.operation_type)
                return False
            
            self.progress_updated.emit(0, translations[self.current_language]["unmount_successful"])
            return True
        except Exception as e:
            # Catch any unexpected errors during the process
            error_msg = translations[self.current_language]["unmount_unexpected_error"].format(str(e))
            self.operation_finished.emit(False, error_msg, self.operation_type)
            return False


    def _format_usb(self):
        """
        Performs a full format of the USB device on Linux.
        This includes wiping signatures, creating a new partition table (MBR),
        and creating/formatting a single FAT32 partition.
        Includes fallback attempts if initial parted commands fail.
        """
        if not sys.platform.startswith('linux'):
            self.operation_finished.emit(False, translations[self.current_language]["format_failed"].format("Unsupported OS for full format."), "format")
            return

        usb_device = self.usb_device
        self.progress_updated.emit(0, translations[self.current_language]["action_formatting"])

        # First, try to unmount any mounted partitions on the USB device
        if not self._unmount_partitions(usb_device):
            return # _unmount_partitions already emits operation_finished

        # --- Begin new formatting logic with fallbacks ---
        try:
            # Attempt 1: Clear first MB with dd (very destructive, but effective)
            self.progress_updated.emit(0, translations[self.current_language]["clearing_usb_signatures"].format(usb_device))
            dd_stdout, dd_stderr = self._execute_command(["sudo", "dd", f"if=/dev/zero", f"of={usb_device}", "bs=1M", "count=1"], check_return=False, custom_error_msg=translations[self.current_language]["dd_clear_fail"])
            # Check stderr for "Error:" prefix from our _execute_command
            if "Error:" in dd_stderr:
                self.operation_finished.emit(False, translations[self.current_language]["dd_clear_fail"].format(dd_stderr.replace("Error: ", "")), "format")
                return

            time.sleep(1) # Give kernel time to process changes

            # Attempt 2: Use wipefs (more targeted, but might have issues if disk is very corrupted)
            self.progress_updated.emit(0, translations[self.current_language]["wiping_usb_signatures"].format(usb_device))
            # check_return=False because wipefs might fail if no signatures are found, but it's still a "success" for our purpose
            wipefs_stdout, wipefs_stderr = self._execute_command(["sudo", "wipefs", "--all", "--force", usb_device], check_return=False, custom_error_msg=translations[self.current_language]["wipefs_fail"])
            # Ignore "No signature" errors from wipefs, but check for other critical errors
            if "Error:" in wipefs_stderr and "No signature" not in wipefs_stderr: # Ignore "No signature" errors
                self.operation_finished.emit(False, translations[self.current_language]["wipefs_fail"].format(wipefs_stderr.replace("Error: ", "")), "format")
                return
            time.sleep(1)

            # Try parted for partition table and FAT32 partition
            try:
                self.progress_updated.emit(0, translations[self.current_language]["creating_partition_table"].format(usb_device))
                self._execute_command(["sudo", "parted", "-s", usb_device, "mklabel", "msdos"], custom_error_msg=translations[self.current_language]["parted_mklabel_fail"])
                time.sleep(1) # Give kernel time to recognize new table

                self.progress_updated.emit(0, translations[self.current_language]["creating_fat32_partition"].format(usb_device))
                self._execute_command(["sudo", "parted", "-s", usb_device, "mkpart", "primary", "fat32", "0%", "100%"], custom_error_msg=translations[self.current_language]["parted_mkpart_fat32_fail"])
                time.sleep(1) # Give kernel time to recognize new partition

                target_partition = self._find_newly_created_partition(usb_device)
                if not target_partition:
                    raise Exception(translations[self.current_language]["partition_not_found_after_creation"])

                self.progress_updated.emit(0, translations[self.current_language]["formatting_fat32"].format(target_partition))
                self._execute_command(["sudo", "mkfs.fat", "-F", "32", target_partition], custom_error_msg=translations[self.current_language]["mkfs_fat_fail"])

            except subprocess.CalledProcessError as e:
                # If parted or mkfs.fat fails, try fdisk + ext4 as a fallback
                error_details = e.stderr.strip() if e.stderr else e.stdout.strip() if e.stdout else translations[self.current_language]["no_error_details_found"]
                self.error_occurred.emit(translations[self.current_language]["parted_fallback_attempt"].format(error_details))
                self._attempt_fdisk_ext4_fallback(usb_device)
                
            except Exception as e:
                # If finding partition or other general error in parted path
                self.error_occurred.emit(translations[self.current_language]["parted_fallback_attempt_general"].format(str(e)))
                self._attempt_fdisk_ext4_fallback(usb_device)

            self.operation_finished.emit(True, translations[self.current_language]["usb_formatted_success"], "format")

        except subprocess.CalledProcessError as e:
            # If dd or wipefs at the very beginning fail, this will catch it
            # _execute_command already emits operation_finished, but we might want to ensure.
            error_details = e.stderr.strip() if e.stderr else e.stdout.strip() if e.stdout else translations[self.current_language]["no_error_details_found"]
            error_msg = translations[self.current_language]["format_failed"].format(error_details)
            self.operation_finished.emit(False, error_msg, "format")
        except Exception as e:
            error_msg = translations[self.current_language]["format_failed_unexpected"].format(str(e))
            self.operation_finished.emit(False, error_msg, "format")


    def _find_newly_created_partition(self, usb_device):
        """
        Attempts to find the newly created partition (e.g., /dev/sdb1) associated with usb_device.
        Retries multiple times to account for kernel delays.
        """
        for _ in range(10): # Try up to 10 times with 0.5 sec delay
            stdout, stderr = self._execute_command(["lsblk", "-n", "-p", "-o", "NAME", usb_device], custom_error_msg=translations[self.current_language]["lsblk_partition_fail_after_creation"], check_return=False)
            if "Error:" in stderr: # If lsblk itself failed here, it's a problem
                self.error_occurred.emit(translations[self.current_language]["lsblk_partition_fail_after_creation"].format(stderr.replace("Error: ", "")))
                return None
            new_partitions = [p for p in stdout.strip().split('\n') if p.startswith(usb_device) and p != usb_device and p != '']
            if new_partitions:
                # Sort to get the first partition (e.g., /dev/sdb1 before /dev/sdb2)
                new_partitions.sort()
                return new_partitions[0]
            time.sleep(0.5)
        return None

    def _attempt_fdisk_ext4_fallback(self, usb_device):
        """
        Attempts to format the USB using fdisk for partitioning and mkfs.ext4 for filesystem.
        This is a fallback if parted/FAT32 fails.
        """
        self.progress_updated.emit(0, translations[self.current_language]["attempting_fdisk_fallback"].format(usb_device))
        
        # Unmount again, just in case
        if not self._unmount_partitions(usb_device):
            return # If unmount fails again, it will emit error and stop.
        
        try:
            # Use fdisk to create a new partition table and a single Linux partition
            # 'o' for new empty DOS partition table
            # 'n' for new partition
            # 'p' for primary
            # '1' for partition number 1
            # '' for default first sector
            # '' for default last sector
            # 'w' to write table to disk and exit
            fdisk_commands = "o\nn\np\n1\n\n\nw\n"
            
            self._execute_command(["sudo", "fdisk", usb_device], input_data=fdisk_commands, custom_error_msg=translations[self.current_language]["fdisk_fail"])
            time.sleep(2) # Give kernel more time to recognize fdisk changes

            target_partition = self._find_newly_created_partition(usb_device)
            if not target_partition:
                raise Exception(translations[self.current_language]["partition_not_found_after_fdisk"])

            self.progress_updated.emit(0, translations[self.current_language]["formatting_ext4"].format(target_partition))
            self._execute_command(["sudo", "mkfs.ext4", "-F", target_partition], custom_error_msg=translations[self.current_language]["mkfs_ext4_fail"])
            
            self.operation_finished.emit(True, translations[self.current_language]["usb_formatted_success_ext4"], "format")

        except subprocess.CalledProcessError as e:
            error_details = e.stderr.strip() if e.stderr else e.stdout.strip() if e.stdout else translations[self.current_language]["no_error_details_found"]
            self.operation_finished.emit(False, translations[self.current_language]["format_failed_fdisk_ext4"].format(error_details), "format")
        except Exception as e:
            self.operation_finished.emit(False, translations[self.current_language]["format_failed_fdisk_ext4_unexpected"].format(str(e)), "format")


    def _write_iso(self):
        """
        Writes the ISO image to the selected USB device using 'dd' command on Linux.
        Monitors progress through 'dd's stderr output.
        """
        if not sys.platform.startswith('linux'):
            self.operation_finished.emit(False, translations[self.current_language]["write_failed"].format("Unsupported OS for writing."), "write")
            return

        iso_path = self.iso_path
        usb_device = self.usb_device
        self.progress_updated.emit(0, translations[self.current_language]["action_writing"])

        # Unmount any partitions on the target USB device before writing
        if not self._unmount_partitions(usb_device):
            # If unmount fails, _unmount_partitions already emits operation_finished
            return

        try:
            iso_size = os.path.getsize(iso_path)
            # dd command with status=progress for real-time updates
            command = ["sudo", "dd", f"if={iso_path}", f"of={usb_device}", "bs=4M", "status=progress"]
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, # dd progress output goes to stderr
                text=True,
                preexec_fn=os.setsid # For Linux, to kill all child processes if parent terminates
            )

            # Monitor stderr for progress updates from dd
            written_bytes = 0
            while True:
                line = process.stderr.readline()
                if not line:
                    break # End of stderr output
                if self._is_cancelled:
                    # If cancelled, kill the dd process and associated process group
                    os.killpg(os.getpgid(process.pid), 9) # SIGKILL
                    self.operation_finished.emit(False, translations[self.current_language]["operation_cancelled"], "write")
                    return

                # Parse dd progress line (e.g., "123456789 bytes (123 MB, 117 MiB) copied, 10.123 s, 12.3 MB/s")
                if "bytes" in line and "(" in line and "copied" in line:
                    parts = line.split("bytes")[0].strip().split()
                    if parts and parts[0].isdigit():
                        try:
                            written_bytes = int(parts[0])
                            progress_percent = int((written_bytes / iso_size) * 100)
                            self.progress_updated.emit(
                                progress_percent,
                                translations[self.current_language]["writing_progress"].format(
                                    self._bytes_to_human_readable(written_bytes),
                                    self._bytes_to_human_readable(iso_size),
                                    progress_percent
                                )
                            )
                        except ValueError:
                            pass # Ignore lines that don't parse as valid progress
            
            # Wait for the dd process to finish and check its return code
            process.wait()
            if process.returncode != 0:
                e = subprocess.CalledProcessError(process.returncode, command)
                e.stdout = process.stdout.read() # Attach stdout/stderr attributes
                e.stderr = process.stderr.read()
                raise e

            self.operation_finished.emit(True, translations[self.current_language]["write_successful"], "write")

        except subprocess.CalledProcessError as e:
            full_stderr = e.stderr.strip() if e.stderr else ""
            full_stdout = e.stdout.strip() if e.stdout else ""

            error_details_parts = []
            if full_stderr:
                error_details_parts.append(f"STDERR:\n{full_stderr}")
            if full_stdout:
                error_details_parts.append(f"STDOUT:\n{full_stdout}")

            if not error_details_parts:
                error_details = translations[self.current_language]["no_error_details_found"]
            else:
                error_details = "\n".join(error_details_parts)
            
            error_msg = translations[self.current_language]["write_failed"].format(error_details)
            self.operation_finished.emit(False, error_msg, "write")
        except FileNotFoundError:
            self.operation_finished.emit(False, translations[self.current_language]["dd_not_found"], "write")
        except Exception as e:
            self.operation_finished.emit(False, translations[self.current_language]["unexpected_error"].format(str(e)), "write")


    def _calculate_sha_iso(self):
        """
        Calculates the SHA256 checksum of the selected ISO file.
        Updates progress and emits the calculated SHA256 value.
        """
        if not self.iso_path or not os.path.exists(self.iso_path):
            self.operation_finished.emit(False, translations[self.current_language]["iso_not_found_sha256"], "sha_iso")
            return

        self.progress_updated.emit(0, translations[self.current_language]["action_verifying"])

        try:
            hasher = hashlib.sha256()
            file_size = os.path.getsize(self.iso_path)
            read_bytes = 0
            with open(self.iso_path, 'rb') as f:
                while True:
                    chunk = f.read(4096) # Read in 4KB chunks for efficiency
                    if not chunk:
                        break # End of file
                    if self._is_cancelled:
                        self.operation_finished.emit(False, translations[self.current_language]["operation_cancelled"], "sha_iso")
                        return
                    hasher.update(chunk)
                    read_bytes += len(chunk)
                    # Update progress
                    progress = int((read_bytes / file_size) * 100)
                    self.progress_updated.emit(progress, translations[self.current_language]["calculating_progress"].format(progress))
            
            # Emit the calculated SHA256 hexadecimal digest
            self.sha_calculated.emit(hasher.hexdigest(), "iso")
            self.operation_finished.emit(True, translations[self.current_language]["sha256_calculated_success"], "sha_iso")
        except Exception as e:
            self.operation_finished.emit(False, translations[self.current_language]["sha256_calc_error"].format(str(e)), "sha_iso")


    def _calculate_sha_usb(self):
        """
        Calculates the SHA256 checksum of the data written to the USB device.
        This reads the exact amount of data that was written (ISO size) from the device.
        Requires Linux for 'dd' and 'sha256sum'.
        """
        if not sys.platform.startswith('linux'):
            self.operation_finished.emit(False, translations[self.current_language]["sha256_calc_device_error"].format("Unsupported OS"), "sha_usb")
            return

        if not self.usb_device:
            self.operation_finished.emit(False, translations[self.current_language]["no_usb_device_selected"], "sha_usb")
            return

        if not self.iso_path or not os.path.exists(self.iso_path):
            self.operation_finished.emit(False, translations[self.current_language]["sha256_calc_device_error"].format("ISO path not available for size lookup."), "sha_usb")
            return
        
        iso_size_bytes = os.path.getsize(self.iso_path)
        if iso_size_bytes == 0:
            self.operation_finished.emit(False, translations[self.current_language]["sha256_calc_device_error"].format("ISO size is zero, cannot verify USB."), "sha_usb")
            return


        self.progress_updated.emit(0, translations[self.current_language]["action_verifying"])

        try:
            # Use dd to read from the device for the exact size of the ISO, then pipe to sha256sum
            # Reading in 4M blocks, then handling any remaining bytes.
            bs = 4 * 1024 * 1024 # 4MB block size
            num_blocks = (iso_size_bytes + bs - 1) // bs # Ceiling division to ensure all bytes are read

            dd_command = ["sudo", "dd", f"if={self.usb_device}", f"bs={bs}", f"count={num_blocks}"]
            # Pipe dd output to sha256sum
            dd_process = subprocess.Popen(dd_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
            sha_process = subprocess.Popen(["sha256sum"], stdin=dd_process.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            dd_process.stdout.close() # Allow dd_process to receive SIGPIPE

            # For USB SHA calculation, progress updates from dd piped to sha256sum are not straightforward.
            # We will emit a general message for now.
            self.progress_updated.emit(0, translations[self.current_language]["verifying_usb_progress_no_update"])

            # Wait for both processes to complete
            dd_stdout, dd_stderr = dd_process.communicate() # Block until dd finishes
            sha_output, sha_error = sha_process.communicate() # Block until sha256sum finishes

            if dd_process.returncode != 0:
                e = subprocess.CalledProcessError(dd_process.returncode, dd_command)
                e.stdout = dd_stdout
                e.stderr = dd_stderr
                raise e
            if sha_process.returncode != 0:
                e = subprocess.CalledCError(sha_process.returncode, "sha256sum")
                e.stdout = sha_output
                e.stderr = sha_error
                raise e

            calculated_sha = sha_output.split(' ')[0] # Get the hash value from sha256sum output
            self.sha_calculated.emit(calculated_sha, "usb")
            self.operation_finished.emit(True, translations[self.current_language]["sha256_calculated_success"], "sha_usb")

        except subprocess.CalledProcessError as e:
            full_stderr = e.stderr.strip() if e.stderr else ""
            full_stdout = e.stdout.strip() if e.stdout else ""

            error_details_parts = []
            if full_stderr:
                error_details_parts.append(f"STDERR:\n{full_stderr}")
            if full_stdout:
                error_details_parts.append(f"STDOUT:\n{full_stdout}")

            if not error_details_parts:
                error_details = translations[self.current_language]["no_error_details_found"]
            else:
                error_details = "\n".join(error_details_parts)

            error_msg = translations[self.current_language]["sha256_calc_device_error"].format(error_details)
            self.operation_finished.emit(False, error_msg, "sha_usb")
        except FileNotFoundError:
            self.operation_finished.emit(False, translations[self.current_language]["read_usb_error"].format("dd or sha256sum not found."), "sha_usb")
        except Exception as e:
            self.operation_finished.emit(False, translations[self.current_language]["unexpected_error"].format(str(e)), "sha_usb")


    def _bytes_to_human_readable(self, num_bytes):
        """
        Converts a number of bytes into a human-readable string (e.g., "1.23 GB").

        Args:
            num_bytes (int): The number of bytes to convert.

        Returns:
            str: Human-readable size string.
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if num_bytes < 1024.0:
                return f"{num_bytes:.2f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.2f} PB"


class HelwanUSBWriter(QWidget):
    """
    Main application window for the Helwan USB Writer.

    Provides a graphical user interface for selecting an ISO file,
    choosing a USB device, writing the ISO to the USB, and verifying
    the integrity using SHA256 checksums. Supports multiple languages (Arabic/English).
    """
    def __init__(self):
        """
        Initializes the HelwanUSBWriter application window.
        Sets up the UI, connects signals, and detects initial USB devices.
        """
        super().__init__()
        self.current_language = "ar" # Default language to Arabic
        self.iso_path = None
        self.usb_devices = {} # {description: path}
        self.selected_usb_device_path = None
        self.worker_thread = None
        self.is_operation_in_progress = False # Flag to disable UI during operations
        self._usb_calculated_sha = None # Stores SHA for USB after write/verify

        # Set window properties
        # Make sure 'icons' folder exists in the same directory as this script
        # and 'halwanmark.png' is inside it. Or update path to 'usb.png' if that's the icon.
        self.setWindowIcon(QIcon("icons/halwanmark.png"))
        self.setWindowTitle(translations[self.current_language]["app_title_usb"])
        self.setGeometry(100, 100, 800, 600) # Initial window size and position

        self._create_widgets()
        self._create_layouts()
        self._connect_signals()
        self._detect_usb_devices() # Initial USB device detection
        self._update_ui_texts() # Apply initial language settings and UI texts

    def _create_widgets(self):
        """
        Creates and initializes all PyQt widgets used in the application UI.
        """
        # Language selection
        self.language_combo = QComboBox()
        self.language_combo.addItem("English", "en")
        self.language_combo.addItem("العربية", "ar")
        self.language_combo.setCurrentText("العربية") # Set default to Arabic visually

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
        self.current_action_label = QLabel(translations[self.current_language]["action_idle"])
        self.current_action_label.setStyleSheet("font-weight: bold; color: blue;")


    def _create_layouts(self):
        """
        Arranges widgets into layouts for the main application window.
        """
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
        """
        Connects UI widget signals to their respective slot functions.
        """
        self.language_combo.currentIndexChanged.connect(self._change_language)
        self.browse_iso_button.clicked.connect(self._browse_iso_file)
        self.calculate_sha256_button.clicked.connect(self._calculate_iso_sha256)
        self.usb_refresh_button.clicked.connect(self._detect_usb_devices)
        self.usb_combo.currentIndexChanged.connect(self._usb_selection_changed)
        self.write_button.clicked.connect(self._start_write_process)
        self.setAcceptDrops(True) # Enable drag and drop for the main window

    def _change_language(self):
        """
        Changes the application's language based on the selected item in the language combo box
        and updates all UI texts.
        """
        lang = self.language_combo.currentData()
        if lang:
            self.current_language = lang
            self._update_ui_texts()

    def _update_ui_texts(self):
        """
        Updates all text elements in the UI to the currently selected language.
        This method is called when the language is changed.
        """
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
            # Re-populate USB combo to update display strings if language affects them
            current_selected_text = self.usb_combo.currentText()
            self._detect_usb_devices() # This will refresh and re-select based on paths
            # Attempt to re-select the previously selected item
            idx = self.usb_combo.findText(current_selected_text)
            if idx >= 0:
                self.usb_combo.setCurrentIndex(idx)


        self.full_format_checkbox.setText(translations[self.current_language]["format_usb_full_option"])
        self.write_button.setText(translations[self.current_language]["write_to_usb"])
        # Status and current action labels are updated by signals, but set default idle if not in progress
        if not self.is_operation_in_progress:
            self.status_label.setText(translations[self.current_language]["ready_to_start"])
            self.current_action_label.setText(translations[self.current_language]["action_idle"])
        
        self.set_direction() # Apply text direction based on selected language


    def set_direction(self):
        """
        Sets the layout direction (LeftToRight or RightToLeft) based on the current language.
        """
        if self.current_language == "ar":
            self.layout().setContentsMargins(20, 20, 20, 20)
            self.layout().setSpacing(10)
            self.setLayoutDirection(Qt.RightToLeft)
        else:
            self.layout().setContentsMargins(20, 20, 20, 20)
            self.layout().setSpacing(10)
            self.setLayoutDirection(Qt.LeftToRight)


    def _check_write_button_state(self):
        """
        Enables or disables the 'Write to USB' button based on whether an ISO file
        and a USB device are selected, and if no operation is currently in progress.
        Also performs a basic size compatibility check.
        """
        iso_selected = self.iso_path is not None and os.path.exists(self.iso_path) and os.path.getsize(self.iso_path) > 0
        usb_selected = self.selected_usb_device_path is not None

        if iso_selected and usb_selected and not self.is_operation_in_progress:
            # Basic size check: Warn if ISO is larger than USB
            try:
                iso_size = os.path.getsize(self.iso_path)
                # Parse USB size from its display string
                usb_display_text = self.usb_combo.currentText()
                usb_size_bytes = self._parse_human_readable_size_display(usb_display_text, return_bytes=True)

                if iso_size > usb_size_bytes and usb_size_bytes > 0:
                    self._show_message(translations[self.current_language]["error"], translations[self.current_language]["insufficient_usb_space_critical"].format(self._bytes_to_human_readable(iso_size), self._bytes_to_human_readable(usb_size_bytes)), "error")
                    self.write_button.setEnabled(False)
                    return
            except ValueError:
                # If USB size parsing fails, keep button disabled
                self.write_button.setEnabled(False)
                return
            except Exception as e:
                # Catch any other unexpected errors during size check
                self._show_message(translations[self.current_language]["error"], translations[self.current_language]["unexpected_error"].format(f"Size check error: {str(e)}"), "error")
                self.write_button.setEnabled(False)
                return

            self.write_button.setEnabled(True)
            self.status_label.setText(translations[self.current_language]["ready_to_start"])
        else:
            self.write_button.setEnabled(False)
            if not self.is_operation_in_progress:
                self.status_label.setText(translations[self.current_language]["ready_to_start"])


    def _browse_iso_file(self):
        """
        Opens a file dialog for the user to select an ISO file.
        Updates the UI with the selected file's path and size.
        """
        if self.is_operation_in_progress: return # Prevent action if operation is running

        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, translations[self.current_language]["open_iso_file"], "", "ISO Files (*.iso);;All Files (*)", options=options)
        if file_path:
            self.iso_path = file_path
            try:
                iso_size = os.path.getsize(self.iso_path)
                if iso_size == 0:
                    self._show_message(translations[self.current_language]["warning"], translations[self.current_language]["iso_size_zero"], "warning")
                    self.iso_path = None # Invalidate selection
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

        self._check_write_button_state() # Update button state based on new selection

    def _calculate_iso_sha256(self):
        """
        Starts a worker thread to calculate the SHA256 checksum of the selected ISO file.
        Disables UI elements during calculation.
        """
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
        self.worker_thread = Worker(
            operation_type="calculate_sha_iso",
            iso_path=self.iso_path,
            current_language=self.current_language
        )
        self.worker_thread.progress_updated.connect(self._update_progress_sha)
        # Directly update the SHA display once calculated
        self.worker_thread.sha_calculated.connect(lambda sha, type: self.calculated_sha256_display.setText(sha))
        self.worker_thread.operation_finished.connect(self._sha_calculation_finished)
        self.worker_thread.error_occurred.connect(self._handle_error)
        self.worker_thread.start()


    def _detect_usb_devices(self):
        """
        Detects and lists available USB devices on the system using 'lsblk' (Linux only).
        Populates the USB device combo box.
        """
        if self.is_operation_in_progress: return
        self.usb_combo.clear() # Clear existing items
        self.usb_devices.clear() # Clear internal dictionary
        self.selected_usb_device_path = None
        self.usb_details_display.setText(translations[self.current_language]["usb_details_placeholder"])
        self.write_button.setEnabled(False) # Disable write button until selection

        if not sys.platform.startswith('linux'):
            # Display a message indicating OS limitation
            self.usb_combo.addItem(translations[self.current_language]["no_usb_found"] + " (Linux only)", None)
            self.usb_combo.setEnabled(False)
            return

        try:
            # Use lsblk to list block devices, excluding loop devices, showing path, size, model
            # -b: bytes, -n: no headers, -p: full path, -d: devices only, -o: output columns
            stdout, stderr = subprocess.Popen(
                ["lsblk", "-b", "-n", "-p", "-d", "-o", "NAME,SIZE,MODEL"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            ).communicate()

            if stderr: # lsblk might print warnings to stderr even if it succeeds
                # self._show_message(translations[self.current_language]["warning"], translations[self.current_language]["lsblk_warning"].format(stderr.strip()), "warning")
                pass # Suppress lsblk stderr warnings for now, as it might still produce valid output

            lines = stdout.strip().split('\n')
            found_usb = False
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 3:
                    device_path = parts[0]
                    device_size = int(parts[1]) if parts[1].isdigit() else 0
                    device_model = " ".join(parts[2:])

                    # Heuristic to identify removable USB devices
                    # Check for devices starting with /dev/sd (common for USB/SATA)
                    # And ensure they are marked as removable in /sys/block
                    sys_removable_path = f"/sys/block/{os.path.basename(device_path)}/removable"
                    if os.path.exists(sys_removable_path):
                        with open(sys_removable_path, 'r') as f:
                            if f.read().strip() == '1': # '1' means removable
                                description = f"{device_model} ({self._bytes_to_human_readable(device_size)}) - {device_path}"
                                self.usb_devices[description] = device_path
                                self.usb_combo.addItem(description, device_path)
                                found_usb = True
            
            if not found_usb:
                self.usb_combo.addItem(translations[self.current_language]["no_usb_found"], None)
                self.usb_combo.setEnabled(False)
            else:
                self.usb_combo.setEnabled(True)
                # Add a placeholder item at the beginning
                self.usb_combo.insertItem(0, translations[self.current_language]["select_usb_device_option"], None)
                self.usb_combo.setCurrentIndex(0) # Select the placeholder initially

        except FileNotFoundError:
            self._show_message(translations[self.current_language]["error"], translations[self.current_language]["lsblk_not_found"], "error")
            self.usb_combo.addItem(translations[self.current_language]["no_usb_found"], None)
            self.usb_combo.setEnabled(False)
        except Exception as e:
            self._show_message(translations[self.current_language]["error"], translations[self.current_language]["lsblk_parse_error"].format(str(e)), "error")
            self.usb_combo.addItem(translations[self.current_language]["no_usb_found"], None)
            self.usb_combo.setEnabled(False)

        self._check_write_button_state() # Update button state after device detection

    def _usb_selection_changed(self):
        """
        Updates the selected USB device path and details display when a new item
        is selected in the USB combo box.
        """
        selected_data = self.usb_combo.currentData()
        if selected_data:
            self.selected_usb_device_path = selected_data
            self.usb_details_display.setText(self.usb_combo.currentText())
        else:
            self.selected_usb_device_path = None
            self.usb_details_display.setText(translations[self.current_language]["usb_details_placeholder"])
        self._check_write_button_state() # Update button state after selection

    def _start_write_process(self):
        """
        Initiates the ISO writing process.
        Performs pre-checks, asks for user confirmation, and then either
        starts formatting (if checked) or directly proceeds to writing.
        """
        if self.is_operation_in_progress: return

        if not self.iso_path or not os.path.exists(self.iso_path):
            self._show_message(translations[self.current_language]["warning"], translations[self.current_language]["no_iso_selected"], "warning")
            return
        if not self.selected_usb_device_path:
            self._show_message(translations[self.current_language]["warning"], translations[self.current_language]["no_usb_device_selected"], "warning")
            return

        iso_basename = os.path.basename(self.iso_path)
        usb_desc = self.usb_combo.currentText()
        usb_size_display = self._parse_human_readable_size_display(usb_desc)

        # Confirm before writing (DANGER ZONE!)
        confirm_msg = translations[self.current_language]["confirm_write_prompt"].format(
            iso_basename, self._bytes_to_human_readable(os.path.getsize(self.iso_path)),
            usb_desc, usb_size_display
        )
        if self.full_format_checkbox.isChecked():
            # Add specific warning for full format
            confirm_msg = translations[self.current_language]["confirm_format_warning"].format(usb_desc) + "\n\n" + confirm_msg

        reply = QMessageBox.question(self, translations[self.current_language]["confirm_write"], confirm_msg,
                                     QMessageBox.Yes | QMessageBox.No)

        if reply == QMessageBox.Yes:
            # Check SHA256 if expected value is provided AND a calculated value exists
            expected_sha = self.expected_sha256_input.text().strip().lower()
            calculated_sha = self.calculated_sha256_display.text().strip().lower()

            # If expected SHA is provided and does not match the calculated one, warn user
            if expected_sha and calculated_sha and expected_sha != calculated_sha and calculated_sha != translations[self.current_language]["sha256_calculation_failed_status"].lower():
                mismatch_reply = QMessageBox.question(self, translations[self.current_language]["warning"],
                                                     translations[self.current_language]["sha256_mismatch_proceed_prompt"],
                                                     QMessageBox.Yes | QMessageBox.No)
                if mismatch_reply == QMessageBox.No:
                    self._show_message(translations[self.current_language]["info"], translations[self.current_language]["operation_cancelled"], "info")
                    return # Stop if user cancels due to SHA mismatch

            # Proceed with format or direct write
            self._format_then_write_or_verify()
        else:
            self._show_message(translations[self.current_language]["info"], translations[self.current_language]["operation_cancelled"], "info")

    def _format_then_write_or_verify(self):
        """
        Determines the next step after user confirmation:
        Either start the full USB format, or proceed directly to writing the ISO.
        """
        if self.full_format_checkbox.isChecked():
            # Start format process in worker thread
            self._set_ui_busy(True, "format")
            self.worker_thread = Worker(
                operation_type="format",
                usb_device=self.selected_usb_device_path,
                current_language=self.current_language
            )
            self.worker_thread.progress_updated.connect(self._update_progress)
            self.worker_thread.operation_finished.connect(self._format_finished)
            self.worker_thread.error_occurred.connect(self._handle_error)
            self.worker_thread.start()
        else:
            # Skip format, directly start write process
            self._start_write_process_actual()

    def _start_write_process_actual(self):
        """
        Starts the actual ISO writing operation in a worker thread.
        This function is called after confirmation and (optional) formatting.
        """
        self._set_ui_busy(True, "write")
        self.worker_thread = Worker(
            operation_type="write",
            iso_path=self.iso_path,
            usb_device=self.selected_usb_device_path,
            current_language=self.current_language
        )
        self.worker_thread.progress_updated.connect(self._update_progress)
        self.worker_thread.operation_finished.connect(self._write_finished)
        self.worker_thread.error_occurred.connect(self._handle_error)
        self.worker_thread.start()


    def _set_ui_busy(self, busy, operation_type="idle"):
        """
        Sets the UI state to busy or idle, disabling/enabling relevant controls.

        Args:
            busy (bool): True to set busy state, False for idle.
            operation_type (str, optional): Describes the current operation ("write", "format", "calculate_sha_iso", "calculate_sha_usb", "idle"). Defaults to "idle".
        """
        self.is_operation_in_progress = busy
        # Disable/enable controls
        self.browse_iso_button.setEnabled(not busy)
        self.calculate_sha256_button.setEnabled(not busy)
        self.usb_refresh_button.setEnabled(not busy)
        self.usb_combo.setEnabled(not busy)
        self.full_format_checkbox.setEnabled(not busy)
        self.expected_sha256_input.setReadOnly(busy) # Allow editing only when idle

        # Update current action label
        if busy:
            self.write_button.setEnabled(False) # Always disable write button when busy
            if operation_type == "write":
                self.current_action_label.setText(translations[self.current_language]["action_writing"])
            elif operation_type == "format":
                self.current_action_label.setText(translations[self.current_language]["action_formatting"])
            elif operation_type.startswith("calculate_sha"):
                self.current_action_label.setText(translations[self.current_language]["action_verifying"])
        else:
            self.current_action_label.setText(translations[self.current_language]["action_idle"])
            self._check_write_button_state() # Re-enable write button if conditions met

        # Reset progress bar when going to busy state
        if busy:
            self.progress_bar.setValue(0)
            self.status_label.setText(translations[self.current_language]["ready_to_start"]) # Or a suitable initial status

    def _update_progress(self, value, message):
        """
        Updates the progress bar and status label with current progress.

        Args:
            value (int): Progress percentage (0-100).
            message (str): A descriptive message about the current progress.
        """
        self.progress_bar.setValue(value)
        self.status_label.setText(message)

    def _update_progress_sha(self, value, message):
        """
        Updates the progress bar and status label specifically for SHA calculation.
        Also updates the calculated SHA display during the process.

        Args:
            value (int): Progress percentage (0-100).
            message (str): A descriptive message about the current progress.
        """
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
        self.calculated_sha256_display.setText(translations[self.current_language]["calculating_sha256_status"])


    def _sha_calculation_finished(self, success, message, op_type):
        """
        Handles the completion of an SHA256 calculation operation for ISO.

        Args:
            success (bool): True if SHA calculation was successful.
            message (str): A message about the operation's outcome.
            op_type (str): The type of operation ("calculate_sha_iso").
        """
        self._set_ui_busy(False) # Set UI to idle
        if success:
            self.status_label.setText(translations[self.current_language]["sha256_calculated_success"])
            # SHA value is already set by worker_thread.sha_calculated signal
        else:
            self.status_label.setText(translations[self.current_language]["sha256_calculation_failed_status"])
            self.calculated_sha256_display.setText(translations[self.current_language]["sha256_calculation_failed_status"])
            if message:
                self._show_message(translations[self.current_language]["error"], message, "error")

        # Compare calculated with expected if both are present
        expected_sha = self.expected_sha256_input.text().strip().lower()
        calculated_sha = self.calculated_sha256_display.text().strip().lower()

        # Update style based on match/mismatch, unless calculation itself failed
        if expected_sha and calculated_sha and calculated_sha != translations[self.current_language]["sha256_calculation_failed_status"].lower():
            if expected_sha == calculated_sha:
                self.status_label.setText(translations[self.current_language]["sha256_match"])
                self.calculated_sha256_display.setStyleSheet("color: green; font-weight: bold;")
            else:
                self.status_label.setText(translations[self.current_language]["sha256_mismatch"])
                self.calculated_sha256_display.setStyleSheet("color: red; font-weight: bold;")
        else:
            self.calculated_sha256_display.setStyleSheet("") # Reset style if no comparison or failed


    def _format_finished(self, success, message, op_type):
        """
        Handles the completion of a USB formatting operation.

        Args:
            success (bool): True if formatting was successful.
            message (str): A message about the operation's outcome.
            op_type (str): The type of operation ("format").
        """
        if success:
            self._show_message(translations[self.current_language]["success"], message, "success")
            # After successful formatting, automatically proceed to write the ISO
            self._start_write_process_actual()
        else:
            self._set_ui_busy(False) # If format fails, go back to idle
            self._show_message(translations[self.current_language]["error"], message, "error")


    def _write_finished(self, success, message, op_type):
        """
        Handles the completion of the ISO writing operation.
        If successful, it initiates the SHA256 verification of the written USB.

        Args:
            success (bool): True if writing was successful.
            message (str): A message about the operation's outcome.
            op_type (str): The type of operation ("write").
        """
        if success:
            # After successful write, start SHA256 verification of the USB
            self.status_label.setText(translations[self.current_language]["verifying_sha256_post_write"])
            self._set_ui_busy(True, "calculate_sha_usb") # Keep UI busy during verification
            self.worker_thread = Worker(
                operation_type="calculate_sha_usb",
                iso_path=self.iso_path, # ISO path is needed to get the size for USB verification
                usb_device=self.selected_usb_device_path,
                current_language=self.current_language
            )
            self.worker_thread.progress_updated.connect(self._update_progress) # Progress updates for verification
            self.worker_thread.sha_calculated.connect(self._usb_sha_calculated) # Get the calculated USB SHA
            self.worker_thread.operation_finished.connect(self._usb_sha_verification_finished)
            self.worker_thread.error_occurred.connect(self._handle_error)
            self.worker_thread.start()
        else:
            self._set_ui_busy(False) # If write fails, go back to idle
            self._show_message(translations[self.current_language]["error"], message, "error")

    def _usb_sha_calculated(self, sha_value, type):
        """
        Slot to receive the calculated SHA256 value for the USB device from the worker.

        Args:
            sha_value (str): The calculated SHA256 hash.
            type (str): "usb" in this context.
        """
        self._usb_calculated_sha = sha_value

    def _usb_sha_verification_finished(self, success, message, op_type):
        """
        Handles the completion of the USB SHA256 verification process.
        Compares it with the ISO's SHA256 if available.

        Args:
            success (bool): True if verification was successful.
            message (str): A message about the operation's outcome.
            op_type (str): The type of operation ("calculate_sha_usb").
        """
        self._set_ui_busy(False) # UI back to idle
        original_iso_sha = self.calculated_sha256_display.text().strip().lower() # Get ISO's calculated SHA
        
        if success:
            if original_iso_sha and self._usb_calculated_sha:
                # Compare SHA if both are available
                if original_iso_sha == self._usb_calculated_sha:
                    self._show_message(translations[self.current_language]["success"], translations[self.current_language]["write_and_verify_successful"], "success")
                else:
                    self._show_message(translations[self.current_language]["warning"], translations[self.current_language]["write_successful_verify_failed"].format(original_iso_sha, self._usb_calculated_sha), "warning")
            else:
                 # If ISO SHA was not calculated or some info missing
                self._show_message(translations[self.current_language]["success"], translations[self.current_language]["write_successful"], "success")
        else:
            self._show_message(translations[self.current_language]["error"], message, "error")

        self._usb_calculated_sha = None # Reset for next operation


    def _handle_error(self, message):
        """
        A general error handler that displays an error message and sets the UI to idle.

        Args:
            message (str): The error message to display.
        """
        self._set_ui_busy(False)
        self._show_message(translations[self.current_language]["error"], message, "error")

    def _show_message(self, title, message, msg_type="info"):
        """
        Displays a QMessageBox to the user.

        Args:
            title (str): Title of the message box.
            message (str): Content message.
            msg_type (str, optional): Type of message ("info", "warning", "error"). Defaults to "info".
        """
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
        """
        Converts a number of bytes into a human-readable string (e.g., "1.23 GB").

        Args:
            num_bytes (int): The number of bytes to convert.

        Returns:
            str: Human-readable size string.
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if num_bytes < 1024.0:
                return f"{num_bytes:.2f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.2f} PB"

    def _parse_human_readable_size(self, size_str):
        """
        Parses a human-readable size string (e.g., "7.50 GB") into bytes.

        Args:
            size_str (str): The size string to parse.

        Returns:
            int: Size in bytes.

        Raises:
            ValueError: If the string format is invalid or unit is unknown.
        """
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

    def _parse_human_readable_size_display(self, display_str, return_bytes=False):
        """
        Extracts and parses size from a display string like "Model (7.50 GB) - /dev/sdx".

        Args:
            display_str (str): The full display string of the USB device.
            return_bytes (bool): If True, returns size in bytes; otherwise, returns human-readable string.

        Returns:
            str or int: Parsed size, either human-readable or in bytes.
        """
        try:
            start_index = display_str.find('(')
            end_index = display_str.find(')')
            if start_index != -1 and end_index != -1:
                size_part = display_str[start_index + 1 : end_index].strip()
                bytes_size = self._parse_human_readable_size(size_part)
                if return_bytes:
                    return bytes_size
                return self._bytes_to_human_readable(bytes_size)
            return "" if not return_bytes else 0
        except Exception:
            return "" if not return_bytes else 0

    def dragEnterEvent(self, event):
        """
        Handles drag enter events, accepting if URLs (files) are dragged.
        """
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        """
        Handles drop events, processing dropped .iso files.
        """
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
        """
        Handles the window close event. Asks for confirmation if an operation is in progress.
        """
        if self.is_operation_in_progress:
            reply = QMessageBox.question(self, translations[self.current_language]["warning"],
                                         translations[self.current_language]["cancel_running_operation"],
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                if self.worker_thread and self.worker_thread.isRunning():
                    self.worker_thread.cancel() # Request worker to cancel
                    self.worker_thread.wait(5000) # Give it a chance to terminate gracefully
                event.accept()
            else:
                event.ignore() # Prevent closing
        else:
            event.accept() # Allow closing


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = HelwanUSBWriter()
    window.show()
    sys.exit(app.exec_())
