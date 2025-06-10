# Helwan USB Writer

**Helwan USB Writer** is a graphical tool built with PyQt5 for writing ISO images to USB drives, 
verifying their SHA256 checksums, and optionally formatting the USB device beforehand.

This project is designed with multi-language support (Arabic 🇪🇬 and English 🇬🇧) and focuses on reliability, 
safety, and a user-friendly interface for both beginners and advanced users.

## ✨ Features

- ✅ ISO to USB writing using `dd` (Linux only).
- ✅ Full USB format with partition table reset (FAT32).
- ✅ SHA256 calculation for ISO and USB (post-write).
- ✅ Language switching (Arabic and English).
- ✅ Real-time progress updates with detailed messages.
- ✅ Safe unmounting and error handling.
- ✅ Drag and drop ISO file support.

## 🧰 Requirements

- Python 3.6+
- Linux OS (Ubuntu, Debian, Arch, etc.)
- `sudo` access (for disk operations)
- Dependencies:
  ```bash
  pip install PyQt5
  ```

- System utilities required:
  - `dd`, `lsblk`, `parted`, `mkfs.fat`, `wipefs`, `sha256sum`

## 🚀 Running the App

```bash
python3 main_usb_writer.py
```

## 📁 Structure

- `main_usb_writer.py` — Main application code with GUI and backend logic.
- `translations.py` — Language dictionary for UI translation.
- `icons/usb.png` — App icon (ensure it exists).
- `README.md` — This file.

## 🛡️ Notes

- **Linux-only**: This tool is designed for Linux. Windows/macOS support is not available due to reliance on `dd` and other Linux utilities.
- **Admin Access**: Make sure you run this with proper permissions (`sudo`) when needed.
- **USB Data Loss**: This app performs destructive operations on USB drives. Backup your data first.

## 📜 License

MIT License — Free to use and modify.

## 👤 Author

Made with ❤️ by **Saeed Badrelden**
