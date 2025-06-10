# Maintainer: Saeed Badrelden <saeedbadrelden2021@gmail.com>
pkgname=hel-usb-writer
pkgver=1.0.0 # Please update this version manually or use dynamic versioning if needed
pkgrel=1
pkgdesc="A powerful tool for writing ISO files to USB drives."
arch=('any')
url="https://github.com/helwan-linux/hel-usb-writer"
license=('MIT') # Verify the actual project license and update if necessary
depends=('python' 'python-pyqt5') # Core dependencies
makedepends=('git') # Required to clone the repository

# Source the latest code from the main branch of the GitHub repository
# For specific versions, you might use:
# source=("${pkgname}-${pkgver}.tar.gz::${url}/archive/refs/tags/v${pkgver}.tar.gz")
source=("git+${url}.git")
sha256sums=('SKIP') # Use SKIP for git sources, or a calculated sum for tarballs

build() {
  # Navigate into the cloned repository directory
  # The directory name will be the last part of the URL, e.g., 'hel-usb-writer'
  cd "${srcdir}/${pkgname}"

  # No specific build steps are typically required for simple Python applications
  # However, if you had complex build steps (e.g., compiling C extensions), they would go here.
}

package() {
  # Define the target installation directory for the application's files
  # This will be /usr/share/hel-usb-writer/ on the installed system
  install_dir="${pkgdir}/usr/share/${pkgname}"

  # Create necessary directories within the package root
  install -d "${pkgdir}/usr/bin/" # For the main executable symlink
  install -d "${install_dir}/"    # For the application's Python files and icons
  install -d "${pkgdir}/usr/share/applications/" # For the .desktop file
  install -d "${pkgdir}/usr/share/icons/hicolor/scalable/apps/" # Standard path for scalable app icons

  # --- Install Application Files ---
  # Copy the main Python script
  cp "${srcdir}/${pkgname}/main_usb_writer.py" "${install_dir}/"
  # Copy the translations file
  cp "${srcdir}/${pkgname}/translations.py" "${install_dir}/"

  # Copy the icons directory and its contents
  # Ensure the 'icons' directory exists in the source before attempting to copy
  if [ -d "${srcdir}/${pkgname}/icons" ]; then
    cp -r "${srcdir}/${pkgname}/icons" "${install_dir}/"
    # Copy the specific 'usb.png' icon to the standard system icon path
    # and rename it to match the pkgname for consistent lookup by desktop environments
    install -Dm644 "${srcdir}/${pkgname}/icons/usb.png" "${pkgdir}/usr/share/icons/hicolor/scalable/apps/${pkgname}.png"
  else
    echo "Warning: 'icons' directory not found in the source repository. Application icon might not be displayed correctly."
  fi


  # --- Create Executable Symlink ---
  # Create a symbolic link in /usr/bin/ that points to the main script
  # This allows the application to be run simply by typing 'hel-usb-writer' in the terminal
  # and also makes it discoverable by desktop environments.
  ln -sf "/usr/share/${pkgname}/main_usb_writer.py" "${pkgdir}/usr/bin/${pkgname}"

  # Set execute permissions for the main Python script
  # This is crucial for the script to be runnable.
  chmod +x "${install_dir}/main_usb_writer.py"

  # --- Create and Install the .desktop file ---
  # Generate the .desktop file content directly into the target directory
  # The paths inside this file MUST be absolute system paths,
  # pointing to where the executable and icon will be installed.
  cat > "${pkgdir}/usr/share/applications/${pkgname}.desktop" << EOF
[Desktop Entry]
Name=Helwan USB Writer
Comment=A powerful tool for writing ISO files to USB drives.
Exec=/usr/bin/${pkgname}
Icon=/usr/share/icons/hicolor/scalable/apps/${pkgname}.png
Terminal=false
Type=Application
Categories=Utility;System;
Keywords=USB;ISO;Writer;Bootable;Helwan;
StartupNotify=true
EOF

  # Set appropriate permissions for the .desktop file
  chmod 644 "${pkgdir}/usr/share/applications/${pkgname}.desktop"
}