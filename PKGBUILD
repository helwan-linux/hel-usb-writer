# Maintainer: Your Name <your.email@example.com>
pkgname=hel-usb-writer
pkgver=0.1 # تم التغيير إلى 0.1 لأنه لا يوجد إصدار v1.0.0 على GitHub، هذا للاصدارات التجريبية
pkgrel=1
pkgdesc="A simple tool to write ISO images to USB drives with checksum verification."
arch=('x86_64')
url="https://github.com/helwan-linux/$pkgname" # رابط مشروعك على GitHub
license=('MIT') # يرجى التأكد من أنك تستخدم ترخيص MIT أو قم بتغييره حسب ترخيص مشروعك

# التبعيات (البرامج الأخرى التي يحتاجها تطبيقك للعمل)
depends=('python' 'python-pyqt5' 'coreutils' 'util-linux' 'polkit')

# المصدر: رابط ملف tarball للفرع الرئيسي (main) من GitHub
# هذا الرابط هو الذي يعمل دائمًا لمحتويات الفرع الرئيسي
source=("https://github.com/helwan-linux/$pkgname/archive/main.tar.gz")
sha256sums=('SKIP') # استخدم 'SKIP' إذا كنت لا ترغب في التحقق من التجزئة، أو قم بتوليدها لاحقاً

# دالة build(): لا تحتاج عادةً لشيء لسكربتات بايثون البسيطة
build() {
  return 0
}

# دالة package(): تقوم بتثبيت الملفات إلى هيكل الدليل الوهمي (pkgdir)
package() {
  # إنشاء مجلدات الوجهة المطلوبة
  install -d "$pkgdir/usr/bin/"
  install -d "$pkgdir/usr/share/pixmaps/"
  install -d "$pkgdir/usr/share/applications/"

  # تثبيت سكربت البايثون وجعله قابلاً للتنفيذ
  # المسار الصحيح: $srcdir/hel-usb-writer-main/HelwanUSBWriter/helwan_usb_writer.py
  # (حيث 'hel-usb-writer-main' هو المجلد الذي يتم فك ضغط المصدر فيه من GitHub's main branch tarball)
  install -m 755 "$srcdir/$pkgname-main/HelwanUSBWriter/helwan_usb_writer.py" "$pkgdir/usr/bin/helwan_usb_writer.py"

  # تثبيت الأيقونة
  # المسار الصحيح: $srcdir/hel-usb-writer-main/HelwanUSBWriter/helwan-usb.png
  install -m 644 "$srcdir/$pkgname-main/HelwanUSBWriter/helwan-usb.png" "$pkgdir/usr/share/pixmaps/helwan-usb.png"

  # إنشاء ملف .desktop مباشرة داخل دالة package()
  cat > "$pkgdir/usr/share/applications/helwan_usb_iso_writer.desktop" << EOF
[Desktop Entry]
Name=Helwan USB ISO Writer
Comment=A simple tool to write ISO images to USB drives
Exec=sh -c "python3 /usr/bin/helwan_usb_writer.py"
Icon=/usr/share/pixmaps/helwan-usb.png
Terminal=false
Type=Application
Categories=System;Utility;
Keywords=usb;iso;writer;bootable;checksum;
StartupNotify=true
EOF
}
