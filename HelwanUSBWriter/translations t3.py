translations = {
    "en": {
        "app_title_usb": "Helwan USB Writer",
        "selected_iso_file": "Selected ISO File:", # تم تعديله ليصبح أكثر وصفًا
        "browse": "Browse...",
        "calculate_sha256": "Calculate SHA256",
        "expected_sha256_label": "Expected SHA256:", # جديد
        "expected_sha256_placeholder": "Enter expected SHA256 checksum (optional)", # جديد
        "calculated_sha256_label": "Calculated SHA256:", # جديد
        "calculated_sha256_placeholder": "Calculated SHA256 will appear here", # تم تعديله
        "select_usb_device": "Select USB Device:",
        "refresh": "Refresh",
        "write_to_usb": "Write to USB",
        "ready_to_start": "Ready to start.",
        "warning": "Warning",
        "error": "Error",
        "success": "Success",
        "failed": "Failed",
        "no_iso_selected": "Please select an ISO file.",
        "no_usb_device_selected": "Please select a USB device.",
        "confirm_write_prompt": "Are you sure you want to write '{}' ({}) to '{}' ({})?\n\n"
                                "ALL DATA ON THE USB DEVICE WILL BE PERMANENTLY ERASED!\n"
                                "This action cannot be undone. Proceed with caution.", # رسالة تحذير أقوى
        "confirm_write": "Confirm Write",
        "preparing_to_write": "Preparing to write to {}...",
        "write_successful": "ISO written successfully!",
        "write_failed": "Failed to write ISO: {}",
        "dd_not_found": "'dd' command not found. Please ensure it's installed and in your PATH.",
        "lsblk_not_found": "'lsblk' command not found. Please ensure it's installed and in your PATH.",
        "lsblk_parse_error": "Failed to parse lsblk output. Please check your system configuration.",
        "unknown_error": "An unknown error occurred during writing.",
        "unexpected_error": "An unexpected error occurred: {}",
        "subprocess_error": "Subprocess command failed: '{}' with exit code {} and error: {}", # جديد
        "starting_write": "Starting write process...",
        "no_usb_found": "No USB devices found.",
        "select_usb_device_option": "--- Select a USB device ---",
        "no_usb_selected_option": "--- No USB selected ---",
        "cancel_running_operation": "A write operation is in progress. Do you want to cancel it and exit?",
        "calculating_sha256": "Calculating SHA256...",
        "calculating_progress": "Calculating SHA256: {}%", # جديد
        "sha256_calculated_success": "SHA256 calculated successfully.",
        "sha256_calculation_failed": "SHA256 calculation failed.",
        "sha256_calculation_failed_status": "SHA256 calculation failed!", # جديد
        "no_iso_selected_sha256": "Please select an ISO file before calculating SHA256.",
        "iso_not_found_sha256": "ISO file not found for SHA256 calculation.",
        "sha256_calc_error": "Error calculating SHA256: {}",
        "iso_size_zero": "Selected ISO file has a size of 0 bytes. Please select a valid ISO.",
        "operation_cancelled": "Operation cancelled by user.",
        "open_iso_file": "Open ISO File",
        "iso_details_placeholder": "No ISO selected. Details will appear here.", # جديد
        "iso_details": "Selected: {} (Size: {})", # جديد
        "usb_details_placeholder": "No USB device selected. Details will appear here.", # جديد
        "insufficient_usb_space": "Insufficient space! ISO ({}) is larger than USB device ({}).", # جديد
        "insufficient_usb_space_critical": "Error: ISO ({}) is larger than the selected USB device ({}). Please choose a larger USB.", # جديد للرسالة الحرجة
        "sha256_match": "SHA256 checksums match!", # جديد
        "sha256_mismatch": "SHA256 checksums MISMATCH!", # جديد
        "sha256_mismatch_proceed_prompt": "Calculated SHA256 does NOT match the expected value.\n\n"
                                        "Proceeding may result in a corrupted USB. Do you still want to continue?", # جديد
        "calculating_sha256_status": "Calculating..." # جديد
    },
    "ar": {
        "app_title_usb": "كاتب حلوان USB",
        "selected_iso_file": "ملف ISO المختار:", # تم تعديله
        "browse": "استعراض...",
        "calculate_sha256": "حساب SHA256",
        "expected_sha256_label": "SHA256 المتوقع:", # جديد
        "expected_sha256_placeholder": "أدخل مجموع التحقق SHA256 المتوقع (اختياري)", # جديد
        "calculated_sha256_label": "SHA256 المحسوب:", # جديد
        "calculated_sha256_placeholder": "سيظهر هنا مجموع التحقق SHA256 المحسوب", # تم تعديله
        "select_usb_device": "اختر جهاز USB:",
        "refresh": "تحديث",
        "write_to_usb": "كتابة إلى USB",
        "ready_to_start": "جاهز للبدء.",
        "warning": "تحذير",
        "error": "خطأ",
        "success": "نجاح",
        "failed": "فشل",
        "no_iso_selected": "الرجاء اختيار ملف ISO.",
        "no_usb_device_selected": "الرجاء اختيار جهاز USB.",
        "confirm_write_prompt": "هل أنت متأكد أنك تريد كتابة '{}' ({}) إلى '{}' ({})؟\n\n"
                                "جميع البيانات الموجودة على جهاز USB سيتم مسحها نهائياً!\n"
                                "لا يمكن التراجع عن هذا الإجراء. يرجى المتابعة بحذر.", # رسالة تحذير أقوى
        "confirm_write": "تأكيد الكتابة",
        "preparing_to_write": "جاري التحضير للكتابة إلى {}...",
        "write_successful": "تمت كتابة ISO بنجاح!",
        "write_failed": "فشل في كتابة ISO: {}",
        "dd_not_found": "أمر 'dd' غير موجود. يرجى التأكد من تثبيته ومساره.",
        "lsblk_not_found": "أمر 'lsblk' غير موجود. يرجى التأكد من تثبيته ومساره.",
        "lsblk_parse_error": "فشل في تحليل إخراج lsblk. يرجى التحقق من إعدادات النظام.",
        "unknown_error": "حدث خطأ غير معروف أثناء الكتابة.",
        "unexpected_error": "حدث خطأ غير متوقع: {}",
        "subprocess_error": "فشل أمر العملية الفرعية: '{}' برمز خروج {} وخطأ: {}", # جديد
        "starting_write": "بدء عملية الكتابة...",
        "no_usb_found": "لم يتم العثور على أجهزة USB.",
        "select_usb_device_option": "--- اختر جهاز USB ---",
        "no_usb_selected_option": "--- لم يتم اختيار USB ---",
        "cancel_running_operation": "توجد عملية كتابة قيد التقدم. هل تريد إلغاءها والخروج؟",
        "calculating_sha256": "جاري حساب SHA256...",
        "calculating_progress": "جاري الحساب SHA256: {}%", # جديد
        "sha256_calculated_success": "تم حساب SHA256 بنجاح.",
        "sha256_calculation_failed": "فشل حساب SHA256.",
        "sha256_calculation_failed_status": "فشل حساب SHA256!", # جديد
        "no_iso_selected_sha256": "الرجاء اختيار ملف ISO قبل حساب SHA256.",
        "iso_not_found_sha256": "ملف ISO غير موجود لحساب SHA256.",
        "sha256_calc_error": "خطأ في حساب SHA256: {}",
        "iso_size_zero": "حجم ملف ISO المختار هو 0 بايت. الرجاء اختيار ملف ISO صالح.",
        "operation_cancelled": "تم إلغاء العملية بواسطة المستخدم.",
        "open_iso_file": "فتح ملف ISO",
        "iso_details_placeholder": "لم يتم اختيار ملف ISO. ستظهر التفاصيل هنا.", # جديد
        "iso_details": "المختار: {} (الحجم: {})", # جديد
        "usb_details_placeholder": "لم يتم اختيار جهاز USB. ستظهر التفاصيل هنا.", # جديد
        "insufficient_usb_space": "مساحة غير كافية! حجم ISO ({}) أكبر من جهاز USB ({}).", # جديد
        "insufficient_usb_space_critical": "خطأ: حجم ISO ({}) أكبر من جهاز USB المختار ({}). الرجاء اختيار USB أكبر حجماً.", # جديد للرسالة الحرجة
        "sha256_match": "تطابق مجموعات التحقق SHA256!", # جديد
        "sha256_mismatch": "عدم تطابق مجموعات التحقق SHA256!", # جديد
        "sha256_mismatch_proceed_prompt": "مجموع التحقق SHA256 المحسوب لا يتطابق مع القيمة المتوقعة.\n\n"
                                        "قد يؤدي المتابعة إلى تلف USB. هل ما زلت تريد المتابعة؟", # جديد
        "calculating_sha256_status": "جاري الحساب..." # جديد
    }
}
