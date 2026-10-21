"""Purple-team simulation catalogue.

Each scenario describes an emulated adversary behaviour and the telemetry a
defensive team would need to observe it.  Simulations never touch a real
target: they ask whether the detections configured in the project would fire
on the described telemetry.  The expected signals are matched against the
project's own detection rules, so the result reflects real configuration
rather than a scripted "pass".
"""

from __future__ import annotations

from typing import Any

SCENARIOS: tuple[dict[str, Any], ...] = (
    {
        "key": "credential_stuffing",
        "title_en": "Credential stuffing against an internet-facing login",
        "title_ar": "هجوم تخمين بيانات الاعتماد ضد تسجيل دخول على الإنترنت",
        "division": "offense",
        "technique": "T1110.004",
        "severity": "high",
        "description_en": (
            "An attacker replays breached username/password pairs against a public "
            "authentication endpoint. The defender needs failed-login telemetry, "
            "source-IP reputation and a rate-limit signal."
        ),
        "description_ar": (
            "يعيد المهاجم بيانات اعتماد مسربة إلى نقطة مصادقة عامة. يحتاج المدافع إلى "
            "سجل فشل الدخول وسمعة عنوان المصدر وإشارة تجاوز الحد."
        ),
        "expected_telemetry": [
            {"signal": "auth_failure", "field": "message", "pattern": "(?i)(failed login|authentication failure|invalid password)"},
            {"signal": "volume_spike", "field": "src_ip", "pattern": "(?i)(src_ip)"},
            {"signal": "user_enumeration", "field": "url", "pattern": "(?i)(login|signin|auth)"},
        ],
        "expected_detections": ["brute force", "credential stuffing", "failed login"],
        "defensive_note_en": "Bind account lockout thresholds and alert on authentication failure bursts.",
        "defensive_note_ar": "اربط حدود قفل الحساب وتنبيه عند تكرار فشل المصادقة.",
    },
    {
        "key": "living_off_the_land",
        "title_en": "Living-off-the-land execution with signed tooling",
        "title_ar": "تنفيذ باستخدام أدوات نظام موقّعة (Living off the Land)",
        "division": "offense",
        "technique": "T1218",
        "severity": "high",
        "description_en": (
            "An adversary uses built-in Windows binaries (PowerShell, certutil, mshta) "
            "to download and execute payloads without dropping a file to disk."
        ),
        "description_ar": (
            "يستخدم المهاجم أدوات ويندوز المدمجة مثل PowerShell وcertutil لتنزيل وتشغيل "
            "حمولة دون كتابة ملف على القرص."
        ),
        "expected_telemetry": [
            {"signal": "script_host", "field": "message", "pattern": "(?i)(powershell|pwsh|certutil|mshta|wmic|rundll32)"},
            {"signal": "encoded_command", "field": "message", "pattern": "(?i)(-enc\\s|-encodedcommand|frombase64string)"},
            {"signal": "network_download", "field": "url", "pattern": "(?i)(http|https)"},
        ],
        "expected_detections": ["powershell", "lolbin", "encoded command"],
        "defensive_note_en": "Constrain script-block logging and alert on encoded command lines.",
        "defensive_note_ar": "فعّل تسجيل كتل السكربتات ونبّه على أسطر الأوامر المشفّرة.",
    },
    {
        "key": "ransomware_staging",
        "title_en": "Ransomware staging and mass file rename",
        "title_ar": "تجهيز الفدية وإعادة تسمية الملفات",
        "division": "forensics",
        "technique": "T1486",
        "severity": "critical",
        "description_en": (
            "An actor stages data, disables recovery and begins bulk file renames. "
            "Detection relies on mass rename operations, shadow-copy deletion and "
            "entropy change in file names."
        ),
        "description_ar": (
            "يجهّز الفاعل البيانات ويعطّل الاستعادة ويبدأ إعادة تسمية الملفات. "
            "يعتمد الكشف على عمليات إعادة التسمية الجماعية وحذف نسخ الظل."
        ),
        "expected_telemetry": [
            {"signal": "shadow_copy_deleted", "field": "message", "pattern": "(?i)(vssadmin|shadowcopy|wmic shadowcopy|bcdedit)"},
            {"signal": "mass_rename", "field": "message", "pattern": "(?i)(rename|\\.encrypted|\\.locked)"},
            {"signal": "service_stopped", "field": "message", "pattern": "(?i)(stopped service|net stop)"},
        ],
        "expected_detections": ["ransomware", "shadow copy", "mass modification"],
        "defensive_note_en": "Alert on shadow-copy deletion and on high-rate file modification.",
        "defensive_note_ar": "نبّه على حذف نسخ الظل وعلى معدل تعديل الملفات المرتفع.",
    },
    {
        "key": "phishing_delivery",
        "title_en": "Credential phishing through a spoofed login page",
        "title_ar": "تصيّد بيانات الاعتماد عبر صفحة تسجيل دخول مزيّفة",
        "division": "offense",
        "technique": "T1566.002",
        "severity": "medium",
        "description_en": (
            "A malicious message leads to a look-alike authentication page. "
            "The signal is a link from mail to a newly registered domain that "
            "immediately collects credentials."
        ),
        "description_ar": (
            "رسالة خبيثة تقود إلى صفحة تسجيل دخول شبيهة. المؤشر هو رابط من البريد "
            "إلى نطاق حديث التسجيل يجمع بيانات الاعتماد فوراً."
        ),
        "expected_telemetry": [
            {"signal": "mail_link", "field": "message", "pattern": "(?i)(href=|<a\\s)"},
            {"signal": "credential_form", "field": "url", "pattern": "(?i)(login|signin|verify|secure|account)"},
            {"signal": "lookalike_domain", "field": "url", "pattern": "(?i)(http)"},
        ],
        "expected_detections": ["phishing", "suspicious url", "credential"],
        "defensive_note_en": "Combine mail-link extraction with newly-registered domain intelligence.",
        "defensive_note_ar": "اجمع استخراج روابط البريد مع ذكاء النطاقات حديثة التسجيل.",
    },
    {
        "key": "lateral_movement_smb",
        "title_en": "Lateral movement over SMB and remote service creation",
        "title_ar": "حركة جانبية عبر SMB وإنشاء خدمة عن بُعد",
        "division": "forensics",
        "technique": "T1021.002",
        "severity": "high",
        "description_en": (
            "A foothold account authenticates to a second host over SMB and creates "
            "a remote service. The evidence chain is an authentication event "
            "followed by a 7045 service-install event."
        ),
        "description_ar": (
            "يستخدم الحساب المُخترق المصادقة إلى مضيف ثانٍ عبر SMB وينشئ خدمة عن بُعد. "
            "سلسلة الأدلة: حدث مصادقة يليه حدث تثبيت خدمة 7045."
        ),
        "expected_telemetry": [
            {"signal": "remote_service_install", "field": "message", "pattern": "(?i)(7045|service installed|system event 7045)"},
            {"signal": "smb_admin_share", "field": "message", "pattern": "(?i)(admin\\$|ipc\\$|\\\\\\\\.*\\\\admin)"},
            {"signal": "type3_auth", "field": "message", "pattern": "(?i)(4624|logon type 3|network logon)"},
        ],
        "expected_detections": ["lateral movement", "service installation", "admin share"],
        "defensive_note_en": "Correlate 4624 type 3 logons with 7045 on the destination host.",
        "defensive_note_ar": "اربط دخول 4624 من النوع 3 مع 7045 على المضيف الوجهة.",
    },
    {
        "key": "data_staging_exfil",
        "title_en": "Data staging and exfiltration over an unusual channel",
        "title_ar": "تجهيز البيانات وتسريبها عبر قناة غير معتادة",
        "division": "defense",
        "technique": "T1048",
        "severity": "high",
        "description_en": (
            "Data is compressed, chunked and uploaded to a cloud storage host the "
            "organisation does not normally use. Volume and destination reputation "
            "are the primary signals."
        ),
        "description_ar": (
            "تُضغط البيانات وتُقسّم وتُرفع إلى خدمة تخزين سحابية غير معتادة. "
            "الحجم وسمعة الوجهة هما المؤشران الرئيسيان."
        ),        "expected_telemetry": [
            {"signal": "archive_tool", "field": "message", "pattern": "(?i)(7z|rar|winrar|tar\\s|zip\\s)"},
            {"signal": "cloud_upload", "field": "dst_ip", "pattern": "(?i)(.)"},
            {"signal": "large_outbound", "field": "message", "pattern": "(?i)(upload|transfer|sync)"},
        ],
        "expected_detections": ["exfiltration", "upload", "data transfer"],
        "defensive_note_en": "Baseline outbound volume per host and alert on new upload destinations.",
        "defensive_note_ar": "ضع خط أساس لحجم الصادرات لكل مضيف ونبّه على وجهات رفع جديدة.",
    },
    {
        "key": "persistence_scheduled_task",
        "title_en": "Persistence through a scheduled task",
        "title_ar": "الثبات عبر مهمة مجدولة",
        "division": "forensics",
        "technique": "T1053.005",
        "severity": "medium",
        "description_en": (
            "A scheduled task is created that launches a binary from a user-writable "
            "path at logon, giving the actor code execution after reboot."
        ),
        "description_ar": (
            "تُنشأ مهمة مجدولة تشغّل ملفاً من مسار يكتبه المستخدم عند تسجيل الدخول، "
            "مما يمنح الفاعل تنفيذاً بعد إعادة التشغيل."
        ),
        "expected_telemetry": [
            {"signal": "task_created", "field": "message", "pattern": "(?i)(schtasks|4698|task scheduler|at\\s)"},
            {"signal": "writable_path", "field": "message", "pattern": "(?i)(appdata|temp|programdata|users\\\\public)"},
            {"signal": "logon_trigger", "field": "message", "pattern": "(?i)(onlogon|at logon|trigger)"},
        ],
        "expected_detections": ["scheduled task", "persistence", "task created"],
        "defensive_note_en": "Monitor 4698 and 7045 and alert on tasks launched from user-writable paths.",
        "defensive_note_ar": "راقب 4698 و7045 ونبّه على المهام المشغّلة من مسارات قابلة للكتابة.",
    },
    {
        "key": "cloud_misconfiguration",
        "title_en": "Public cloud storage exposure",
        "title_ar": "كشف تخزين سحابي مكشوف للعامة",
        "division": "defense",
        "technique": "T1530",
        "severity": "high",
        "description_en": (
            "An object storage bucket or container is configured for anonymous read "
            "access. The signal is a successful unauthenticated listing response."
        ),
        "description_ar": (
            "تُهيّأ حاوية تخزين للقراءة المجهولة. المؤشر هو استجابة ناجحة "
            "لقائمة غير مصادَق عليها."
        ),
        "expected_telemetry": [
            {"signal": "public_listing", "field": "status_code", "pattern": "(?i)(200)"},
            {"signal": "bucket_api", "field": "url", "pattern": "(?i)(storage.googleapis|amazonaws|blob.core.windows|list-type=2)"},
            {"signal": "no_auth_header", "field": "message", "pattern": "(?i)(anonymous|public|unauthenticated)"},
        ],
        "expected_detections": ["public bucket", "cloud exposure", "storage"],
        "defensive_note_en": "Audit bucket policies continuously and alert on anonymous list operations.",
        "defensive_note_ar": "راجع سياسات الحاويات باستمرار ونبّه على عمليات القوائم المجهولة.",
    },
    {
        "key": "defense_evasion_disabling_logs",
        "title_en": "Disabling or clearing security logs",
        "title_ar": "تعطيل أو مسح سجلات الأمان",
        "division": "defense",
        "technique": "T1070.001",
        "severity": "critical",
        "description_en": (
            "An actor clears the Windows event log or stops the logging service. "
            "This is one of the highest-signal events in a defensive stack."
        ),
        "description_ar": (
            "يمسح الفاعل سجل أحداث ويندوز أو يوقف خدمة التسجيل. هذه من أعلى الإشارات "
            "دفاعياً."
        ),
        "expected_telemetry": [
            {"signal": "log_cleared", "field": "message", "pattern": "(?i)(clearev|clear-eventlog|wevtutil|104|1102)"},
            {"signal": "logging_stopped", "field": "message", "pattern": "(?i)(stop.*eventlog|net stop.*eventlog)"},
            {"signal": "audit_policy_change", "field": "message", "pattern": "(?i)(auditpol|1102)"},
        ],
        "expected_detections": ["log cleared", "defense evasion", "audit policy"],
        "defensive_note_en": "Forward logs off-host so a local clear cannot erase the trail.",
        "defensive_note_ar": "وجّه السجلات إلى خادم بعيد حتى لا يمحو المسح المحلي الأثر.",
    },
    {
        "key": "dns_tunnelling",
        "title_en": "Command channel over DNS tunnelling",
        "title_ar": "قناة تحكم عبر نفق DNS",
        "division": "defense",
        "technique": "T1572",
        "severity": "high",
        "description_en": (
            "Data is encoded into unusually long subdomain labels sent to a domain "
            "the organisation does not own."
        ),
        "description_ar": (
            "تُشفَّر البيانات في تسميات فرعية طويلة غير معتادة تُرسَل إلى نطاق لا تملكه "
            "المنشأة."
        ),
        "expected_telemetry": [
            {"signal": "long_label", "field": "url", "pattern": "(?i)(\\.[a-z0-9]{20,})"},
            {"signal": "high_qps", "field": "dst_ip", "pattern": "(?i)(.)"},
            {"signal": "unusual_tld", "field": "url", "pattern": "(?i)(http|https)"},
        ],
        "expected_detections": ["dns tunnel", "suspicious dns", "encoded traffic"],
        "defensive_note_en": "Alert on label entropy and volume anomalies in DNS queries.",
        "defensive_note_ar": "نبّه على شذوذentropy تسميات DNS وكميات الاستعلامات.",
    },
)

SCENARIO_INDEX = {scenario["key"]: scenario for scenario in SCENARIOS}


def list_scenarios(division: str | None = None) -> list[dict[str, Any]]:
    if division:
        return [dict(item) for item in SCENARIOS if item["division"] == division]
    return [dict(item) for item in SCENARIOS]
