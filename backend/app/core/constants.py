"""Shared domain constants — single source of truth for severities, statuses, categories.

The frontend fetches these via /api/v1/system/meta so labels stay in sync.
"""

from __future__ import annotations

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_LABELS: dict[str, dict[str, str]] = {
    "critical": {"ar": "حرجة", "en": "Critical"},
    "high": {"ar": "عالية", "en": "High"},
    "medium": {"ar": "متوسطة", "en": "Medium"},
    "low": {"ar": "منخفضة", "en": "Low"},
    "info": {"ar": "معلوماتية", "en": "Informational"},
}
SEVERITY_COLORS: dict[str, str] = {
    "critical": "#f43f5e",
    "high": "#fb7185",
    "medium": "#f59e0b",
    "low": "#38bdf8",
    "info": "#64748b",
}

CONFIDENCES: tuple[str, ...] = ("certain", "firm", "tentative")
CONFIDENCE_LABELS: dict[str, dict[str, str]] = {
    "certain": {"ar": "مؤكد", "en": "Certain"},
    "firm": {"ar": "مرجّح", "en": "Firm"},
    "tentative": {"ar": "محتمل", "en": "Tentative"},
}

FINDING_STATUSES: tuple[str, ...] = ("open", "confirmed", "fixed", "accepted_risk", "false_positive", "duplicate")
FINDING_STATUS_LABELS: dict[str, dict[str, str]] = {
    "open": {"ar": "مفتوحة", "en": "Open"},
    "confirmed": {"ar": "مُتحقَّق منها", "en": "Confirmed"},
    "fixed": {"ar": "مُصلَحة", "en": "Fixed"},
    "accepted_risk": {"ar": "مخاطرة مقبولة", "en": "Accepted Risk"},
    "false_positive": {"ar": "إنذار كاذب", "en": "False Positive"},
    "duplicate": {"ar": "مكررة", "en": "Duplicate"},
}

# Categories carry bilingual labels so reports and the UI never hardcode text.
FINDING_CATEGORIES: dict[str, dict[str, str]] = {
    "xss": {"ar": "برمجة عبر المواقع (XSS)", "en": "Cross-Site Scripting (XSS)"},
    "sqli": {"ar": "حقن SQL", "en": "SQL Injection"},
    "csrf": {"ar": "تزوير الطلب عبر المواقع (CSRF)", "en": "Cross-Site Request Forgery"},
    "auth": {"ar": "مصادقة وتفويض", "en": "Authentication & Authorization"},
    "access_control": {"ar": "ضبط الوصول", "en": "Access Control"},
    "misconfig": {"ar": "سوء إعداد", "en": "Security Misconfiguration"},
    "headers": {"ar": "رؤوس أمنية", "en": "Security Headers"},
    "cookie": {"ar": "سمات الكوكيز", "en": "Cookie Attributes"},
    "tls": {"ar": "TLS/الشهادات", "en": "TLS / Certificates"},
    "info_disclosure": {"ar": "إفصاح عن معلومات", "en": "Information Disclosure"},
    "exposure": {"ar": "ملفات/مسارات مكشوفة", "en": "Exposed Files & Paths"},
    "crypto": {"ar": "تشفير ضعيف", "en": "Weak Cryptography"},
    "injection_other": {"ar": "حقن آخر", "en": "Other Injection"},
    "ssrf": {"ar": "تزوير الطلبات من الخادم (SSRF)", "en": "Server-Side Request Forgery"},
    "dns": {"ar": "DNS والإعدادات", "en": "DNS & Configuration"},
    "network_service": {"ar": "خدمات شبكية مكشوفة", "en": "Exposed Network Services"},
    "outdated_component": {"ar": "مكوّن قديم", "en": "Outdated Component"},
    "other": {"ar": "أخرى", "en": "Other"},
}

SCAN_STATUSES: tuple[str, ...] = ("queued", "running", "paused", "completed", "failed", "canceled", "partial")
SCAN_STATUS_LABELS: dict[str, dict[str, str]] = {
    "queued": {"ar": "في الانتظار", "en": "Queued"},
    "running": {"ar": "يعمل الآن", "en": "Running"},
    "paused": {"ar": "متوقف مؤقتًا", "en": "Paused"},
    "completed": {"ar": "مكتمل", "en": "Completed"},
    "partial": {"ar": "مكتمل جزئيًا", "en": "Partial"},
    "failed": {"ar": "فاشل", "en": "Failed"},
    "canceled": {"ar": "مُلغى", "en": "Canceled"},
}

SCAN_KINDS: dict[str, dict[str, str]] = {
    "asset_discovery": {"ar": "استكشاف الأصول", "en": "Asset Discovery"},
    "http_analysis": {"ar": "تحليل HTTP", "en": "HTTP Analysis"},
    "web_vuln": {"ar": "تقييم ثغرات الويب", "en": "Web Vulnerability Assessment"},
    "network_scan": {"ar": "فحص الشبكة والمنافذ", "en": "Network & Port Scan"},
    "dns_diagnostics": {"ar": "تشخيصات DNS", "en": "DNS Diagnostics"},
    "pcap_analysis": {"ar": "تحليل PCAP", "en": "PCAP Analysis"},
    "log_analysis": {"ar": "تحليل السجلات", "en": "Log Analysis"},
    "intel_correlation": {"ar": "ربط الاستخبارات", "en": "Intel Correlation"},
}

SCAN_PROFILES: dict[str, dict[str, str]] = {
    "passive": {"ar": "سلبي (آمن تمامًا)", "en": "Passive (fully safe)"},
    "safe_active": {"ar": "نشط آمن (يتطلب تصريحًا)", "en": "Safe Active (authorization required)"},
    "zap_passive": {"ar": "ZAP سلبي", "en": "ZAP Passive"},
    "zap_active": {"ar": "ZAP نشط (يتطلب تصريحًا)", "en": "ZAP Active (authorization required)"},
}

JOB_STATUSES: tuple[str, ...] = ("queued", "running", "succeeded", "failed", "canceled", "dead")

PROJECT_KINDS: dict[str, dict[str, str]] = {
    "assessment": {"ar": "تقييم أمني", "en": "Security Assessment"},
    "asm": {"ar": "إدارة سطح الهجوم", "en": "Attack Surface Management"},
    "lab": {"ar": "مختبر تدريب", "en": "Training Lab"},
}

GLOBAL_ROLES: tuple[str, ...] = ("owner", "admin", "analyst", "viewer")
PROJECT_ROLES: tuple[str, ...] = ("owner", "admin", "analyst", "viewer")
ROLE_LABELS: dict[str, dict[str, str]] = {
    "owner": {"ar": "مالك", "en": "Owner"},
    "admin": {"ar": "مدير", "en": "Admin"},
    "analyst": {"ar": "محلل", "en": "Analyst"},
    "viewer": {"ar": "مشاهد", "en": "Viewer"},
}
ROLE_POWER: dict[str, int] = {"viewer": 0, "analyst": 1, "admin": 2, "owner": 3}

SCOPE_KINDS: tuple[str, ...] = ("domain", "ip", "cidr", "url")
SCOPE_VERIFICATION_METHODS: tuple[str, ...] = ("none", "dns_txt", "http_file", "manual")

ASSET_TYPES: tuple[str, ...] = ("domain", "subdomain", "ip", "host", "url", "network")
SERVICE_STATES: tuple[str, ...] = ("open", "closed", "filtered", "unknown")

ASSET_CHANGE_KINDS: dict[str, dict[str, str]] = {
    "new_asset": {"ar": "أصل جديد", "en": "New asset"},
    "asset_removed": {"ar": "أصل اختفى", "en": "Asset disappeared"},
    "new_service": {"ar": "خدمة جديدة", "en": "New service"},
    "service_removed": {"ar": "خدمة أُغلقت", "en": "Service removed"},
    "service_changed": {"ar": "تغيّر وصف الخدمة", "en": "Service fingerprint changed"},
    "tls_change": {"ar": "تغيّر شهادة TLS", "en": "TLS certificate changed"},
    "header_change": {"ar": "تغيّر الرؤوس الأمنية", "en": "Security headers changed"},
    "state_change": {"ar": "تغيّر حالة الأصل", "en": "Asset state changed"},
    "risk_change": {"ar": "تغيّر مستوى الخطر", "en": "Risk level changed"},
}

ALERT_STATUSES: tuple[str, ...] = ("new", "acknowledged", "investigating", "closed", "false_positive")
ALERT_STATUS_LABELS: dict[str, dict[str, str]] = {
    "new": {"ar": "جديد", "en": "New"},
    "acknowledged": {"ar": "مُستلَم", "en": "Acknowledged"},
    "investigating": {"ar": "قيد التحقيق", "en": "Investigating"},
    "closed": {"ar": "مغلق", "en": "Closed"},
    "false_positive": {"ar": "إنذار كاذب", "en": "False Positive"},
}

INCIDENT_STATUSES: tuple[str, ...] = ("open", "contained", "eradicated", "recovering", "closed")
INCIDENT_STATUS_LABELS: dict[str, dict[str, str]] = {
    "open": {"ar": "مفتوحة", "en": "Open"},
    "contained": {"ar": "مُحتَوى", "en": "Contained"},
    "eradicated": {"ar": "مُستأصل", "en": "Eradicated"},
    "recovering": {"ar": "قيد التعافي", "en": "Recovering"},
    "closed": {"ar": "مغلقة", "en": "Closed"},
}

LOG_FORMATS: tuple[str, ...] = ("auto", "nginx", "apache", "syslog", "json", "csv")

LAB_LEVELS: dict[str, dict[str, str]] = {
    "beginner": {"ar": "مبتدئ", "en": "Beginner"},
    "intermediate": {"ar": "متوسط", "en": "Intermediate"},
    "advanced": {"ar": "متقدم", "en": "Advanced"},
}
LAB_CATEGORIES: dict[str, dict[str, str]] = {
    "web": {"ar": "أمن الويب", "en": "Web Security"},
    "http": {"ar": "HTTP والرؤوس", "en": "HTTP & Headers"},
    "dns": {"ar": "DNS", "en": "DNS"},
    "network": {"ar": "استكشاف الشبكة", "en": "Network Enumeration"},
    "logs": {"ar": "تحليل السجلات", "en": "Log Analysis"},
    "pcap": {"ar": "تحليل PCAP", "en": "PCAP Analysis"},
    "vuln_hunt": {"ar": "اكتشاف الثغرات", "en": "Vulnerability Hunting"},
    "fix": {"ar": "الإصلاح والتحقق", "en": "Fixing & Verification"},
}

REPORT_KINDS: dict[str, dict[str, str]] = {
    "executive": {"ar": "تقرير تنفيذي", "en": "Executive Report"},
    "technical": {"ar": "تقرير تقني", "en": "Technical Report"},
    "comparison": {"ar": "تقرير مقارنة", "en": "Comparison Report"},
    "scan_summary": {"ar": "ملخص فحص", "en": "Scan Summary"},
}

EVIDENCE_KINDS: tuple[str, ...] = (
    "http_request",
    "http_response",
    "header_dump",
    "cookie_dump",
    "tls_chain",
    "dns_record",
    "port_banner",
    "pcap_snippet",
    "log_excerpt",
    "analysis_note",
    "raw",
)

# Sensitive header/parameter names that must never reach evidence in clear text.
SENSITIVE_HEADERS: tuple[str, ...] = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "api-key",
    "apikey",
    "token",
    "password",
    "passwd",
    "pwd",
    "secret",
    "client_secret",
    "refresh_token",
    "access_token",
    "session",
    "sessionid",
    "jwt",
)

SENSITIVE_PATTERNS: tuple[str, ...] = (
    r"(?i)bearer\s+[a-z0-9\-._~+/]+=*",
    r"(?i)basic\s+[a-z0-9+/]{8,}=*",
    r"(?i)eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{4,}",  # JWT
    r"(?i)(password|passwd|pwd)\s*[=:]\s*[^\s&'\"]{3,}",
    r"(?i)(api[_-]?key|secret|token)\s*[=:]\s*[a-z0-9\-._~+/]{8,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",  # emails
    r"\b(?:\d[ -]*?){13,16}\b",  # payment-card-like digits
)

DEFAULT_PROJECT_RETENTION_DAYS = 180
MAX_EVIDENCE_SNIPPET = 4000
