"""Built-in academy curriculum for the three NEXUS divisions.

Lessons are structured content, not fake videos.  Every lesson carries an
explicit video_status; no video URL is invented.  Official documentation links
are supplementary reading and are shown separately from videos.

The 300 lessons are generated from a reviewed category/stage matrix.  Titles,
descriptions, objectives, exercises, prerequisites and knowledge checks are
unique per lesson.  Videos remain pending independent verification until a
human reviewer attaches a verified URL.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Lesson

log = logging.getLogger("nexus.academy.content")

DIVISIONS: dict[str, dict[str, Any]] = {
    "defense": {
        "key": "defense",
        "title_en": "Defense",
        "title_ar": "الدفاع السيبراني",
        "tagline_en": "Blue-team operations, detection, and response.",
        "tagline_ar": "عمليات الفريق الأزرق والكشف والاستجابة.",
        "description_en": "Build a defensive operations practice across SOC workflows, telemetry, detection engineering, incident response, and recovery.",
        "description_ar": "ابنِ ممارسة دفاعية تشمل عمليات مركز العمليات الأمنية والبيانات التشغيلية وهندسة الكشف والاستجابة للحوادث والتعافي.",
        "accent": "cyan",
        "icon": "shield",
        "stages": [
            {
                "key": "foundations",
                "en": "Foundations & Vocabulary",
                "ar": "الأساسيات والمصطلحات",
                "difficulty": "beginner",
                "minutes": 30,
                "summary_en": "Build the mental model, scope, and vocabulary before using tools.",
                "summary_ar": "ابنِ النموذج الذهني والنطاق والمصطلحات قبل استخدام الأدوات.",
            },
            {
                "key": "sources",
                "en": "Telemetry & Data Sources",
                "ar": "المصادر والبيانات التشغيلية",
                "difficulty": "beginner",
                "minutes": 35,
                "summary_en": "Identify the logs, sensors, and context needed for reliable decisions.",
                "summary_ar": "حدد السجلات والمستشعرات والسياق اللازم لقرارات موثوقة.",
            },
            {
                "key": "workflow",
                "en": "Triage & Investigation Workflow",
                "ar": "سير عمل الفرز والتحقيق",
                "difficulty": "intermediate",
                "minutes": 45,
                "summary_en": "Work from signal to evidence using a repeatable triage process.",
                "summary_ar": "انتقل من الإشارة إلى الدليل عبر عملية فرز قابلة للتكرار.",
            },
            {
                "key": "practice",
                "en": "Detection & Response Practice",
                "ar": "تدريب الكشف والاستجابة",
                "difficulty": "intermediate",
                "minutes": 50,
                "summary_en": "Practice detection, escalation, containment, and documentation.",
                "summary_ar": "تدرّب على الكشف والتصعيد والاحتواء والتوثيق.",
            },
            {
                "key": "capstone",
                "en": "Capstone Challenge",
                "ar": "تحدي التطبيق",
                "difficulty": "advanced",
                "minutes": 60,
                "summary_en": "Combine the track in a realistic, self-contained exercise.",
                "summary_ar": "اجمع مهارات المسار في تمرين واقعي ومكتفٍ ذاتياً.",
            },
        ],
        "categories": [
            ("soc_operations", "SOC Operations", "عمليات مركز العمليات الأمنية",
             "alert intake, severity, ownership, escalation, and shift handover.",
             "استقبال التنبيهات وتحديد الخطورة والمالك والتصعيد وتسليم المناوبات.",
             "https://www.cisa.gov/cybersecurity-best-practices", "CISA"),
            ("siem_correlation", "SIEM & Event Correlation", "SIEM وربط الأحداث",
             "normalization, correlation rules, search queries, and alert tuning.",
             "التطبيع وقواعد الربط واستعلامات البحث وضبط التنبيهات.",
             "https://learn.microsoft.com/en-us/azure/sentinel/", "Microsoft Learn"),
            ("windows_logs", "Windows Security & Event Logs", "أمن Windows وسجلات الأحداث",
             "Windows event channels, audit policy, logon events, PowerShell, and Sysmon.",
             "قنوات أحداث Windows وسياسة التدقيق وأحداث الدخول وPowerShell وSysmon.",
             "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy", "Microsoft Learn"),
            ("linux_monitoring", "Linux Security Monitoring", "مراقبة أمن Linux",
             "auditd, syslog, authentication logs, process accounting, and file integrity.",
             "auditd وsyslog وسجلات المصادقة ومحاسبة العمليات وسلامة الملفات.",
             "https://github.com/linux-audit/audit-documentation/wiki", "Linux Audit"),
            ("endpoint_edr", "Endpoint Protection & EDR/XDR", "حماية الأطراف وEDR/XDR",
             "endpoint telemetry, process trees, isolation, and response actions.",
             "بيانات الأطراف التشغيلية وأشجار العمليات والعزل وإجراءات الاستجابة.",
             "https://learn.microsoft.com/en-us/defender-endpoint/", "Microsoft Learn"),
            ("threat_hunting", "Threat Hunting & Behavioral Detection", "اصطياد التهديدات والكشف السلوكي",
             "hypothesis-driven hunting, baselines, and behavioral indicators.",
             "الاصطياد المبني على الفرضيات وخطوط الأساس والمؤشرات السلوكية.",
             "https://attack.mitre.org/resources/", "MITRE ATT&CK"),
            ("malware_defense", "Defensive Malware Analysis", "تحليل البرمجيات الخبيثة دفاعياً",
             "static triage, sandboxing, IOCs, and safe containment.",
             "الفرز الساكن والتحليل داخل صندوق رمل ومؤشرات الاختراق والاحتواء الآمن.",
             "https://www.cisa.gov/topics/cyber-threats-and-advisories", "CISA"),
            ("phishing_email", "Phishing & Email Security", "التصيد وأمن البريد الإلكتروني",
             "headers, authentication results, attachments, URLs, and user reporting.",
             "الترويسات ونتائج المصادقة والمرفقات والروابط وبلاغات المستخدمين.",
             "https://www.cisa.gov/secure-our-world/recognize-and-report-phishing", "CISA"),
            ("network_traffic", "Network Traffic Analysis", "تحليل حركة الشبكة",
             "flow records, PCAP triage, beaconing, and unusual protocols.",
             "سجلات التدفق وفرز PCAP والاتصالات الدورية والبروتوكولات غير المعتادة.",
             "https://www.wireshark.org/docs/", "Wireshark"),
            ("firewall_ids_dns", "Firewall, IDS, IPS & DNS Security", "الجدار الناري وIDS/IPS وأمن DNS",
             "rule review, IDS alerts, DNS telemetry, and egress control.",
             "مراجعة القواعد وتنبيهات IDS وبيانات DNS والتحكم في الخروج.",
             "https://docs.zeek.org/", "Zeek"),
            ("http_tls", "HTTP & TLS Security Monitoring", "مراقبة أمن HTTP وTLS",
             "web logs, status codes, user agents, certificates, and TLS anomalies.",
             "سجلات الويب ورموز الحالة ووكلاء المستخدم والشهادات وشذوذ TLS.",
             "https://developer.mozilla.org/en-US/docs/Web/HTTP", "MDN"),
            ("incident_response", "Incident Response & Containment", "الاستجابة للحوادث والاحتواء",
             "triage, containment, eradication, recovery, and communications.",
             "الفرز والاحتواء والاستئصال والتعافي والتواصل.",
             "https://csrc.nist.gov/pubs/sp/800/61/r3/final", "NIST SP 800-61"),
            ("detection_engineering", "Detection Engineering & Sigma", "هندسة الكشف وSigma",
             "rule design, validation, false positives, and deployment.",
             "تصميم القواعد والتحقق منها والنتائج الإيجابية الزائفة ونشرها.",
             "https://sigmahq.io/", "SigmaHQ"),
            ("mitre_attack", "MITRE ATT&CK Mapping", "ربط MITRE ATT&CK",
             "technique mapping, coverage gaps, and evidence-based attribution.",
             "ربط التقنيات وفجوات التغطية والإسناد المبني على الأدلة.",
             "https://attack.mitre.org/", "MITRE ATT&CK"),
            ("vulnerability_mgmt", "Vulnerability Management", "إدارة الثغرات",
             "inventory, CVSS/KEV context, exposure, and remediation priority.",
             "الجرد وسياق CVSS وKEV والتعرض وأولوية المعالجة.",
             "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "CISA KEV"),
            ("cloud_identity", "Cloud Security & Identity Protection", "أمن السحابة وحماية الهوية",
             "cloud audit logs, IAM, conditional access, and misconfiguration.",
             "سجلات تدقيق السحابة وIAM والوصول الشرطي وسوء التكوين.",
             "https://learn.microsoft.com/en-us/security/zero-trust/", "Microsoft Learn"),
            ("automation_soar", "Security Automation & SOAR", "الأتمتة الأمنية وSOAR",
             "playbooks, enrichment, approvals, and safe automation.",
             "كتب التشغيل والإثراء والموافقات والأتمتة الآمنة.",
             "https://www.cisa.gov/cybersecurity-best-practices", "CISA"),
            ("ransomware", "Ransomware Prevention & Recovery", "الوقاية من الفدية والتعافي",
             "backups, segmentation, detection, and recovery testing.",
             "النسخ الاحتياطي والتقسيم والكشف واختبار التعافي.",
             "https://www.cisa.gov/stopransomware", "CISA StopRansomware"),
            ("threat_intel", "Threat Intelligence Enrichment", "إثراء استخبارات التهديدات",
             "IOC context, confidence, source quality, and sharing.",
             "سياق مؤشرات الاختراق والثقة وجودة المصدر والمشاركة.",
             "https://www.cisa.gov/topics/cyber-threats-and-advisories", "CISA"),
            ("reporting_cases", "Security Reporting, Case Management & Timelines", "التقارير الأمنية وإدارة الحالات والجداول الزمنية",
             "case notes, evidence references, timelines, and executive summaries.",
             "ملاحظات الحالة ومراجع الأدلة والجداول الزمنية والملخصات التنفيذية.",
             "https://csrc.nist.gov/pubs/sp/800/61/r3/final", "NIST SP 800-61"),
        ],
    },
    "offense": {
        "key": "offense",
        "title_en": "Offense",
        "title_ar": "الأمن الهجومي",
        "tagline_en": "Authorized offensive testing and scoped labs.",
        "tagline_ar": "اختبار هجومي مصرح به ومختبرات محددة النطاق.",
        "description_en": "Learn ethical hacking, reconnaissance, controlled exploitation, and professional reporting inside explicit authorization boundaries.",
        "description_ar": "تعلّم الاختبار الأخلاقي والاستطلاع والاستغلال المضبوط والتقارير المهنية ضمن حدود تصريح واضحة.",
        "accent": "violet",
        "icon": "swords",
        "stages": [
            {
                "key": "foundations",
                "en": "Foundations & Authorization",
                "ar": "الأساسيات والتصريح",
                "difficulty": "beginner",
                "minutes": 30,
                "summary_en": "Establish scope, consent, ethics, and a safe lab boundary.",
                "summary_ar": "حدد النطاق والموافقة والأخلاق وحدود المختبر الآمن.",
            },
            {
                "key": "sources",
                "en": "Reconnaissance & Data Sources",
                "ar": "الاستطلاع ومصادر البيانات",
                "difficulty": "beginner",
                "minutes": 35,
                "summary_en": "Collect and validate information before touching a target.",
                "summary_ar": "اجمع المعلومات وتحقق منها قبل لمس الهدف.",
            },
            {
                "key": "workflow",
                "en": "Testing Workflow",
                "ar": "سير عمل الاختبار",
                "difficulty": "intermediate",
                "minutes": 45,
                "summary_en": "Use a repeatable, evidence-driven testing process.",
                "summary_ar": "استخدم عملية اختبار قابلة للتكرار ومبنية على الأدلة.",
            },
            {
                "key": "practice",
                "en": "Safe Exploitation Practice",
                "ar": "تدريب الاستغلال الآمن",
                "difficulty": "intermediate",
                "minutes": 50,
                "summary_en": "Validate impact with minimal, non-destructive proof in an authorized lab.",
                "summary_ar": "أثبت الأثر بدليل أدنى وغير تدميري داخل مختبر مصرح به.",
            },
            {
                "key": "capstone",
                "en": "Capstone Challenge",
                "ar": "تحدي التطبيق",
                "difficulty": "advanced",
                "minutes": 60,
                "summary_en": "Combine the track in a scoped, authorized lab challenge.",
                "summary_ar": "اجمع مهارات المسار في تحدي مختبري مصرح به ومحدد النطاق.",
            },
        ],
        "categories": [
            ("legal_authorization", "Ethical Hacking & Legal Authorization", "الاختبار الأخلاقي والتصريح القانوني",
             "rules of engagement, scope, consent, and safe lab boundaries.",
             "قواعد الاشتباك والنطاق والموافقة وحدود المختبر الآمن.",
             "https://www.ncsc.gov.uk/collection/penetration-testing", "NCSC"),
            ("reconnaissance", "Reconnaissance & OSINT", "الاستطلاع والمصادر المفتوحة",
             "passive collection, asset discovery, and source validation.",
             "الجمع السلبي واكتشاف الأصول والتحقق من المصادر.",
             "https://owasp.org/www-project-web-security-testing-guide/", "OWASP WSTG"),
            ("dns_asm", "DNS & Attack-Surface Mapping", "DNS ورسم سطح الهجوم",
             "DNS records, subdomains, certificates, and exposure mapping.",
             "سجلات DNS والنطاقات الفرعية والشهادات ورسم التعرض.",
             "https://owasp.org/www-project-amass/", "OWASP Amass"),
            ("network_scanning", "Network Scanning & Enumeration", "مسح الشبكة وتعداد الخدمات",
             "host discovery, port scanning, service enumeration, and rate control.",
             "اكتشاف المضيفين ومسح المنافذ وتعداد الخدمات وضبط المعدل.",
             "https://nmap.org/book/", "Nmap"),
            ("web_owasp", "Web Application Security & OWASP Top 10", "أمن تطبيقات الويب وOWASP Top 10",
             "web architecture, OWASP risks, and controlled validation.",
             "معمارية الويب ومخاطر OWASP والتحقق المضبوط.",
             "https://owasp.org/www-project-top-ten/", "OWASP Top 10"),
            ("auth_session", "Authentication & Session Security", "المصادقة وأمن الجلسات",
             "login flows, MFA, session handling, and token hygiene.",
             "تدفقات الدخول وMFA وإدارة الجلسات ونظافة الرموز.",
             "https://owasp.org/www-project-web-security-testing-guide/", "OWASP WSTG"),
            ("access_control", "Access Control & IDOR", "التحكم في الوصول وIDOR",
             "object ownership, role checks, and authorization testing.",
             "ملكية الكائنات وفحص الأدوار واختبار التصريح.",
             "https://owasp.org/www-project-web-security-testing-guide/", "OWASP WSTG"),
            ("injection", "Injection: SQLi & XSS", "حقن SQL وXSS",
             "input handling, safe proof-of-concept testing, and remediation.",
             "معالجة المدخلات واختبار إثبات المفهوم الآمن والمعالجة.",
             "https://portswigger.net/web-security", "PortSwigger Academy"),
            ("ssrf_upload", "SSRF, Uploads & Path Traversal", "SSRF والرفع واجتياز المسار",
             "server-side trust boundaries, file handling, and safe validation.",
             "حدود الثقة في الخادم ومعالجة الملفات والتحقق الآمن.",
             "https://portswigger.net/web-security", "PortSwigger Academy"),
            ("api_security", "API Security Testing", "اختبار أمن API",
             "authentication, authorization, schemas, rate limits, and API abuse cases.",
             "المصادقة والتصريح والمخططات وحدود المعدل وحالات إساءة API.",
             "https://owasp.org/www-project-api-security/", "OWASP API Security"),
            ("burp_zap", "Burp Suite & OWASP ZAP Workflows", "سير عمل Burp Suite وOWASP ZAP",
             "interception, scoping, passive/active scans, and evidence capture.",
             "الاعتراض وتحديد النطاق والفحص السلبي والنشط وتوثيق الأدلة.",
             "https://portswigger.net/burp/documentation", "PortSwigger"),
            ("nmap_assessment", "Nmap & Vulnerability Assessment", "Nmap وتقييم الثغرات",
             "service detection, scripts, and assessment planning.",
             "كشف الخدمات والسكربتات وتخطيط التقييم.",
             "https://nmap.org/book/", "Nmap"),
            ("os_assessment", "Linux & Windows Security Assessment", "تقييم أمن Linux وWindows",
             "hardening checks, permissions, services, and patch posture.",
             "فحوصات التحصين والصلاحيات والخدمات وحالة التحديثات.",
             "https://www.cisecurity.org/cis-benchmarks", "CIS Benchmarks"),
            ("active_directory", "Active Directory Security", "أمن Active Directory",
             "AD structure, authentication, delegation, and common misconfigurations.",
             "بنية AD والمصادقة والتفويض وسوء التكوين الشائع.",
             "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-domain-services", "Microsoft Learn"),
            ("privesc", "Privilege Escalation Concepts", "مفاهيم رفع الصلاحيات",
             "enumeration, misconfiguration analysis, and isolated lab practice.",
             "التعداد وتحليل سوء التكوين والتدريب في مختبر معزول.",
             "https://attack.mitre.org/", "MITRE ATT&CK"),
            ("password_security", "Password Security & Authentication Testing", "أمن كلمات المرور واختبار المصادقة",
             "credential policy, hashing, spraying defenses, and safe testing.",
             "سياسة بيانات الاعتماد والتجزئة ودفاعات الرش واختبار آمن.",
             "https://owasp.org/www-project-web-security-testing-guide/", "OWASP WSTG"),
            ("exploit_poc", "Exploit Analysis & Safe PoCs", "تحليل الاستغلال وإثباتات المفهوم الآمنة",
             "root-cause analysis, minimal PoCs, and non-destructive validation.",
             "تحليل السبب الجذري وإثباتات المفهوم الدنيا والتحقق غير التدميري.",
             "https://owasp.org/www-project-web-security-testing-guide/", "OWASP WSTG"),
            ("metasploit", "Metasploit in Authorized Labs", "Metasploit في مختبرات مصرح بها",
             "module selection, payload safety, session handling, and cleanup.",
             "اختيار الوحدات وسلامة الحمولة وإدارة الجلسات والتنظيف.",
             "https://docs.metasploit.com/", "Metasploit Docs"),
            ("cloud_container", "Cloud & Container Security", "أمن السحابة والحاويات",
             "IAM, storage, container images, Kubernetes, and cloud logging.",
             "IAM والتخزين وصور الحاويات وKubernetes وسجلات السحابة.",
             "https://kubernetes.io/docs/concepts/security/", "Kubernetes"),
            ("reporting_remediation", "Reporting, Remediation & Attack Paths", "التقارير والمعالجة ومسارات الهجوم",
             "evidence quality, risk narrative, remediation, and retesting.",
             "جودة الأدلة ورواية المخاطر والمعالجة وإعادة الاختبار.",
             "https://owasp.org/www-project-web-security-testing-guide/", "OWASP WSTG"),
        ],
    },
    "forensics": {
        "key": "forensics",
        "title_en": "Digital Forensics",
        "title_ar": "التحقيق الجنائي الرقمي",
        "tagline_en": "DFIR, evidence integrity, and case reconstruction.",
        "tagline_ar": "الاستجابة الرقمية وسلامة الأدلة وإعادة بناء الحالات.",
        "description_en": "Investigate Windows, Linux, network, memory, and email artifacts while preserving provenance, integrity, and chain of custody.",
        "description_ar": "حقّق في آثار Windows وLinux والشبكة والذاكرة والبريد مع الحفاظ على المصدر والسلامة وسلسلة الحيازة.",
        "accent": "amber",
        "icon": "fingerprint",
        "stages": [
            {
                "key": "method",
                "en": "Foundations & Method",
                "ar": "الأساسيات والمنهجية",
                "difficulty": "beginner",
                "minutes": 30,
                "summary_en": "Build a defensible, evidence-first investigation method.",
                "summary_ar": "ابنِ منهجية تحقيق قابلة للدفاع تضع الدليل أولاً.",
            },
            {
                "key": "acquisition",
                "en": "Evidence Sources & Acquisition",
                "ar": "مصادر الأدلة والحيازة",
                "difficulty": "beginner",
                "minutes": 35,
                "summary_en": "Identify relevant artifacts and preserve them without alteration.",
                "summary_ar": "حدد الآثار ذات الصلة واحفظها دون تغيير.",
            },
            {
                "key": "analysis",
                "en": "Analysis Workflow",
                "ar": "سير عمل التحليل",
                "difficulty": "intermediate",
                "minutes": 45,
                "summary_en": "Correlate artifacts into a testable investigative narrative.",
                "summary_ar": "اربط الآثار في رواية تحقيق قابلة للاختبار.",
            },
            {
                "key": "reporting",
                "en": "Reporting & Peer Review",
                "ar": "التقارير ومراجعة الأقران",
                "difficulty": "intermediate",
                "minutes": 50,
                "summary_en": "Document findings, limitations, and chain-of-custody decisions.",
                "summary_ar": "وثّق النتائج والقيود وقرارات سلسلة الحيازة.",
            },
            {
                "key": "capstone",
                "en": "Capstone Investigation",
                "ar": "التحقيق الختامي",
                "difficulty": "advanced",
                "minutes": 60,
                "summary_en": "Solve a self-contained case from evidence to defensible conclusion.",
                "summary_ar": "حل قضية مكتفية ذاتياً من الدليل إلى استنتاج قابل للدفاع.",
            },
        ],
        "categories": [
            ("fundamentals", "Forensics Fundamentals & Methodology", "أساسيات التحقيق الجنائي والمنهجية",
             "evidence types, order of volatility, scientific method, and documentation.",
             "أنواع الأدلة وترتيب التطاير والمنهج العلمي والتوثيق.",
             "https://csrc.nist.gov/pubs/sp/800/86/final", "NIST SP 800-86"),
            ("evidence_custody", "Evidence Preservation & Chain of Custody", "حفظ الأدلة وسلسلة الحيازة",
             "acquisition, hashing, storage, handover, and integrity verification.",
             "الحيازة والتجزئة والتخزين والتسليم والتحقق من السلامة.",
             "https://csrc.nist.gov/pubs/sp/800/86/final", "NIST SP 800-86"),
            ("windows_artifacts", "Windows Forensic Artifacts", "آثار Windows الجنائية",
             "registry, event logs, prefetch, shimcache, amcache, and user activity.",
             "Registry وسجلات الأحداث وPrefetch وShimcache وAmcache ونشاط المستخدم.",
             "https://learn.microsoft.com/en-us/sysinternals/", "Microsoft Sysinternals"),
            ("linux_artifacts", "Linux Forensic Artifacts", "آثار Linux الجنائية",
             "auth logs, auditd, bash history, systemd, cron, and package history.",
             "سجلات المصادقة وauditd وتاريخ Bash وsystemd وcron وتاريخ الحزم.",
             "https://github.com/linux-audit/audit-documentation/wiki", "Linux Audit"),
            ("timeline", "Event Logs & Timeline Reconstruction", "سجلات الأحداث وإعادة بناء الجدول الزمني",
             "normalization, correlation, time zones, and super-timelines.",
             "التطبيع والربط والمناطق الزمنية والجداول الزمنية الفائقة.",
             "https://www.sans.org/posters/?focus-area=digital-forensics", "SANS DFIR"),
            ("filesystem", "Filesystem & Metadata Analysis", "تحليل نظام الملفات والبيانات الوصفية",
             "MFT, timestamps, inodes, journaling, and file carving concepts.",
             "MFT والطوابع الزمنية وinodes والتدوين واستخراج الملفات.",
             "https://csrc.nist.gov/pubs/sp/800/86/final", "NIST SP 800-86"),
            ("deleted_files", "Deleted-File Recovery Concepts", "مفاهيم استعادة الملفات المحذوفة",
             "unallocated space, carving, slack space, and evidential limits.",
             "المساحة غير المخصصة والاستخراج والمساحة المهدورة وحدود الدليل.",
             "https://csrc.nist.gov/pubs/sp/800/86/final", "NIST SP 800-86"),
            ("browser", "Browser & Download Artifacts", "آثار المتصفح والتنزيلات",
             "history, cache, cookies, downloads, and profile analysis.",
             "السجل والذاكرة المؤقتة وملفات تعريف الارتباط والتنزيلات وتحليل الملف الشخصي.",
             "https://www.sans.org/posters/?focus-area=digital-forensics", "SANS DFIR"),
            ("email_phishing", "Email Header & Phishing Analysis", "تحليل ترويسات البريد والتصيد",
             "Received chains, SPF/DKIM/DMARC, attachments, and URL analysis.",
             "سلاسل Received وSPF/DKIM/DMARC والمرفقات وتحليل الروابط.",
             "https://www.cisa.gov/secure-our-world/recognize-and-report-phishing", "CISA"),
            ("pcap", "Network Forensics & PCAP", "التحقيق الجنائي للشبكة وPCAP",
             "capture points, flow reconstruction, protocol analysis, and extraction.",
             "نقاط الالتقاط وإعادة بناء التدفق وتحليل البروتوكول والاستخراج.",
             "https://www.wireshark.org/docs/", "Wireshark"),
            ("dns_http", "DNS & HTTP Traffic Investigations", "تحقيقات حركة DNS وHTTP",
             "queries, responses, tunneling, user agents, and web artifacts.",
             "الاستعلامات والاستجابات والنفق ووكلاء المستخدم وآثار الويب.",
             "https://docs.zeek.org/", "Zeek"),
            ("memory", "Memory Forensics & Process Analysis", "التحقيق في الذاكرة وتحليل العمليات",
             "volatile acquisition, process trees, injected code, and network connections.",
             "حيازة البيانات المتطايرة وأشجار العمليات والكود المحقون واتصالات الشبكة.",
             "https://volatility3.readthedocs.io/", "Volatility 3"),
            ("malware_triage", "Malware Triage & Persistence", "فرز البرمجيات الخبيثة والاستمرارية",
             "hashes, strings, sandbox reports, persistence, and IOC extraction.",
             "التجزئات والسلاسل وتقارير صندوق الرمل والاستمرارية واستخراج المؤشرات.",
             "https://virustotal.github.io/yara/", "YARA"),
            ("registry_startup", "Registry, Startup & Scheduled Tasks", "Registry والبدء والمهام المجدولة",
             "run keys, services, scheduled tasks, and startup locations.",
             "مفاتيح التشغيل والخدمات والمهام المجدولة ومواقع البدء.",
             "https://learn.microsoft.com/en-us/sysinternals/", "Microsoft Sysinternals"),
            ("account_login", "Account & Login Investigations", "تحقيقات الحسابات وتسجيل الدخول",
             "logon types, failures, privilege changes, and account creation.",
             "أنواع الدخول والفشل وتغييرات الصلاحيات وإنشاء الحسابات.",
             "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy", "Microsoft Learn"),
            ("lateral_movement", "Lateral Movement & Auth Correlation", "الحركة الجانبية وربط المصادقة",
             "remote execution, SMB, RDP, service accounts, and hop correlation.",
             "التنفيذ عن بُعد وSMB وRDP وحسابات الخدمة وربط القفزات.",
             "https://attack.mitre.org/", "MITRE ATT&CK"),
            ("exfiltration", "Data Exfiltration Detection", "كشف تسريب البيانات",
             "staging, compression, transfer channels, and volume anomalies.",
             "التجميع والضغط وقنوات النقل وشذوذ الأحجام.",
             "https://attack.mitre.org/", "MITRE ATT&CK"),
            ("ransomware_ir", "Ransomware Reconstruction & IOCs", "إعادة بناء الفدية ومؤشرات الاختراق",
             "encryption traces, notes, recovery, and actor behavior.",
             "آثار التشفير والملاحظات والتعافي وسلوك الفاعل.",
             "https://www.cisa.gov/stopransomware", "CISA StopRansomware"),
            ("attack_hashing", "MITRE ATT&CK & Evidence Hashing", "MITRE ATT&CK وتجزئة الأدلة",
             "technique mapping, evidence integrity, and defensible conclusions.",
             "ربط التقنيات وسلامة الأدلة والاستنتاجات القابلة للدفاع.",
             "https://attack.mitre.org/", "MITRE ATT&CK"),
            ("case_reporting", "Case Documentation, Reporting & Capstone", "توثيق الحالة والتقارير والتطبيق الختامي",
             "case files, findings, limitations, peer review, and final report.",
             "ملفات القضية والنتائج والقيود ومراجعة الأقران والتقرير النهائي.",
             "https://csrc.nist.gov/pubs/sp/800/61/r3/final", "NIST SP 800-61"),
        ],
    },
}

DIVISION_KEYS: tuple[str, ...] = tuple(DIVISIONS.keys())

DIFFICULTY_AR: dict[str, str] = {
    "beginner": "مبتدئ",
    "intermediate": "متوسط",
    "advanced": "متقدم",
}

def _cap(value: str) -> str:
    if not value:
        return value
    return value[0].upper() + value[1:]


def _slug(division: str, category_key: str, stage_key: str) -> str:
    return f"{division}-{category_key}-{stage_key}"


def _safety_choice(division: str) -> tuple[str, str]:
    if division == "offense":
        return (
            "Use only synthetic or explicitly authorized targets, minimize impact, and document evidence and uncertainty.",
            "استخدم أهدافاً اصطناعية أو مصرحاً بها صراحة فقط، وقلل الأثر، ووثّق الأدلة وعدم اليقين.",
        )
    if division == "forensics":
        return (
            "Preserve the original evidence, record hashes and provenance, and document uncertainty.",
            "احفظ الدليل الأصلي، وسجّل التجزئات والمصدر، ووثّق عدم اليقين.",
        )
    return (
        "Use synthetic or explicitly authorized data, preserve evidence, and document uncertainty.",
        "استخدم بيانات اصطناعية أو مصرحاً بها صراحة، واحفظ الأدلة، ووثّق عدم اليقين.",
    )


def _quiz_definition(
    *,
    slug: str,
    title_en: str,
    title_ar: str,
    division: str,
    division_title_en: str,
    division_title_ar: str,
    category: tuple[str, ...],
    categories: list[tuple[str, ...]],
    category_index: int,
    stage: dict[str, Any],
) -> list[dict[str, Any]]:
    focus_current = (category[3], category[4])
    choices = [focus_current]
    for step in (1, 2, 3):
        other = categories[(category_index + step) % len(categories)]
        choices.append((other[3], other[4]))

    # Deterministic rotation prevents the correct option from always being first.
    shift = sum(ord(ch) for ch in slug) % 4
    rotated = choices[shift:] + choices[:shift]
    options: list[dict[str, str]] = []
    answer = "a"
    for index, choice in enumerate(rotated):
        option_id = "abcd"[index]
        options.append({"id": option_id, "en": _cap(choice[0]), "ar": choice[1]})
        if choice == focus_current:
            answer = option_id

    safety_en, safety_ar = _safety_choice(division)
    return [
        {
            "id": "focus",
            "question_en": f'Which activity is the primary focus of the lesson "{title_en}"?',
            "question_ar": f"ما النشاط الأساسي في درس «{title_ar}»؟",
            "options": options,
            "answer": answer,
            "explanation_en": f"The lesson focuses on {category[3]}",
            "explanation_ar": f"يركز الدرس على {category[4]}",
        },
        {
            "id": "safety",
            "question_en": "Which approach keeps this lesson within authorized, defensible practice?",
            "question_ar": "أي أسلوب يبقي هذا الدرس ضمن الممارسة المصرح بها والقابلة للدفاع عنها؟",
            "options": [
                {"id": "a", "en": safety_en, "ar": safety_ar},
                {"id": "b", "en": "Test any public system if the goal is educational.", "ar": "اختبر أي نظام عام إذا كان الهدف تعليمياً."},
                {"id": "c", "en": "Ignore scope limits when the finding looks important.", "ar": "تجاهل حدود النطاق عندما تبدو النتيجة مهمة."},
                {"id": "d", "en": "Publish credentials or personal data to prove the result.", "ar": "انشر بيانات الاعتماد أو البيانات الشخصية لإثبات النتيجة."},
            ],
            "answer": "a",
            "explanation_en": "Authorization, evidence preservation, and documented uncertainty are mandatory. Educational intent never expands scope.",
            "explanation_ar": "التصريح وحفظ الأدلة وتوثيق عدم اليقين إلزامية. النية التعليمية لا توسّع النطاق أبداً.",
        },
    ]


def _build_lesson(division: str, spec: dict[str, Any], category_index: int, stage_index: int) -> dict[str, Any]:
    category = spec["categories"][category_index]
    stage = spec["stages"][stage_index]
    stage_key = stage["key"]
    slug = _slug(division, category[0], stage_key)
    difficulty = stage["difficulty"]
    title_en = f"{category[1]} - {stage['en']}"
    title_ar = f"{category[2]} - {stage['ar']}"

    prerequisites: list[str] = []
    if stage_index > 0:
        prerequisites.append(_slug(division, category[0], spec["stages"][stage_index - 1]["key"]))

    related: list[str] = []
    if stage_index + 1 < len(spec["stages"]):
        related.append(_slug(division, category[0], spec["stages"][stage_index + 1]["key"]))
    if category_index + 1 < len(spec["categories"]):
        related.append(_slug(division, spec["categories"][category_index + 1][0], stage_key))
    capstone = _slug(division, category[0], spec["stages"][-1]["key"])
    if capstone != slug and capstone not in related:
        related.append(capstone)

    summary_en = f"{stage['summary_en']} This lesson focuses on {category[3]}"
    summary_ar = f"{stage['summary_ar']} يركز الدرس على {category[4]}"

    description_en = (
        f"This {difficulty} lesson in the {spec['title_en']} division covers {stage['en'].lower()} "
        f"for {category[1]}. It focuses on {category[3]} "
        "It uses synthetic or explicitly authorized data and requires a written record of evidence, scope, and uncertainty. "
        f"A verified video is not attached yet, so the lesson is marked pending verification; the linked {category[6]} "
        "documentation is supplementary reading, not a substitute for the exercise."
    )
    description_ar = (
        f"درس بمستوى {DIFFICULTY_AR[difficulty]} ضمن قسم {spec['title_ar']} يغطي {stage['ar']} "
        f"في مجال {category[2]}. يركز على {category[4]} "
        "يستخدم الدرس بيانات اصطناعية أو مصرحاً بها صراحة، ويتطلب سجلاً مكتوباً للأدلة والنطاق وعدم اليقين. "
        "لا يوجد فيديو متحقق منه بعد، لذا يُعرض الدرس بحالة قيد التحقق؛ وثائق "
        f"{category[6]} المرفقة هي قراءة مساندة وليست بديلاً عن التمرين."
    )

    objectives = [
        {
            "en": f"Explain {stage['en'].lower()} in the context of {category[1]}.",
            "ar": f"اشرح {stage['ar']} في سياق {category[2]}.",
        },
        {
            "en": f"Apply {category[3]} to a safe, authorized scenario.",
            "ar": f"طبّق {category[4]} في سيناريو آمن ومصرح به.",
        },
        {
            "en": "Document the evidence, the limits of the conclusion, and the next defensible action.",
            "ar": "وثّق الأدلة وحدود الاستنتاج والخطوة التالية القابلة للدفاع عنها.",
        },
    ]

    exercise_en = (
        f"Guided exercise: build a small worksheet for \"{title_en}\". Use synthetic data or an explicitly authorized "
        "lab only. Record the source, the steps, the evidence, one alternative hypothesis, and one limitation. "
        "Do not test third-party systems."
    )
    exercise_ar = (
        f"تمرين موجه: أنشئ ورقة عمل صغيرة لدرس «{title_ar}». استخدم بيانات اصطناعية أو مختبراً مصرحاً به صراحة فقط. "
        "سجّل المصدر والخطوات والأدلة وفرضية بديلة واحدة وحداً واحداً للاستنتاج. لا تختبر أنظمة طرف ثالث."
    )

    return {
        "slug": slug,
        "division": division,
        "category": category[0],
        "difficulty": difficulty,
        "order_index": category_index * len(spec["stages"]) + stage_index + 1,
        "title_ar": title_ar,
        "title_en": title_en,
        "summary_ar": summary_ar,
        "summary_en": summary_en,
        "description_ar": description_ar,
        "description_en": description_en,
        "objectives": objectives,
        "prerequisites": prerequisites,
        "related": related,
        "video_url": "",
        "video_status": "pending_verification",
        "resource_url": category[5],
        "resource_label_ar": f"{category[6]} - وثائق رسمية",
        "resource_label_en": f"{category[6]} - official documentation",
        "duration_minutes": int(stage["minutes"]),
        "exercise_ar": exercise_ar,
        "exercise_en": exercise_en,
        "quiz": _quiz_definition(
            slug=slug,
            title_en=title_en,
            title_ar=title_ar,
            division=division,
            division_title_en=spec["title_en"],
            division_title_ar=spec["title_ar"],
            category=category,
            categories=spec["categories"],
            category_index=category_index,
            stage=stage,
        ),
        "tags": [division, category[0], stage_key, difficulty],
        "is_published": True,
    }


def lesson_definitions() -> list[dict[str, Any]]:
    """Return the deterministic 300-lesson curriculum (100 per division)."""
    items: list[dict[str, Any]] = []
    for division, spec in DIVISIONS.items():
        for category_index in range(len(spec["categories"])):
            for stage_index in range(len(spec["stages"])):
                items.append(_build_lesson(division, spec, category_index, stage_index))
    expected = sum(len(spec["categories"]) * len(spec["stages"]) for spec in DIVISIONS.values())
    if len(items) != expected:
        raise RuntimeError(f"academy curriculum mismatch: {len(items)} != {expected}")
    return items


def public_divisions() -> list[dict[str, Any]]:
    """Division metadata safe to expose to the UI (no answer keys or user data)."""
    result: list[dict[str, Any]] = []
    for key, spec in DIVISIONS.items():
        result.append(
            {
                "key": key,
                "title_en": spec["title_en"],
                "title_ar": spec["title_ar"],
                "tagline_en": spec["tagline_en"],
                "tagline_ar": spec["tagline_ar"],
                "description_en": spec["description_en"],
                "description_ar": spec["description_ar"],
                "accent": spec["accent"],
                "icon": spec["icon"],
                "lesson_count": len(spec["categories"]) * len(spec["stages"]),
                "categories": [
                    {
                        "key": category[0],
                        "en": category[1],
                        "ar": category[2],
                        "focus_en": category[3],
                        "focus_ar": category[4],
                    }
                    for category in spec["categories"]
                ],
                "stages": [
                    {
                        "key": stage["key"],
                        "en": stage["en"],
                        "ar": stage["ar"],
                        "difficulty": stage["difficulty"],
                        "minutes": stage["minutes"],
                    }
                    for stage in spec["stages"]
                ],
            }
        )
    return result


def category_label(division: str, category_key: str) -> dict[str, str]:
    spec = DIVISIONS.get(division, {})
    for category in spec.get("categories", []):
        if category[0] == category_key:
            return {"en": category[1], "ar": category[2]}
    return {"en": category_key, "ar": category_key}


def sync_academy(db: Session) -> dict[str, int]:
    """Insert or refresh the built-in curriculum without touching progress."""
    definitions = lesson_definitions()
    existing = {
        lesson.slug: lesson
        for lesson in db.execute(select(Lesson)).scalars().all()
    }
    created = updated = 0
    for definition in definitions:
        lesson = existing.get(definition["slug"])
        if lesson is None:
            db.add(Lesson(**definition))
            created += 1
        else:
            for field, value in definition.items():
                setattr(lesson, field, value)
            updated += 1
    db.commit()
    log.info("academy synced: %s created, %s updated, %s total", created, updated, len(definitions))
    return {"created": created, "updated": updated, "total": len(definitions)}