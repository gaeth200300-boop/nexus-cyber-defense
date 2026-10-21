"""Built-in lab catalogue.

Every lab is verifiable by the platform itself: `file_analysis` checks run the
real engines/parsers against real fixture files (`app/labs/files.py`),
`project_state` checks inspect the user's own project data, and `quiz` checks are
auto-graded against their answer key. No lab depends on attacking a third party.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Lab

log = logging.getLogger("nexus.labs.content")


def _quiz(
    key: str,
    points: int,
    *,
    label_en: str,
    label_ar: str,
    question_en: str,
    question_ar: str,
    options: list[dict[str, str]],
    answer: str,
    explanation_en: str = "",
    explanation_ar: str = "",
) -> dict[str, Any]:
    return {
        "key": key,
        "type": "quiz",
        "points": points,
        "label_en": label_en,
        "label_ar": label_ar,
        "spec": {
            "question_en": question_en,
            "question_ar": question_ar,
            "options": options,
            "answer": answer,
            "explanation_en": explanation_en,
            "explanation_ar": explanation_ar,
        },
    }


def _file_check(key: str, points: int, *, label_en: str, label_ar: str, spec: dict[str, Any]) -> dict[str, Any]:
    return {"key": key, "type": "file_analysis", "points": points, "label_en": label_en, "label_ar": label_ar, "spec": spec}


def _project_check(key: str, points: int, *, label_en: str, label_ar: str, spec: dict[str, Any]) -> dict[str, Any]:
    return {"key": key, "type": "project_state", "points": points, "label_en": label_en, "label_ar": label_ar, "spec": spec}


LAB_DEFINITIONS: tuple[dict[str, Any], ...] = (
    # ------------------------------------------------------------------ http
    {
        "slug": "http-security-headers",
        "category": "http",
        "level": "beginner",
        "points": 150,
        "title_en": "Audit HTTP security headers",
        "title_ar": "تدقيق رؤوس HTTP الأمنية",
        "description_en": "A real captured response is waiting for you. NEXUS grades your reading of it against the same header analyzer it uses on live targets.",
        "description_ar": "لديك استجابة HTTP حقيقية تم التقاطها. ستقيّم المنصة قراءتك لها باستخدام نفس محلل الرؤوس المستخدم في الفحوصات الحقيقية.",
        "objectives": [
            {"key": "read", "label_en": "Read the captured response and list absent defence headers", "label_ar": "اقرأ الاستجابة الملتقطة واذكر الرؤوس الدفاعية الغائبة"},
            {"key": "cookie", "label_en": "Spot the session cookie weakness", "label_ar": "اكتشف ضعف كوكيز الجلسة"},
        ],
        "hints": [
            {"en": "The fixture lives in storage/labs/ — open it in the Log & File Lab viewer, or read it in any text editor.", "ar": "الملف موجود في storage/labs — افتحه من عارض الملفات أو بأي محرر نصوص."},
            {"en": "NEXUS flags a missing header as a finding when it is *absent*, not when it is weak.", "ar": "تعتمد المنصة على غياب الرأس أساسًا للنتيجة، وليس ضعفه."},
            {"en": "A session cookie needs three attributes to be safe on HTTPS: Secure, HttpOnly and SameSite.", "ar": "الكوكي الآمن على HTTPS يحتاج ثلاث سمات: Secure وHttpOnly وSameSite."},
        ],
        "checks": [
            _file_check(
                "auto_missing_headers",
                60,
                label_en="The analyzer confirms the missing defence headers",
                label_ar="يؤكد المحلل غياب الرؤوس الدفاعية",
                spec={"kind": "http", "file": "lab_captured_headers.txt", "assert": "issue_check_ids", "value": ["http_hsts_missing", "http_csp_missing"]},
            ),
            _file_check(
                "auto_cookie_issues",
                40,
                label_en="The cookie analyzer confirms session cookie weaknesses",
                label_ar="يؤكد محلل الكوكيز ضعف كوكيز الجلسة",
                spec={"kind": "http", "file": "lab_captured_headers.txt", "assert": "issue_check_ids", "value": ["cookie_insecure_session", "cookie_no_httponly_session"]},
            ),
            _quiz(
                "q_clickjacking",
                50,
                label_en="Which control stops framing?",
                label_ar="أي ضابط يمنع تأطير الصفحة؟",
                question_en="Which response-header combination is the current-best defence against clickjacking?",
                question_ar="أي توليفة رؤوس استجابة تُعد الأفضل حاليًا لمنع clickjacking؟",
                options=[
                    {"id": "xfo", "en": "X-Frame-Options: DENY only", "ar": "X-Frame-Options: DENY فقط"},
                    {"id": "csp_frame", "en": "Content-Security-Policy: frame-ancestors 'none' (with X-Frame-Options for old clients)", "ar": "CSP مع frame-ancestors 'none' مع X-Frame-Options للعملاء القدامى"},
                    {"id": "hsts", "en": "Strict-Transport-Security only", "ar": "Strict-Transport-Security فقط"},
                    {"id": "nosniff", "en": "X-Content-Type-Options: nosniff", "ar": "X-Content-Type-Options: nosniff"},
                ],
                answer="csp_frame",
                explanation_en="CSP frame-ancestors supersedes X-Frame-Options in modern browsers; keep XFO for legacy clients.",
                explanation_ar="يحدّث CSP إطار الأسلاف بديلًا عن X-Frame-Options في المتصفحات الحديثة، مع إبقائه للعملاء القدامى.",
            ),
        ],
        "target_kind": "file",
        "target_ref": "labs/lab_captured_headers.txt",
        "order_index": 10,
    },
    {
        "slug": "cookies-hardening",
        "category": "http",
        "level": "beginner",
        "points": 150,
        "title_en": "Harden session cookies",
        "title_ar": "تقوية كوكيز الجلسة",
        "description_en": "Classify every cookie attribute issue in the captured response and decide the correct fix.",
        "description_ar": "صنّف كل مشكلة في سمات الكوكيز داخل الاستجابة الملتقطة وحدد الإصلاح الصحيح.",
        "objectives": [
            {"key": "flags", "label_en": "Name the three protective cookie attributes", "label_ar": "اذكر السمات الثلاث لحماية الكوكيز"},
            {"key": "samesite", "label_en": "Explain when SameSite=None is legitimate", "label_ar": "اشرح متى يكون SameSite=None مشروعًا"},
        ],
        "hints": [
            {"en": "Compare the two Set-Cookie headers: one is a session cookie, the other only stores a theme.", "ar": "قارن رأسي Set-Cookie: أحدهما جلسة والآخر يحفظ المظهر فقط."},
        ],
        "checks": [
            _file_check(
                "auto_cookie_analyzer",
                80,
                label_en="Cookie analyzer confirms all three weaknesses on the session cookie",
                label_ar="يؤكد المحلل الثلاث نقاط الضعف على كوكي الجلسة",
                spec={
                    "kind": "http",
                    "file": "lab_captured_headers.txt",
                    "assert": "issue_check_ids",
                    "value": ["cookie_insecure_session", "cookie_no_httponly_session", "cookie_no_samesite_session"],
                },
            ),
            _quiz(
                "q_samesite_none",
                70,
                label_en="SameSite=None",
                label_ar="SameSite=None",
                question_en="When is SameSite=None the correct choice?",
                question_ar="متى يكون SameSite=None هو الخيار الصحيح؟",
                options=[
                    {"id": "never", "en": "Never — it is always unsafe", "ar": "أبدًا — غير آمن دائمًا"},
                    {"id": "cross_site_secure", "en": "Only for cookies that genuinely must be sent in cross-site requests, and always together with Secure", "ar": "فقط للكوكيز التي يجب إرسالها فعلًا في طلبات عبر المواقع، ومع Secure دائمًا"},
                    {"id": "http_only", "en": "Whenever the site runs on HTTP", "ar": "كلما كان الموقع يعمل على HTTP"},
                ],
                answer="cross_site_secure",
                explanation_en="None disables the browser's Lax default; browsers require Secure alongside it, so it is only for legitimate cross-site flows (e.g. embedded checkout).",
                explanation_ar="القيمة None تعطّل الافتراضي Lax؛ تشترط المتصفحات Secure معها، لذا تُستخدم فقط لتدفقات مشروعة عبر المواقع.",
            ),
        ],
        "target_kind": "file",
        "target_ref": "labs/lab_captured_headers.txt",
        "order_index": 20,
    },
    # ----------------------------------------------------------------- pcap
    {
        "slug": "pcap-dns-tunnel",
        "category": "pcap",
        "level": "intermediate",
        "points": 200,
        "title_en": "Find DNS tunnelling in a capture",
        "title_ar": "اكتشف نفق DNS داخل ملف التقاط",
        "description_en": "A real PCAP contains encoded queries. Let the PCAP engine prove it, then explain the technique.",
        "description_ar": "ملف PCAP حقيقي يحتوي استعلامات مُشفّرة. دع محرك التحليل يثبت ذلك ثم اشرح الأسلوب.",
        "objectives": [
            {"key": "detect", "label_en": "Produce at least two suspicious-query detections with the PCAP engine", "label_ar": "أنتج كشفين على الأقل للاستعلامات المشبوهة عبر محرك PCAP"},
            {"key": "explain", "label_en": "Name the exfiltration technique", "label_ar": "اذكر أسلوب تسريب البيانات"},
        ],
        "hints": [
            {"en": "Long labels and high entropy in subdomains are the giveaway; the engine measures both.", "ar": "العلامة الفارقة هي طول النطاقات الفرعية وارتفاع العشوائية، وكلاهما يقيسه المحرك."},
            {"en": "Look at the TLD too — some TLDs are heavily abused.", "ar": "لاحظ النطاق الأعلى أيضًا — بعض النطاقات الأعلى يُساء استخدامها بكثافة."},
        ],
        "checks": [
            _file_check(
                "auto_dns_entropy",
                120,
                label_en="PCAP engine flags at least two suspicious queries",
                label_ar="يرصد محرك PCAP استعلامين مشبوهين على الأقل",
                spec={"kind": "pcap", "file": "lab_traffic.pcap", "assert": "dns_suspicious_min", "value": 2},
            ),
            _quiz(
                "q_tunnel_name",
                80,
                label_en="Name the technique",
                label_ar="سمِّ الأسلوب",
                question_en="Which technique embeds data in DNS query names so that firewall-allowlisted DNS becomes an exfiltration channel?",
                question_ar="أي أسلوب يضع البيانات داخل أسماء استعلامات DNS لتتحول إلى قناة تسريب عبر المنفذ المسموح؟",
                options=[
                    {"id": "dns_spoof", "en": "DNS spoofing", "ar": "انتحال DNS"},
                    {"id": "dns_tunnel", "en": "DNS tunnelling (T1071.004)", "ar": "نفق DNS (T1071.004)"},
                    {"id": "dga", "en": "Domain generation algorithm", "ar": "خوارزمية توليد النطاقات"},
                    {"id": "zone_transfer", "en": "Zone transfer", "ar": "نقل المنطقة"},
                ],
                answer="dns_tunnel",
                explanation_en="The query name is the payload; encoding keeps it alphanumeric so it passes name validation. Real defence is resolver logging plus entropy/volume detection.",
                explanation_ar="اسم الاستعلام هو الحمولة، والترميز يجعله أبجديًا رقميًا ليتجاوز التحقق. الدفاع الحقيقي: تسجيل استعلامات المُحلِّل + كشف العشوائية والحجم.",
            ),
        ],
        "target_kind": "file",
        "target_ref": "labs/lab_traffic.pcap",
        "order_index": 30,
    },
    {
        "slug": "pcap-cleartext-credentials",
        "category": "pcap",
        "level": "intermediate",
        "points": 200,
        "title_en": "Cleartext credentials on the wire",
        "title_ar": "بيانات اعتماد مكشوفة على الشبكة",
        "description_en": "Two separate credential leaks hide in the same capture. Find both, then choose the correct remediation.",
        "description_ar": "تسريبان مختلفان لبيانات الاعتماد في الملف نفسه. اعثر عليهما واختر الإصلاح الصحيح.",
        "objectives": [
            {"key": "find", "label_en": "Let the engine confirm both credential patterns", "label_ar": "دع المحرك يؤكد نمطي التسريب"},
            {"key": "fix", "label_en": "Choose the correct protocol remediation", "label_ar": "اختر الإصلاح البروتوكولي الصحيح"},
        ],
        "hints": [
            {"en": "One leak is a header, the other is a request body.", "ar": "أحدهما في رؤوس الطلب والآخر في جسمه."},
        ],
        "checks": [
            _file_check(
                "auto_credentials",
                120,
                label_en="Engine finds at least two cleartext credential leaks",
                label_ar="يعثر المحرك على تسريبين على الأقل",
                spec={"kind": "pcap", "file": "lab_traffic.pcap", "assert": "credentials_min", "value": 2},
            ),
            _quiz(
                "q_fix_protocol",
                80,
                label_en="Correct remediation",
                label_ar="الإصلاح الصحيح",
                question_en="What is the correct, durable fix for credentials travelling in cleartext?",
                question_ar="ما الإصلاح الصحيح والمستدام لبيانات الاعتماد المنقولة بوضوح؟",
                options=[
                    {"id": "warn", "en": "User education only", "ar": "توعية المستخدمين فقط"},
                    {"id": "tls", "en": "Move the service to its TLS variant and rotate the exposed credentials", "ar": "نقل الخدمة إلى نسختها المشفّرة مع تغيير بيانات الاعتماد المكشوفة"},
                    {"id": "obscure", "en": "Encode credentials in base64", "ar": "ترميز بيانات الاعتماد بـ base64"},
                ],
                answer="tls",
                explanation_en="Base64 is encoding, not encryption. Only TLS removes the exposure, and anything that was captured must be rotated.",
                explanation_ar="Base64 ترميز وليس تشفيرًا. الوحيد الذي يزيل التعرض هو TLS، وكل ما التُقط يجب تغييره.",
            ),
        ],
        "target_kind": "file",
        "target_ref": "labs/lab_traffic.pcap",
        "order_index": 40,
    },
    {
        "slug": "pcap-arp-mitm",
        "category": "network",
        "level": "advanced",
        "points": 220,
        "title_en": "ARP conflict → on-path attack",
        "title_ar": "تعارض ARP ← هجوم في المسار",
        "description_en": "One IP, two MAC addresses. Prove the on-path (MITM) indicator with the engine, then write the switch-side defence.",
        "description_ar": "عنوان IP واحد بعنوانين MAC. أثبت مؤشر الهجوم ثم اذكر الدفاع على مستوى المُبدّل.",
        "objectives": [
            {"key": "prove", "label_en": "Engine reports the ARP conflict", "label_ar": "يُبلغ المحرك عن تعارض ARP"},
            {"key": "defend", "label_en": "Choose the correct switch defence", "label_ar": "اختر دفاع المُبدّل الصحيح"},
        ],
        "hints": [
            {"en": "The engine keeps a per-IP MAC table while parsing the capture.", "ar": "يحتفظ المحرك بجدول يربط كل IP بعناوين MAC أثناء التحليل."},
        ],
        "checks": [
            _file_check(
                "auto_arp_conflict",
                120,
                label_en="Engine detects the ARP conflict",
                label_ar="يكشف المحرك تعارض ARP",
                spec={"kind": "pcap", "file": "lab_traffic.pcap", "assert": "arp_conflicts_min", "value": 1},
            ),
            _quiz(
                "q_arp_defence",
                100,
                label_en="Switch-side defence",
                label_ar="الدفاع على مستوى المُبدّل",
                question_en="Which switch feature directly blocks a rogue ARP responder on the access port?",
                question_ar="أي ميزة في المُبدّل تمنع مستجيب ARP المزيّف على المنفذ مباشرةً؟",
                options=[
                    {"id": "dai", "en": "Dynamic ARP Inspection with DHCP snooping", "ar": "Dynamic ARP Inspection مع DHCP snooping"},
                    {"id": "stp", "en": "Spanning tree", "ar": "بروتوكول الشجرة الممتدة"},
                    {"id": "qos", "en": "QoS prioritisation", "ar": "أولوية QoS"},
                    {"id": "vlan", "en": "VLAN tagging", "ar": "وسم VLAN"},
                ],
                answer="dai",
                explanation_en="DAI validates ARP packets against the DHCP snooping binding table and drops forgeries; static ARP or port security is a stopgap.",
                explanation_ar="يتحقق DAI من حزم ARP مقابل جدول ربط DHCP snooping ويسقط الرسائل المزيّفة، أما ARP الساكن فهما حلّ مؤقت.",
            ),
        ],
        "target_kind": "file",
        "target_ref": "labs/lab_traffic.pcap",
        "order_index": 50,
    },
    # ----------------------------------------------------------------- logs
    {
        "slug": "logs-web-attacks",
        "category": "logs",
        "level": "intermediate",
        "points": 200,
        "title_en": "Read the web server's attack log",
        "title_ar": "اقرأ سجل الهجمات على خادم الويب",
        "description_en": "A real nginx access log holds several distinct attacks. The detection engine grades your analysis with its built-in rules.",
        "description_ar": "سجل وصول nginx حقيقي يحمل عدة هجمات. يقيّم محرك الكشف تحليلك عبر قواعده المدمجة.",
        "objectives": [
            {"key": "format", "label_en": "Detect the log format automatically", "label_ar": "اكتشف صيغة السجل تلقائيًا"},
            {"key": "attacks", "label_en": "Hit the SQL injection and scanner rules", "label_ar": "فعّل قاعدتي حقن SQL وكاشف الأدوات"},
            {"key": "attribution", "label_en": "Identify the attacker IP", "label_ar": "حدد عنوان IP المهاجم"},
        ],
        "hints": [
            {"en": "Ingest the file through NEXUS SOC → log upload (or run the log engine) so the rules run for real.", "ar": "ارفع الملف عبر قسم SOC ثم رفع السجلات، أو شغّل محرك السجلات لتعمل القواعد فعليًا."},
            {"en": "The scanner identifies itself in the user-agent.", "ar": "الأداة تعرّف بنفسها في ترويسة user-agent."},
        ],
        "checks": [
            _file_check(
                "auto_format",
                40,
                label_en="Format detected as nginx",
                label_ar="تم كشف الصيغة nginx",
                spec={"kind": "logs", "file": "lab_nginx_access.log", "assert": "format", "value": "nginx"},
            ),
            _file_check(
                "auto_sqli_rule",
                70,
                label_en="SQL injection rule matches at least 3 events",
                label_ar="قاعدة حقن SQL تطابق 3 أحداث على الأقل",
                spec={"kind": "logs", "file": "lab_nginx_access.log", "assert": "rule_events", "rule": "SQL injection attempts", "min": 3},
            ),
            _file_check(
                "auto_scanner_rule",
                40,
                label_en="Scanner user-agent rule matches",
                label_ar="قاعدة أداة الفحص تطابق",
                spec={"kind": "logs", "file": "lab_nginx_access.log", "assert": "rule_events", "rule": "Automated scanner user-agent", "min": 1},
            ),
            _quiz(
                "q_attacker_ip",
                50,
                label_en="Attacker IP",
                label_ar="عنوان المهاجم",
                question_en="Which single source IP performed the SQL injection and path-probing activity?",
                question_ar="ما عنوان IP الوحيد الذي نفّذ حقن SQL ومسح المسارات؟",
                options=[
                    {"id": "a", "en": "203.0.113.9", "ar": "203.0.113.9"},
                    {"id": "b", "en": "198.51.100.23", "ar": "198.51.100.23"},
                    {"id": "c", "en": "10.20.30.40", "ar": "10.20.30.40"},
                ],
                answer="b",
                explanation_en="198.51.100.23 appears in every attack line; 203.0.113.9 is normal browsing.",
                explanation_ar="العنوان 198.51.100.23 يظهر في كل سطر هجومي، بينما 203.0.113.9 تصفح طبيعي.",
            ),
        ],
        "target_kind": "file",
        "target_ref": "labs/lab_nginx_access.log",
        "order_index": 60,
    },
    {
        "slug": "logs-brute-force",
        "category": "logs",
        "level": "intermediate",
        "points": 200,
        "title_en": "Login brute force in the logs",
        "title_ar": "هجوم تخمين على تسجيل الدخول",
        "description_en": "Ten failures then a success — a classic credential-stuffing outcome. Confirm it with the rules, then answer the incident question.",
        "description_ar": "عشر محاولات فاشلة ثم نجاح — نتيجة كلاسيكية لهجوم حشو بيانات الاعتماد. أكّدها بالقواعد ثم أجب عن سؤال الحادثة.",
        "objectives": [
            {"key": "rule", "label_en": "Trigger the authentication brute-force rule", "label_ar": "فعّل قاعدة التخمين على المصادقة"},
            {"key": "response", "label_en": "Choose the correct first response step", "label_ar": "اختر خطوة الاستجابة الأولى الصحيحة"},
        ],
        "hints": [
            {"en": "The rule groups failures per source IP inside a 15-minute window.", "ar": "القاعدة تجمّع الإخفاقات لكل مصدر داخل نافذة 15 دقيقة."},
        ],
        "checks": [
            _file_check(
                "auto_bruteforce_rule",
                110,
                label_en="Brute-force rule matches the login burst",
                label_ar="قاعدة التخمين تطابق وابل محاولات الدخول",
                spec={"kind": "logs", "file": "lab_nginx_access.log", "assert": "rule_events", "rule": "Authentication brute force", "min": 1},
            ),
            _quiz(
                "q_first_response",
                90,
                label_en="First response step",
                label_ar="خطوة الاستجابة الأولى",
                question_en="The attacker succeeded once. What is the FIRST correct response step?",
                question_ar="نجح المهاجم مرة واحدة. ما أول خطوة صحيحة في الاستجابة؟",
                options=[
                    {"id": "block", "en": "Block the IP and consider the incident closed", "ar": "حجب العنوان واعتبار الحادثة مغلقة"},
                    {"id": "revoke", "en": "Disable/rotate the compromised account sessions and credentials, then investigate scope", "ar": "تعطيل/تدوير جلسات وبيانات الحساب المخترق ثم تحديد نطاق الأثر"},
                    {"id": "delete", "en": "Delete the log lines to avoid noise", "ar": "حذف السجلات لتفادي الضجيج"},
                    {"id": "email", "en": "Email the attacker to stop", "ar": "مراسلة المهاجم للتوقف"},
                ],
                answer="revoke",
                explanation_en="A successful login means attacker access exists right now; containment starts with cutting that access, and evidence must be preserved (never deleted).",
                explanation_ar="نجاح الدخول يعني وجود وصول فعلي للمهاجم الآن؛ يبدأ الاحتواء بقطع هذا الوصول مع الحفاظ على الأدلة (ولا تُحذف أبدًا).",
            ),
        ],
        "target_kind": "file",
        "target_ref": "labs/lab_nginx_access.log",
        "order_index": 70,
    },
    {
        "slug": "logs-secret-leak",
        "category": "logs",
        "level": "advanced",
        "points": 250,
        "title_en": "Secrets written into application logs",
        "title_ar": "أسرار مكتوبة داخل سجلات التطبيق",
        "description_en": "JSON application logs contain real-looking secrets and API keys. Detect it with the engine, then handle it like an incident.",
        "description_ar": "سجلات JSON تحوي أسرارًا ومفاتيح API. اكتشفها بالمحرك ثم تعامل معها كحادثة.",
        "objectives": [
            {"key": "detect", "label_en": "Trigger the cleartext-credentials-in-logs rule", "label_ar": "فعّل قاعدة بيانات الاعتماد المكتوبة في السجلات"},
            {"key": "handle", "label_en": "Choose the correct handling order", "label_ar": "اختر ترتيب المعالجة الصحيح"},
        ],
        "hints": [
            {"en": "Search the JSON fixture for 'password', 'api_key' and connection strings.", "ar": "ابحث في ملف JSON عن password وapi_key وسلاسل الاتصال."},
            {"en": "A leaked key is compromised the moment it is written, whether or not anyone reads it.", "ar": "المفتاح المكشوف يُعد مخترقًا لحظة كتابته، سواء قرأه أحد أم لا."},
        ],
        "checks": [
            _file_check(
                "auto_secret_rule",
                140,
                label_en="Cleartext credentials rule matches at least 2 events",
                label_ar="قاعدة الأسرار تطابق حدثين على الأقل",
                spec={"kind": "logs", "file": "lab_app_errors.json", "assert": "rule_events", "rule": "Cleartext credentials in logs", "min": 2},
            ),
            _quiz(
                "q_secret_order",
                110,
                label_en="Correct order of operations",
                label_ar="الترتيب الصحيح للعمليات",
                question_en="What is the correct order after discovering secrets in logs?",
                question_ar="ما الترتيب الصحيح بعد اكتشاف أسرار في السجلات؟",
                options=[
                    {"id": "rotate_then_fix", "en": "Rotate the exposed secrets → remove the logging → purge log retention copies", "ar": "غيّر الأسرار المكشوفة ← أوقف تسجيلها ← أتلف النسخ المحفوظة من السجلات"},
                    {"id": "fix_only", "en": "Only stop logging them; rotation is unnecessary if the file is restricted", "ar": "أوقف التسجيل فقط؛ لا حاجة لتغيير الأسرار إن كان الملف محميًا"},
                    {"id": "purge_first", "en": "Delete all logs first, then investigate later", "ar": "احذف السجلات أولًا ثم تحقق لاحقًا"},
                ],
                answer="rotate_then_fix",
                explanation_en="Rotation comes first because exposure already happened; then stop the leak, then remove stored copies since file permissions are not a guarantee.",
                explanation_ar="التدوير أولًا لأن الكشف حصل فعلًا، ثم إيقاف التسريب، ثم إتلاف النسخ المحفوظة لأن صلاحيات الملفات ليست ضمانًا.",
            ),
        ],
        "target_kind": "file",
        "target_ref": "labs/lab_app_errors.json",
        "order_index": 80,
    },
    # ------------------------------------------------------------------ tls
    {
        "slug": "tls-legacy-certificate",
        "category": "vuln_hunt",
        "level": "intermediate",
        "points": 220,
        "title_en": "An expired, weak certificate in the inventory",
        "title_ar": "شهادة منتهية بمفتاح ضعيف في الجرد",
        "description_en": "A genuine X.509 certificate from a legacy system. Three independent problems hide in it — the verifier reads the real certificate.",
        "description_ar": "شهادة X.509 حقيقية من نظام قديم. ثلاث مشكلات مستقلة داخلها، والمتحقق يقرأ الشهادة الفعلية.",
        "objectives": [
            {"key": "expiry", "label_en": "Confirm the certificate is expired", "label_ar": "أكّد أن الشهادة منتهية"},
            {"key": "keysize", "label_en": "Confirm the key size is below today's minimum", "label_ar": "أكّد أن حجم المفتاح أقل من الحد الأدنى اليوم"},
            {"key": "fix", "label_en": "Choose the correct replacement policy", "label_ar": "اختر سياسة الاستبدال الصحيحة"},
        ],
        "hints": [
            {"en": "openssl x509 -in storage/labs/lab_legacy_cert.pem -noout -text works if you have OpenSSL; NEXUS reads it for you otherwise.", "ar": "يمكنك استخدام openssl لعرض الشهادة، أو دع المنصة تقرأها."},
        ],
        "checks": [
            _file_check(
                "auto_expired",
                70,
                label_en="Certificate is expired",
                label_ar="الشهادة منتهية",
                spec={"kind": "tls", "file": "lab_legacy_cert.pem", "assert": "expired"},
            ),
            _file_check(
                "auto_keysize",
                70,
                label_en="RSA key below 2048 bits",
                label_ar="مفتاح RSA أقل من 2048 بت",
                spec={"kind": "tls", "file": "lab_legacy_cert.pem", "assert": "key_size_lt", "value": 2048},
            ),
            _quiz(
                "q_renewal_policy",
                80,
                label_en="Replacement policy",
                label_ar="سياسة الاستبدال",
                question_en="What is the correct long-term fix for legacy certificates like this one?",
                question_ar="ما الإصلاح الصحيح طويل الأمد لشهادات قديمة كهذه؟",
                options=[
                    {"id": "renew_rsa", "en": "Renew for another 10 years with a 1024-bit key (it still works)", "ar": "تجديد لعشر سنوات بمفتاح 1024 بت لأنه ما زال يعمل"},
                    {"id": "ecdsa_short", "en": "Replace with a modern key (RSA ≥3072 or ECDSA P-256) and automate renewal with short lifetimes", "ar": "الاستبدال بمفتاح حديث (RSA ≥3072 أو ECDSA P-256) مع تجديد آلي ومدة صلاحية قصيرة"},
                    {"id": "self_signed", "en": "Replace with a self-signed certificate to skip the CA", "ar": "استبدالها بشهادة موقّعة ذاتيًا لتجاوز المرجع"},
                ],
                answer="ecdsa_short",
                explanation_en="Short-lived, automated certificates shrink the window a compromised key is useful; 1024-bit RSA is deprecated and long validity invites silent expiry.",
                explanation_ar="الشهادات قصيرة العمر المُجدّدة آليًا تقلّص نافذة استغلال أي مفتاح مسرّب، ومفتاح 1024 بت مهمل والصلاحية الطويلة تؤجل الانتباه للانتهاء.",
            ),
        ],
        "target_kind": "file",
        "target_ref": "labs/lab_legacy_cert.pem",
        "order_index": 90,
    },
    # --------------------------------------------------------- project work
    {
        "slug": "first-asm-scan",
        "category": "dns",
        "level": "beginner",
        "points": 150,
        "title_en": "Your first authorized discovery scan",
        "title_ar": "أول فحص استكشاف مصرّح به",
        "description_en": "Practice the real workflow: define scope → run discovery → verify assets landed. The verifier reads your project's own data.",
        "description_ar": "تدرّب على سير العمل الحقيقي: حدد النطاق ← شغّل الاستكشاف ← تحقّق من وصول الأصول. يقرأ المتحقق بيانات مشروعك الفعلية.",
        "objectives": [
            {"key": "scope", "label_en": "Create a scope entry you are authorized to test", "label_ar": "أنشئ نطاقًا مصرّحًا لك بفحصه"},
            {"key": "scan", "label_en": "Run an asset_discovery scan to completion", "label_ar": "شغّل فحص استكشاف أصول حتى الإكمال"},
            {"key": "assets", "label_en": "Confirm at least one asset was recorded", "label_ar": "أكّد تسجيل أصل واحد على الأقل"},
        ],
        "hints": [
            {"en": "Add your scope under Project → Scope. Use a domain you own or are contractually authorized to test.", "ar": "أضف النطاق من صفحة المشروع ← النطاق. استخدم نطاقًا تملكه أو لديك تفويض مكتوب بفحصه."},
            {"en": "Scans appear under Web Security Center → New scan; pick the passive profile for a first run.", "ar": "الفحوصات تظهر في مركز أمن الويب ← فحص جديد؛ اختر الملف السلبي في البداية."},
        ],
        "checks": [
            _project_check(
                "auto_scope",
                40,
                label_en="At least one active scope entry exists",
                label_ar="يوجد نطاق نشط واحد على الأقل",
                spec={"kind": "project", "assert": "scopes_min", "value": 1},
            ),
            _project_check(
                "auto_discovery_ran",
                60,
                label_en="An asset_discovery scan completed in this project",
                label_ar="اكتمل فحص استكشاف أصول في هذا المشروع",
                spec={"kind": "project", "assert": "scan_kind_completed", "value": "asset_discovery"},
            ),
            _project_check(
                "auto_assets",
                50,
                label_en="At least one asset recorded",
                label_ar="تم تسجيل أصل واحد على الأقل",
                spec={"kind": "project", "assert": "assets_min", "value": 1},
            ),
        ],
        "target_kind": "none",
        "target_ref": "",
        "order_index": 100,
    },
    {
        "slug": "incident-triage-order",
        "category": "fix",
        "level": "advanced",
        "points": 250,
        "title_en": "Incident triage: prove your judgement",
        "title_ar": "فرز الحوادث: أثبت حكمتك",
        "description_en": "A pure judgement lab: three incident scenarios with exactly one defensible answer each, based on established IR practice.",
        "description_ar": "مختبر حكم بحت: ثلاث سيناريوهات حوادث بإجابة واحدة سليمة لكل منها وفق الممارسة المعتمدة.",
        "objectives": [
            {"key": "order", "label_en": "Get the containment order right", "label_ar": "رتّب خطوات الاحتواء بشكل صحيح"},
            {"key": "evidence", "label_en": "Preserve evidence correctly", "label_ar": "احفظ الأدلة بالشكل الصحيح"},
            {"key": "comms", "label_en": "Choose the right communication trigger", "label_ar": "اختر مُحفّز الإبلاغ الصحيح"},
        ],
        "hints": [
            {"en": "Order matters: contain → preserve → eradicate → recover → lessons.", "ar": "الترتيب مهم: احتوِ ← حافظ على الأدلة ← استأصل ← تعافَ ← دروس."},
        ],
        "checks": [
            _quiz(
                "q_containment_order",
                80,
                label_en="Containment ordering",
                label_ar="ترتيب الاحتواء",
                question_en="Ransomware is spreading across file shares right now. Which action comes first?",
                question_ar="برمجية فدية تنتشر على المشاركات الآن. ما الإجراء الأول؟",
                options=[
                    {"id": "isolate", "en": "Disconnect affected segments/hosts from the network to stop propagation", "ar": "افصل الشبكات والمضيفين المتأثرين لإيقاف الانتشار"},
                    {"id": "rebuild", "en": "Rebuild the servers immediately", "ar": "أعد بناء الخوادم فورًا"},
                    {"id": "pay", "en": "Contact the payment channel first", "ar": "تواصل مع قناة الدفع أولًا"},
                    {"id": "wait", "en": "Wait for all backups to finish", "ar": "انتظر انتهاء النسخ الاحتياطية"},
                ],
                answer="isolate",
                explanation_en="Stopping propagation limits damage; everything else (rebuild, recovery) comes after containment and evidence capture.",
                explanation_ar="إيقاف الانتشار يحدّ الضرر، وكل ما بعده من إعادة بناء وتعافٍ يأتي بعد الاحتواء وتوثيق الأدلة.",
            ),
            _quiz(
                "q_evidence",
                80,
                label_en="Evidence handling",
                label_ar="التعامل مع الأدلة",
                question_en="A compromised laptop is still running. What preserves the most defensible evidence?",
                question_ar="حاسوب مخترق ما زال يعمل. ما الذي يحفظ أقوى دليل قابل للدفاع؟",
                options=[
                    {"id": "shutdown", "en": "Shut it down at once", "ar": "أطفئه فورًا"},
                    {"id": "capture_live", "en": "Capture volatile memory and network state first, then isolate and image", "ar": "التقط الذاكرة المتغيرة وحالة الشبكة أولًا ثم اعزل وصوّر القرص"},
                    {"id": "reimage", "en": "Re-image it directly to save time", "ar": "أعد تصويره مباشرة لتوفير الوقت"},
                    {"id": "scandisk", "en": "Run antivirus clean-up first", "ar": "شغّل مضاد الفيروسات أولًا"},
                ],
                answer="capture_live",
                explanation_en="RAM and live connections vanish on power-off; volatile evidence must be captured before isolation/darkening.",
                explanation_ar="الذاكرة والاتصالات النشطة تختفي بانقطاع الطاقة؛ تُلتقط الأدلة المتطايرة قبل العزل.",
            ),
            _quiz(
                "q_comms",
                90,
                label_en="Communication trigger",
                label_ar="مُحفّز الإبلاغ",
                question_en="When does an incident become reportable to regulators/clients?",
                question_ar="متى تصبح الحادثة قابلة للإبلاغ للجهات التنظيمية أو العملاء؟",
                options=[
                    {"id": "always", "en": "Every alert, regardless of impact", "ar": "كل تنبيه مهما كان أثره"},
                    {"id": "never", "en": "Never before full attribution", "ar": "لا أبدًا قبل الإسناد الكامل"},
                    {"id": "policy", "en": "According to legal/policy thresholds: confirmed impact, personal-data or critical-service involvement", "ar": "بحسب عتبات السياسة والقانون: أثر مؤكد أو بيانات شخصية أو خدمة حرجة"},
                ],
                answer="policy",
                explanation_en="Notification duty follows defined thresholds (e.g. personal-data breach, critical service impact), which should be pre-agreed with legal — not improvised.",
                explanation_ar="واجب الإبلاغ يتبع عتبات محددة مسبقًا بالاتفاق مع الإدارة القانونية، لا اجتهادًا لحظيًا.",
            ),
        ],
        "target_kind": "none",
        "target_ref": "",
        "order_index": 110,
    },
)


def sync_labs(db: Session) -> dict[str, int]:
    """Insert/refresh the built-in labs. Never deletes user runs."""
    created = updated = 0
    for definition in LAB_DEFINITIONS:
        lab = db.execute(select(Lab).where(Lab.slug == definition["slug"])).scalar_one_or_none()
        fields = {
            "title_ar": definition["title_ar"],
            "title_en": definition["title_en"],
            "category": definition["category"],
            "level": definition["level"],
            "points": definition["points"],
            "description_ar": definition["description_ar"],
            "description_en": definition["description_en"],
            "objectives": definition["objectives"],
            "hints": definition["hints"],
            "checks": definition["checks"],
            "target_kind": definition["target_kind"],
            "target_ref": definition["target_ref"],
            "resource_limits": {"timeout_seconds": 300, "max_file_mb": 25},
            "requires_private_access": False,
            "enabled": True,
            "order_index": definition["order_index"],
        }
        if lab is None:
            db.add(Lab(slug=definition["slug"], **fields))
            created += 1
        else:
            # update content but preserve nothing user-owned (Lab has no user state)
            for key, value in fields.items():
                setattr(lab, key, value)
            updated += 1
    db.commit()
    log.info("labs synced: %s created, %s updated", created, updated)
    return {"created": created, "updated": updated, "total": len(LAB_DEFINITIONS)}
