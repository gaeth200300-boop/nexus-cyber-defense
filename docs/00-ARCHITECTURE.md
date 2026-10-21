# NEXUS CYBER DEFENSE — المعمارية

> منصة دفاع سيبراني متكاملة: Web Application Security Testing · Penetration Testing Labs · Threat Intelligence · AI Security Copilot · Network Analysis · Security Operations.

## 1. المبادئ المعمارية

1. **لا نتيجة بلا مصدر**: كل سجل في قاعدة البيانات يحمل `source` و`engine_version` و`scan_id` وزمن الاكتشاف.
2. **الأمان أولًا**: كل اتصال خارجي يمر عبر حاجز واحد (`netguard`) يفرض نطاق التفويض (RoE) ويمنع SSRF والشبكات الخاصة و Cloud Metadata.
3. **العزل**: محركات الفحص لا تعمل بصلاحيات الخادم أبدًا؛ تُنفَّذ كمهام محدودة الوقت والموارد مع سياسة خروج شبكي.
4. **لا وهم**: عند غياب مكوّن (ZAP، nmap، مزوّد AI) تظهر حالته صريحة "غير مهيّأ" مع بديل حقيقي، ولا تُعرض بيانات مُلفَّقة كأنها نتائج.
5. **قابلية التتبع**: سجل تدقيق Append-Only، وكل تغيير في حالة ثغرة أو نطاق مُسجَّل بهوية الفاعل والوقت.

## 2. مخطط المكونات

```mermaid
flowchart TB
    subgraph Client["🖥️ الواجهة (React + TypeScript)"]
        UI["Design System\nNEXUS UI Kit"]
        PAGES["Pages\nDashboard · Web Security · ASM · SOC · Labs · Reports"]
        CP["Command Palette"]
        I18N["i18n AR/EN + RTL/LTR"]
        SSE["Live Stream (SSE)"]
    end

    subgraph API["⚙️ الـ API (FastAPI)"]
        AUTH["Auth: JWT + Refresh + MFA + API Keys"]
        RBAC["RBAC + Project Isolation"]
        ROEG["RoE Guard (نطاق التفويض)"]
        RATE["Rate Limiter"]
        AUDIT["Audit Log (append-only)"]
        ROUTES["REST /api/v1/*"]
    end

    subgraph CORE["🧠 النواة"]
        QUEUE["DB-Backed Job Queue\nأولويات · إعادة محاولة · منع تكرار · Lease"]
        WORKER["Worker Pool (محدود الموارد)"]
        EVENTS["Event Bus → SSE"]
        REDACT["Evidence Redactor"]
    end

    subgraph ENGINES["🔬 محركات الفحص"]
        DNS["DNS Engine\ndnspython + crt.sh"]
        TLS["TLS Engine\nssl + cryptography"]
        HTTP["HTTP/Web Engine\nhttpx — headers/cookies/redirects"]
        WEBVULN["Web Vuln Engine\npassive + safe-active (مصرّح)"]
        ZAP["ZAP Adapter\nREST API (اختياري)"]
        NMAP["Nmap Adapter / TCP Scanner"]
        PCAP["PCAP Analyzer\ndpkt"]
        LOGS["Log Analyzer + Rule Engine"]
    end

    subgraph AI["🤖 AI Copilot"]
        PROV["Provider Adapter\nOpenAI · OpenRouter · Azure · Ollama · Custom"]
        GUARD2["Prompt-Injection Guard + Citations + Budget"]
    end

    subgraph INTEL["📡 Threat Intelligence"]
        NVD["NVD 2.0 API (cache)"]
        KEV["CISA KEV Feed"]
    end

    subgraph DATA["🗄️ البيانات"]
        DB[("PostgreSQL / SQLite\nSQLAlchemy 2 + Alembic")]
        FS["Evidence & Reports\n(local object store → S3 لاحقًا)"]
    end

    UI --> ROUTES
    PAGES --> ROUTES
    CP --> ROUTES
    I18N --> UI
    SSE --> EVENTS
    ROUTES --> AUTH --> RBAC --> ROEG --> QUEUE
    ROUTES --> RATE
    ROUTES --> AUDIT
    QUEUE --> WORKER
    WORKER --> ENGINES
    WORKER --> EVENTS
    ENGINES --> ROEG
    ENGINES --> REDACT --> FS
    ENGINES --> DB
    ROUTES --> AI
    PROV --> GUARD2
    AI --> DB
    ROUTES --> INTEL
    NVD --> DB
    KEV --> DB
    ROUTES --> DB
```

## 3. مسار طلب فحص نموذجي

```mermaid
sequenceDiagram
    participant U as المحلل
    participant A as API
    participant Q as Queue (DB)
    participant W as Worker
    participant E as Engine
    participant D as Database

    U->>A: POST /scans (project, assets, profile)
    A->>A: RBAC + RoE: هل كل هدف داخل نطاق مصرّح؟
    A->>D: لقطة تفويض (authorization_snapshot)
    A->>Q: إنشاء Scan + Jobs (dedup_key)
    A-->>U: 201 + scan_id
    U->>A: GET /scans/{id}/stream (SSE)
    W->>Q: claim job (lease + heartbeat)
    W->>E: تشغيل المرحلة (DNS/TLS/HTTP/...)
    E->>E: netguard: resolve → validate → connect
    E->>D: events + findings (+evidence مُنقّح)
    D-->>U: أحداث حية عبر SSE
    W->>Q: job done → next phase
    W->>D: scan completed + stats
```

## 4. نموذج البيانات (الملخص)

| المجموعة | الجداول |
|---|---|
| الهوية والصلاحيات | `users`, `api_keys`, `projects`, `project_members`, `scopes` (RoE), `audit_log` |
| الأصول | `assets`, `services`, `asset_changes` |
| الفحص | `scans`, `jobs`, `events`, `findings`, `finding_events`, `evidence` |
| الاستخبارات | `cve_records`, `kev_entries`, `finding_intel_links` |
| العمليات (SOC) | `log_sources`, `log_events`, `detection_rules`, `alerts`, `incidents`, `incident_events` |
| التدريب | `labs`, `lab_runs`, `achievements` |
| التقارير | `reports` |
| النظام | `settings_kv` |

التفاصيل الكاملة: `docs/05-DATA-MODEL.md` (يُولَّد من `backend/app/models/`).

## 5. البيئات

| البيئة | قاعدة البيانات | العامل | المحركات | ملاحظات |
|---|---|---|---|---|
| **dev-lite** (الوضع الحالي لديك — Windows 10) | SQLite (WAL) | داخل عملية API | DNS/TLS/HTTP/WebVuln/TCP-Scanner/PCAP/Logs (Python خالص) | بلا Docker، بلا صلاحيات مدير؛ Nmap اختياري |
| **dev-docker** | PostgreSQL 16 | عامل مستقل | + nmap داخل الصورة، + ZAP اختياري | `docker-compose.yml` |
| **production** | PostgreSQL 16 (Managed) | N Workers | عوامل معزولة + ZAP + nmap بصلاحيات شبكية محدودة | راجع `docs/03-OPERATIONS.md` |

## 6. حدود معروفة (بصراحة)

- في dev-lite: عامل واحد داخل العملية، لذا الفحوصات المتزامنة محدودة (`NEXUS_MAX_CONCURRENT_SCANS`).
- الفحص النشط (Active) يحتاج تفعيلًا مزدوجًا: على مستوى المنصة + على مستوى النطاق المصرّح + ملف الفحص.
- ZAP غير مهيّأ لديك → تعمل المحركات الداخلية الحقيقية، وتظهر حالة التكامل بوضوح في صفحة `System`.
- nmap غير مثبّت محليًا → يعمل ماسح TCP الداخلي دائمًا؛ صورة Docker تتضمن nmap.
- محرك PCAP يدعم pcap/pcapng شائع الاستخدام؛ بعض الصيغ النادرة قد تُرفض برسالة واضحة بدل فشل صامت.
- بيانات العرض الحالية مولّدة من المحركات نفسها: 7 فحوصات، 18 نتيجة، 10 أصول، 4 خدمات، 4 تنبيهات، 23 حدثًا، 1754 إدخال KEV، 8 سجلات NVD.
