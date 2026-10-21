# NEXUS — نموذج البيانات

> المصدر التنفيذي: `backend/app/models/`. هذا المستند خريطة مختصرة للمجموعات والعلاقات والحقول الحاكمة.

## 1. المجموعات

| المجموعة | الجداول |
|---|---|
| الهوية والصلاحيات | `users`, `api_keys`, `projects`, `project_members`, `scopes`, `audit_log` |
| الأصول | `assets`, `services`, `asset_changes` |
| الفحص والنتائج | `scans`, `jobs`, `scan_events`, `findings`, `finding_events`, `evidence` |
| الاستخبارات | `cve_records`, `kev_entries`, `finding_intel_links` |
| العمليات (SOC) | `log_sources`, `log_events`, `detection_rules`, `alerts`, `incidents`, `incident_events` |
| التدريب | `labs`, `lab_runs`, `achievements`, `academy_lessons`, `academy_lesson_progress` |
| التقارير والنظام | `reports`, `settings_kv` |

إجمالي الجداول: **31**.

## 2. الهوية والصلاحيات

### `users`
- `email` فريد، `password_hash` (Argon2)، `full_name`، `role`، `is_active`.
- `mfa_enabled`, `mfa_secret_enc`, `recovery_codes_enc`.
- `token_version` لإبطال كل الجلسات عند تغيير كلمة المرور.
- `failed_login_attempts`, `locked_until`.

### `api_keys`
- `key_prefix` للعرض، `key_hash` فريد، `scopes` JSON، `expires_at`, `revoked_at`.

### `projects` / `project_members`
- عزل إلزامي عبر `project_members.role`.
- `projects.allow_private_targets` لا يتجاوز حاجز `netguard` ولا يلغي تفويض النطاق.

### `scopes`
- `kind`, `value`, `include_subdomains`, `allow_active`.
- `authorization_ref`, `authorized_by`, `verified_method`, `verified_at`, `verification_evidence`.
- `expires_at`, `is_active`.
- لا يُسمح بأي اتصال إلا لنطاق نشط غير منتهي.

### `audit_log`
- Append-only ومترابطة بالتجزئة: `prev_hash` → `entry_hash`.
- لا تُحدَّث ولا تُحذف من أي مسار في الواجهة.

## 3. الفحص والنتائج

### `scans`
- `kind`, `profile`, `status`, `progress`, `phases`, `stats`, `targets`, `options`.
- `authorization_snapshot`: إثبات التفويض عند الإنشاء.
- `dedup_key`, `heartbeat_at`, `cancel_requested`, `error`.

### `jobs`
- طابور متين بقاعدة البيانات: `priority`, `status`, `attempts`, `max_attempts`.
- `locked_by`, `lease_expires_at`, `run_after`, `timeout_seconds`.
- فهرس فريد جزئي على `dedup_key` للحالات النشطة فقط.

### `scan_events`
- سجل حي: `level`, `kind`, `phase`, `message`, `data`.
- يُستهلك عبر المسارات أو SSE.

### `findings`
- `fingerprint` فريد لكل مشروع لمنع التكرار.
- `severity`, `confidence`, `status`, `verified`, `active_check`.
- `cwe`, `cve`, `owasp`, `cvss_score`, `cvss_vector`.
- `detected_by`, `engine_version`, `primary_evidence_id`.
- `occurrence_count`, `first_seen_at`, `last_seen_at`, `resolved_at`.

### `finding_events`
- مسار حالة النتيجة: من، متى، من حالة إلى حالة، ولماذا.

### `evidence`
- `kind`, `label`, `request_snippet`, `response_snippet`, `headers`, `body_excerpt`.
- `raw_sha256`, `redacted`, `redactions`.
- تُنقّى الأسرار قبل التخزين.

## 4. الاستخبارات

### `cve_records`
- `cve_id`, `description`, `published`, `last_modified`, `cvss_score`, `cvss_vector`, `cwe`, `references`.
- `source` يميّز NVD عن غيره.

### `kev_entries`
- `cve_id`, `vendor`, `product`, `vulnerability_name`, `due_date`, `ransomware_campaign`.
- `catalog_version`, `date_released`, `synced_at`.

### `finding_intel_links`
- `finding_id`, `cve_id`, `match_type` (`exact`/`inferred`), `confidence`, `evidence`.

## 5. العمليات (SOC)

- `log_sources`: اسم، نوع، تنسيق، حجم، حالة تحليل.
- `log_events`: حدث مطبَّع (وقت، IP، طريقة، URL، حالة، وكيل).
- `detection_rules`: قاعدة DSL آمنة (ليست `eval`).
- `alerts`: تجميع حسب القاعدة/المصدر/الخطورة.
- `incidents` + `incident_events`: ربط التنبيهات بالحوادث.

## 6. التدريب

- `labs`: تعريف المختبر، الصعوبة، الأهداف، الحالة.
- `lab_runs`: محاولة المستخدم، الأدلة، النتيجة.
- `achievements`: شارات مربوطة بإنجاز حقيقي.
- `academy_lessons` + `academy_lesson_progress`: دروس وتقدم.

## 7. التقارير والنظام

- `reports`: `kind`, `format`, `title`, `version`, `status`, `file_path`, `size_bytes`, `sha256`, `summary`.
- `settings_kv`: إعدادات المنصة المتغيرة.

## 8. أدلة إضافية خارج الجداول

- ملفات مرفوعة في `storage/uploads`.
- أدلة نتائج في `storage/evidence`.
- تقارير في `storage/reports`.
- ملفات مختبرات في `storage/labs`.
