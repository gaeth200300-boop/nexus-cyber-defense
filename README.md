# NEXUS CYBER DEFENSE

> منصة دفاع سيبراني مؤسسية: فحص مصرّح به، استخبارات ثغرات حقيقية، مركز عمليات أمنية، مختبرات تدريب، تقارير قابلة للتدقيق، ومساعد ذكي اختياري — بواجهة عربية/إنجليزية كاملة.

## الحالة الحالية

- **Backend:** FastAPI + Pydantic v2 + SQLAlchemy 2 + Alembic.
- **Frontend:** React 19 + TypeScript + Vite + Tailwind 3.4 + Radix + TanStack Query + ECharts + i18next.
- **Queue:** طابور مهام داخل قاعدة البيانات (أولويات، Lease، Heartbeat، منع تكرار، إعادة محاولة).
- **المحركات:** DNS، TLS، HTTP/Web، Web Vuln، TCP Scanner، PCAP، Log/SOC، NVD 2.0 + CISA KEV.
- **بيانات العرض الحقيقية:** مشروع واحد، 7 فحوصات مكتملة، 18 نتيجة، 10 أصول، 4 خدمات، 4 تنبيهات، 23 حدثًا، 1754 إدخال KEV، و8 سجلات CVE مخزّنة من NVD.
- **الحسابات:** حساب مالك مُهيّأ مسبقًا، وإنشاء حساب ذاتي من الواجهة بدور «مشاهد» (viewer).
- **الاختبارات:** 45 اختبار backend ناجحًا، وفحص TypeScript ناجحًا.

كل الأرقام أعلاه قابلة للتحقق من الواجهة أو من سجلات الأدلة. لا توجد مقاييس تزيينية أو بيانات مُلفَّقة.

## التشغيل على Windows 10

الطريقة الصحيحة هي عبر المشغّل، **وليس** فتح `frontend/index.html` مباشرة:

```bat
START-NEXUS.cmd
```

الأوامر المتاحة:

```bat
SETUP-NEXUS.cmd     REM تثبيت المتطلبات وإنشاء backend\.env وترجمة قاعدة البيانات
START-NEXUS.cmd     REM تشغيل API + واجهة الويب ثم فتح المتصفح
STOP-NEXUS.cmd      REM إيقاف العمليات
scripts\nexus.cmd status
scripts\nexus.cmd logs
scripts\nexus.cmd test
scripts\nexus.cmd build
```

بيانات الدخول الافتراضية للعرض المحلي:

- **المالك:** `admin@nexus.local` / كلمة المرور تُسلَّم بشكل منفصل عن المستودع
- **محلل:** `analyst@nexus.local` / كلمة المرور تُسلَّم بشكل منفصل عن المستودع
- **الرابط:** `http://127.0.0.1:8000` أو `http://127.0.0.1:5173`
- **حساب جديد:** من صفحة الدخول اضغط «إنشاء حساب جديد»؛ يُحفظ الحساب فورًا بدور «مشاهد» ويمكن للمسؤول منحه صلاحيات المشروع.

غيّر كلمة المرور بعد أول دخول، ولا ترسل ملف `backend\.env` أو مجلد `backend\storage` إلى أي شخص.

## التشغيل عبر Docker Compose

```bat
copy .env.production.example .env.production
REM عدّل كل قيمة REPLACE_WITH_* في الملف الجديد
docker compose up -d --build
start http://localhost:8080
```

البنية:

- `db`: PostgreSQL 16.
- `api`: FastAPI، ينفّذ الترحيلات والseed ثم يبدأ الخدمة.
- `worker`: عامل مهام مستقل (نفس الصورة، `NEXUS_INPROCESS_WORKER=false`).
- `web`: Nginx يقدّم واجهة React المبنية ويحوّل `/api` إلى حاوية `api`.
- `nmap` مثبّت داخل صورة الـAPI/العامل، والماسح الداخلي يبقى البديل الذي لا يحتاج صلاحيات.

## بنية المشروع

```text
backend/            FastAPI + المحركات + الطابور + التقارير + الاختبارات
frontend/           React SPA (مصدر) + إعداد Nginx للإنتاج
scripts/            أوامر دورة الحياة على Windows
docs/               المعمارية، الطريق، التشغيل، الأمان، نموذج البيانات، التسليم
.dockerignore      ملفات استبعاد البناء
docker-compose.yml نشر إنتاجي محلي
```

## مبادئ الصدق

1. كل نتيجة تحمل `engine` و`engine_version` و`scan_id` ووقت الاكتشاف.
2. الثقة مسجّلة: `certain` / `firm` / `tentative`.
3. ربط CVE يميّز `exact` عن `inferred`، ولا يُعرض الاستنتاج كتابع مؤكد.
4. عند غياب ZAP أو مزوّد AI تظهر حالته بصراحة "غير مهيّأ" مع بديل حقيقي متاح.
5. لا توجد بيانات تدريب مخفية تظهر كبيانات إنتاج.

## الأمان

- رفض أهداف loopback/private/cloud-metadata افتراضيًا.
- الفحص النشط يتطلب تفعيلًا على مستوى المنصة **و** تفويضًا صريحًا في النطاق.
- JWT + Refresh + MFA/TOTP + API Keys.
- RBAC وعزل المشاريع.
- سجل تدقيق append-only.
- تنقية الأسرار من الأدلة.
- Rate limiting وملفات مرفوعة مقيّدة الحجم.

التفاصيل: `docs/04-SECURITY-AND-COMPLIANCE.md`.

## التوثيق

- `docs/00-ARCHITECTURE.md`
- `docs/01-STACK-AND-ENGINES.md`
- `docs/02-ROADMAP.md`
- `docs/03-OPERATIONS.md`
- `docs/04-SECURITY-AND-COMPLIANCE.md`
- `docs/05-DATA-MODEL.md`
- `docs/06-DELIVERY.md`

## الترخيص

ملكية خاصة لأغراض العرض والتقييم الداخلي. لا تستخدمه لفحص أي هدف دون تفويض كتابي.
