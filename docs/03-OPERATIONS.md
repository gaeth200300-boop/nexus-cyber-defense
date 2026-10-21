# NEXUS — التشغيل والصيانة

## 1. البيئة المحلية على Windows

### التثبيت لأول مرة

```bat
SETUP-NEXUS.cmd
```

يقوم بـ:

1. إنشاء `backend\.venv` وتثبيت متطلبات Python.
2. إنشاء `backend\.env` بمفتاح سري عشوائي حقيقي.
3. تثبيت متطلبات الواجهة.
4. تطبيق ترحيلات Alembic.
5. إنشاء المختبرات والحساب الأول.

### التشغيل والإيقاف

```bat
START-NEXUS.cmd
STOP-NEXUS.cmd
scripts\nexus.cmd status
scripts\nexus.cmd logs 80 both
```

`START-NEXUS.cmd` يفتح المتصفح على `http://127.0.0.1:8000` إذا كانت نسخة الإنتاج مبنية، وإلا على `http://127.0.0.1:5173`.

للاستخدام من جهاز آخر (جوال أو كمبيوتر) شغّل `PUBLIC-LINK.cmd` للحصول على رابط عام مؤقت يعمل من أي شبكة.

### الفحوصات والبناء

```bat
scripts\nexus.cmd test
scripts\nexus.cmd build
scripts\nexus.cmd migrate
scripts\nexus.cmd seed
```

## 2. Docker Compose

```bat
copy .env.production.example .env.production
REM عدّل كل REPLACE_WITH_*
docker compose up -d --build
docker compose ps
docker compose logs -f api worker web
docker compose down
docker compose down -v   REM تحذير: يحذف قاعدة البيانات والأدلة
```

الخدمات:

| الخدمة | الوصف | المنفذ |
|---|---|---|
| `db` | PostgreSQL 16 | داخلي |
| `api` | FastAPI + ترحيلات + seed | `8000` |
| `worker` | عامل مهام مستقل | داخلي |
| `web` | Nginx + SPA + تحويل `/api` | `8080` |

الترتيب مضمون عبر `depends_on` + healthchecks: لا يبدأ `worker` قبل أن يصبح `api` صحيًا، ولا تبدأ الواجهة قبل الـAPI.

## 3. الأدلة والتخزين

- `backend\storage\uploads` — الملفات المرفوعة (PCAP/سجلات).
- `backend\storage\evidence` — أدلة النتائج المُنقّاة.
- `backend\storage\reports` — التقارير المولّدة.
- `backend\storage\logs` — سجلات التطبيق.

لا تضع أي ملف من `storage` في Git. احتفظ بنسخة احتياطية من قاعدة البيانات ومجلد `storage` معًا عند النقل.

## 4. النسخ الاحتياطي والاستعادة

### SQLite (تطوير)

```powershell
Copy-Item backend\storage\nexus.db "$env:TEMP\nexus-backup-$(Get-Date -Format yyyyMMdd).db"
```

### PostgreSQL (إنتاج)

```bash
docker compose exec db pg_dump -U nexus nexus > nexus-backup.sql
```

الاستعادة: أوقف الخدمات، استعد قاعدة البيانات، أعد التشغيل، ثم `docker compose exec api python -m alembic upgrade head`.

## 5. استكشاف الأخطاء

| العرض | السبب المحتمل | الحل |
|---|---|---|
| `Port 8000 is busy` | عملية قديمة | `STOP-NEXUS.cmd` ثم `START-NEXUS.cmd` |
| `unable to open database file` | تشغيل CLI من جذر المشروع بدل `backend` | شغّل الأوامر من `backend` أو عبر `scripts\nexus.cmd` |
| الشاشة السوداء عند فتح `index.html` | فتح ملف مباشرة | استخدم `START-NEXUS.cmd` |
| الفحص معلق في `queued` | العامل متوقف | `scripts\nexus.cmd status` ثم أعد تشغيل العامل |
| `database not reachable` في Docker | `POSTGRES_HOST` غير مضبوط | تأكد من `.env.production` وأن `db` سليم |
| تقرير `failed` | خطأ في التوليد | افتح تفاصيل التقرير في الواجهة أو سجلات `api` |

## 6. سجلات مفيدة

```bat
scripts\nexus.cmd logs 120 api
scripts\nexus.cmd logs 120 web
docker compose logs -f --tail=200 api worker
```

## 7. تغيير كلمة المرور

```bat
cd backend
.\.venv\Scripts\python.exe -m app.cli create-admin --email admin@nexus.local --password "كلمة-قوية-جديدة" --role owner --reset
```

ثم سجّل الدخول فورًا للتأكد.
