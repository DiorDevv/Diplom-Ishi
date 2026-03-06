# WebSec Analyzer (Diplom ishi) — Django REST Framework

Bu loyiha **web sayt(lar)ni himoyaviy (defensive) maqsadda** tahlil qiladi:  
- **Headers / Cookies** konfiguratsiyalarini tekshiradi  
- HTML va assetlar (JS/CSS) orqali **tech stack** signallarini yig‘adi  
- **Stack fingerprint** (oddiy scoring) qiladi  
- **White-box SCA**: `requirements.txt` yoki `package-lock.json` yuklansa dependency versiyalarini chiqaradi  
- Topilmalar bo‘yicha **hisobot (report)** qaytaradi  
- Celery + Redis orqali scan’ni background’da bajaradi (server “osilib” qolmasin)

> ⚠️ Eslatma: Bu loyiha **buzish/payload/exploit** uchun emas. Faqat **passive audit** va **white-box dependency tahlili** uchun mo‘ljallangan.

---

## ✨ Asosiy imkoniyatlar
- `POST /api/scans/` — URL (va ixtiyoriy dependency file) yuborib scan yaratish
- `GET /api/scans/{id}/` — scan status/progress
- `GET /api/scans/{id}/report/` — findings + components + CVE (demo)
- `POST /api/scans/{id}/run_sync/` — Celery ishlamasa, scan’ni sync ishlatish

---

## ✅ Talablar
- Python 3.10+
- Django + DRF
- (Ixtiyoriy) Redis + Celery

---

## 📦 O‘rnatish (Local)
```bash
git clone <REPO_URL>
cd websec_analyzer

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
