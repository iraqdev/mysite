# DNZ Team - موقع فريق المطورين العراقيين

موقع ويب احترافي لفريق المطورين العراقيين متخصص في البرمجة والذكاء الاصطناعي وتطوير التطبيقات.

## المميزات

- 🎨 تصميم احترافي وجذاب
- 📱 متجاوب مع جميع الأجهزة
- 📧 نموذج تواصل يعمل مع البريد الإلكتروني
- 🌐 واجهة عربية كاملة
- ⚡ سريع وخفيف

## المتطلبات

- Python 3.7+
- Flask
- Flask-Mail

## التثبيت والتشغيل

### 1. تثبيت المتطلبات

```bash
pip install -r requirements.txt
```

### 2. إعداد البريد الإلكتروني

#### الخيار الأول: Gmail (مجاني)
1. اذهب إلى [Google Account Settings](https://myaccount.google.com/)
2. فعّل "2-Step Verification"
3. اذهب إلى "App passwords"
4. أنشئ كلمة مرور للتطبيق
5. عدّل ملف `app.py`:

```python
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_app_password'
```

#### الخيار الثاني: Outlook/Hotmail (مجاني)
1. اذهب إلى [Outlook Security Settings](https://account.live.com/proofs/AppPassword)
2. أنشئ كلمة مرور للتطبيق
3. عدّل ملف `app.py`:

```python
app.config['MAIL_SERVER'] = 'smtp-mail.outlook.com'
app.config['MAIL_USERNAME'] = 'your_email@outlook.com'
app.config['MAIL_PASSWORD'] = 'your_app_password'
```

### 3. تشغيل الموقع

```bash
python app.py
```

الموقع سيعمل على: `http://localhost:5000`

## نشر الموقع على الإنترنت (مجاناً)

### الخيار الأول: Render (مجاني)
1. اذهب إلى [Render.com](https://render.com)
2. أنشئ حساب جديد
3. اختر "New Web Service"
4. اربط حساب GitHub
5. اختر المشروع
6. اكتب الأمر: `python app.py`
7. اكتب Port: `5000`

### الخيار الثاني: Railway (مجاني)
1. اذهب إلى [Railway.app](https://railway.app)
2. اربط حساب GitHub
3. اختر المشروع
4. اكتب الأمر: `python app.py`

### الخيار الثالث: Heroku (مجاني)
1. اذهب إلى [Heroku.com](https://heroku.com)
2. أنشئ حساب جديد
3. اربط حساب GitHub
4. اختر المشروع
5. اكتب الأمر: `python app.py`

## إعداد البريد الإلكتروني coding@dnzteam.com

### الخيار الأول: Gmail (مجاني)
1. اذهب إلى [Google Workspace](https://workspace.google.com)
2. اختر "Get started"
3. اختر "Business Starter" (مجاني)
4. أدخل اسم النطاق: `dnzteam.com`
5. اتبع التعليمات لإعداد النطاق

### الخيار الثاني: Zoho Mail (مجاني)
1. اذهب إلى [Zoho Mail](https://zoho.com/mail)
2. اختر "Free Forever"
3. أدخل اسم النطاق: `dnzteam.com`
4. اتبع التعليمات لإعداد النطاق

### الخيار الثالث: Yandex 360 (مجاني)
1. اذهب إلى [Yandex 360](https://360.yandex.com)
2. اختر "Free"
3. أدخل اسم النطاق: `dnzteam.com`
4. اتبع التعليمات لإعداد النطاق

## هيكل المشروع

```
mysiteandemail/
├── app.py                 # التطبيق الرئيسي
├── requirements.txt       # المتطلبات
├── README.md             # هذا الملف
├── templates/            # قوالب HTML
│   ├── home.html        # الصفحة الرئيسية
│   └── contact.html     # صفحة التواصل
└── static/              # الملفات الثابتة
    └── css/
        └── style.css    # ملف CSS
```

## الملفات المطلوبة

- `app.py` - التطبيق الرئيسي
- `requirements.txt` - متطلبات Python
- `templates/` - قوالب HTML
- `static/css/style.css` - ملف التصميم

## ملاحظات مهمة

1. **البريد الإلكتروني**: تأكد من إعداد كلمة مرور التطبيق وليس كلمة مرور الحساب العادية
2. **الأمان**: لا تشارك كلمات المرور في الكود
3. **النطاق**: يمكنك استخدام نطاق فرعي مثل `mail.dnzteam.com` إذا لم يكن لديك نطاق رئيسي
4. **المجانية**: جميع الخدمات المذكورة مجانية تماماً

## الدعم

إذا واجهت أي مشاكل، تأكد من:
- تثبيت جميع المتطلبات
- إعداد البريد الإلكتروني بشكل صحيح
- تشغيل الموقع على المنفذ الصحيح

## الترخيص

هذا المشروع مفتوح المصدر ومتاح للاستخدام التجاري والشخصي.
