# دليل النشر المجاني - DNZ Team

## نشر الموقع على الإنترنت (مجاناً تماماً)

### الخيار الأول: Render.com (الأسهل والأفضل)

#### الخطوات:
1. اذهب إلى [Render.com](https://render.com) وأنشئ حساب جديد
2. اضغط على "New +" ثم اختر "Web Service"
3. اربط حساب GitHub الخاص بك
4. اختر المشروع `mysiteandemail`
5. اكتب المعلومات التالية:
   - **Name**: `dnzteam-website`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python app.py`
   - **Port**: `5000`
6. اضغط "Create Web Service"
7. انتظر حتى ينتهي البناء (Build)
8. الموقع سيكون متاحاً على: `https://dnzteam-website.onrender.com`

#### المميزات:
- ✅ مجاني تماماً
- ✅ SSL تلقائي
- ✅ نطاق فرعي مجاني
- ✅ إعادة تشغيل تلقائي
- ✅ سهل الاستخدام

---

### الخيار الثاني: Railway.app

#### الخطوات:
1. اذهب إلى [Railway.app](https://railway.app)
2. اضغط "Login with GitHub"
3. اضغط "New Project"
4. اختر "Deploy from GitHub repo"
5. اختر المشروع `mysiteandemail`
6. اكتب الأمر: `python app.py`
7. اضغط "Deploy Now"
8. الموقع سيكون متاحاً على نطاق فرعي من Railway

---

### الخيار الثالث: Heroku

#### الخطوات:
1. اذهب إلى [Heroku.com](https://heroku.com)
2. أنشئ حساب جديد
3. اضغط "New" ثم "Create new app"
4. اكتب اسم التطبيق: `dnzteam-website`
5. اربط حساب GitHub
6. اختر المشروع `mysiteandemail`
7. اضغط "Deploy Branch"
8. الموقع سيكون متاحاً على: `https://dnzteam-website.herokuapp.com`

---

## إعداد البريد الإلكتروني coding@dnzteam.com

### الخيار الأول: Gmail Workspace (مجاني)

#### الخطوات:
1. اذهب إلى [Google Workspace](https://workspace.google.com)
2. اضغط "Get started"
3. اختر "Business Starter" (مجاني)
4. أدخل اسم النطاق: `dnzteam.com`
5. اتبع التعليمات لإعداد النطاق
6. أنشئ المستخدم: `coding@dnzteam.com`
7. فعّل "2-Step Verification"
8. اذهب إلى "App passwords" وأنشئ كلمة مرور للتطبيق
9. عدّل ملف `config.py`:

```python
MAIL_USERNAME = 'coding@dnzteam.com'
MAIL_PASSWORD = 'your_app_password_from_google'
```

---

### الخيار الثاني: Zoho Mail (مجاني)

#### الخطوات:
1. اذهب إلى [Zoho Mail](https://zoho.com/mail)
2. اضغط "Sign Up Free"
3. اختر "Free Forever"
4. أدخل اسم النطاق: `dnzteam.com`
5. اتبع التعليمات لإعداد النطاق
6. أنشئ المستخدم: `coding@dnzteam.com`
7. اذهب إلى "Settings" > "Mail Accounts" > "Security"
8. فعّل "App-Specific Passwords"
9. أنشئ كلمة مرور للتطبيق
10. عدّل ملف `config.py`:

```python
MAIL_SERVER = 'smtp.zoho.com'
MAIL_USERNAME = 'coding@dnzteam.com'
MAIL_PASSWORD = 'your_app_password_from_zoho'
```

---

### الخيار الثالث: Yandex 360 (مجاني)

#### الخطوات:
1. اذهب إلى [Yandex 360](https://360.yandex.com)
2. اضغط "Get Started Free"
3. اختر "Free"
4. أدخل اسم النطاق: `dnzteam.com`
5. اتبع التعليمات لإعداد النطاق
6. أنشئ المستخدم: `coding@dnzteam.com`
7. اذهب إلى "Security" > "App passwords"
8. أنشئ كلمة مرور للتطبيق
9. عدّل ملف `config.py`:

```python
MAIL_SERVER = 'smtp.yandex.com'
MAIL_USERNAME = 'coding@dnzteam.com'
MAIL_PASSWORD = 'your_app_password_from_yandex'
```

---

## إعداد النطاق dnzteam.com

### شراء النطاق:
1. اذهب إلى [Namecheap.com](https://namecheap.com) أو [GoDaddy.com](https://godaddy.com)
2. ابحث عن `dnzteam.com`
3. اشترِ النطاق (عادةً $10-15 سنوياً)

### ربط النطاق مع Render:
1. في Render، اذهب إلى إعدادات الموقع
2. اضغط "Custom Domains"
3. أضف `dnzteam.com`
4. اتبع التعليمات لتحديث DNS

---

## اختبار البريد الإلكتروني

### بعد إعداد البريد الإلكتروني:
1. شغل الموقع محلياً: `python app.py`
2. اذهب إلى صفحة التواصل
3. أرسل رسالة تجريبية
4. تحقق من استلام الرسالة على `coding@dnzteam.com`

### إذا لم تعمل الرسائل:
1. تأكد من إعدادات SMTP
2. تأكد من كلمة مرور التطبيق
3. تأكد من تفعيل "Less secure app access" (لـ Gmail)
4. تحقق من إعدادات Firewall

---

## ملاحظات مهمة

- **المجانية**: جميع الخدمات المذكورة مجانية تماماً
- **الأمان**: استخدم دائماً كلمات مرور التطبيق
- **النطاق**: يمكنك استخدام نطاق فرعي إذا لم يكن لديك نطاق رئيسي
- **الدعم**: جميع المنصات تقدم دعم مجاني

---

## روابط مفيدة

- [Render.com](https://render.com) - النشر المجاني
- [Railway.app](https://railway.app) - النشر المجاني
- [Heroku.com](https://heroku.com) - النشر المجاني
- [Google Workspace](https://workspace.google.com) - البريد المجاني
- [Zoho Mail](https://zoho.com/mail) - البريد المجاني
- [Yandex 360](https://360.yandex.com) - البريد المجاني
