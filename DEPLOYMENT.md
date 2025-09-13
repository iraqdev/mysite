# دليل نشر موقع HTITI على Render

## المتطلبات
- حساب على موقع Render.com
- ملفات المشروع جاهزة

## خطوات النشر

### 1. إعداد المشروع
```bash
# تأكد من وجود جميع الملفات
ls -la
# يجب أن ترى:
# - index.html
# - server.js
# - package.json
# - script.js
# - security.js
# - styles.css
# - logo.png
# - render.yaml
```

### 2. رفع المشروع إلى GitHub
```bash
# إنشاء مستودع جديد
git init
git add .
git commit -m "HTITI Chat System - Initial Release"
git branch -M main
git remote add origin https://github.com/username/htiti-chat.git
git push -u origin main
```

### 3. النشر على Render

#### الطريقة الأولى: من GitHub
1. اذهب إلى [Render.com](https://render.com)
2. اضغط على "New +"
3. اختر "Web Service"
4. اربط حساب GitHub
5. اختر المستودع `htiti-chat`
6. اترك الإعدادات الافتراضية:
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Environment**: `Node`
7. اضغط "Create Web Service"

#### الطريقة الثانية: من ملف render.yaml
1. اذهب إلى [Render.com](https://render.com)
2. اضغط على "New +"
3. اختر "Blueprint"
4. ارفع ملف `render.yaml`
5. اضغط "Apply"

### 4. إعداد متغيرات البيئة (اختياري)
```yaml
NODE_ENV: production
PORT: 3000
```

### 5. اختبار الموقع
- بعد النشر، ستحصل على رابط مثل: `https://htiti-chat.onrender.com`
- افتح الرابط في المتصفح
- تأكد من عمل المحادثة

## الميزات المتاحة بعد النشر

### للمستخدمين العاديين:
- ✅ محادثة جماعية حقيقية
- ✅ جميع المستخدمين يرون نفس الرسائل
- ✅ تشفير متقدم للرسائل
- ✅ أمان عالي

### للمديرين:
- ✅ إشعارات فورية عند وصول رسائل جديدة
- ✅ إيقاف/تشغيل المحادثة
- ✅ مسح جميع الرسائل
- ✅ حظر المستخدمين
- ✅ تصدير المحادثة

## استكشاف الأخطاء

### المشكلة: الموقع لا يعمل
**الحل:**
1. تأكد من أن جميع الملفات موجودة
2. تحقق من logs في Render Dashboard
3. تأكد من أن package.json صحيح

### المشكلة: الرسائل لا تظهر
**الحل:**
1. تأكد من اتصال Socket.IO
2. تحقق من console في المتصفح
3. تأكد من أن الخادم يعمل

### المشكلة: المدير لا يستطيع التحكم
**الحل:**
1. تأكد من الرمز السري: `htiti_2025_admin_secure_token_advanced`
2. تحقق من localStorage
3. تأكد من اتصال Socket.IO

## الأمان

### الحماية المطبقة:
- ✅ Rate Limiting (3 طلبات/ثانية)
- ✅ CSRF Protection
- ✅ XSS Protection
- ✅ Content Security Policy
- ✅ تشفير AES-256
- ✅ Session Management

### نصائح إضافية:
- استخدم HTTPS دائماً
- راقب logs بانتظام
- حدث النظام دورياً
- احتفظ بنسخ احتياطية

## التحديثات

### لتحديث الموقع:
```bash
git add .
git commit -m "Update message"
git push origin main
# Render سيقوم بالتحديث تلقائياً
```

### لمراقبة الأداء:
- اذهب إلى Render Dashboard
- تحقق من Metrics
- راقب Logs

## الدعم

### في حالة المشاكل:
1. تحقق من Render Dashboard
2. راجع Logs
3. تأكد من صحة الكود
4. اتصل بالدعم الفني

---

**HTITI Global Hacking Team**  
*Advanced Security • Maximum Protection • Elite Technology*
