@echo off
echo ========================================
echo    DNZ Team - موقع فريق المطورين العراقيين
echo ========================================
echo.
echo جاري تشغيل الموقع...
echo.
echo تأكد من تثبيت المتطلبات أولاً:
echo pip install -r requirements.txt
echo.
echo تأكد من تحديث ملف config.py بإعدادات البريد الإلكتروني
echo.
echo الموقع سيعمل على: http://localhost:5000
echo.
echo اضغط Ctrl+C لإيقاف الموقع
echo.
python app.py
pause
