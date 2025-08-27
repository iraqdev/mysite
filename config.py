# إعدادات البريد الإلكتروني
# قم بتغيير هذه القيم حسب إعداداتك
import os

# Zoho Mail
MAIL_SERVER = 'smtp.zoho.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'coding@dnzteam.online'
MAIL_PASSWORD = 'md8Xsdn0BXH0'

# أو Outlook/Hotmail
# MAIL_SERVER = 'smtp-mail.outlook.com'
# MAIL_PORT = 587
# MAIL_USE_TLS = True
# MAIL_USERNAME = 'your_email@outlook.com'
# MAIL_PASSWORD = 'your_app_password'

# كلمة سر التطبيق - قوية ومعقدة
SECRET_KEY = 'dnzteam_super_secure_key_2024_iraq_dev_team_!@#$%^&*()'

# إعدادات إضافية
DEBUG = False  # إيقاف وضع التطوير في الإنتاج
HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', 5000))  # مهم لـ Render

# إعدادات الأمان
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # حد أقصى 16MB للملفات
SESSION_COOKIE_SECURE = False  # كوكيز آمن (False لـ Render)
SESSION_COOKIE_HTTPONLY = True  # منع الوصول عبر JavaScript
PERMANENT_SESSION_LIFETIME = 1800  # انتهاء الجلسة بعد 30 دقيقة
