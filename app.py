from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_mail import Mail, Message
import config
import re
import hashlib
import time

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# إعدادات الأمان
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH
app.config['SESSION_COOKIE_SECURE'] = False  # False لـ Render
app.config['SESSION_COOKIE_HTTPONLY'] = config.SESSION_COOKIE_HTTPONLY
app.config['PERMANENT_SESSION_LIFETIME'] = config.PERMANENT_SESSION_LIFETIME

# إعداد البريد الإلكتروني
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD

mail = Mail(app)

# حماية ضد CSRF
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = hashlib.sha256(str(time.time()).encode()).hexdigest()
    return session['csrf_token']

# حماية ضد الهجمات
def validate_input(text):
    # إزالة الأحرف الخطرة
    dangerous_chars = ['<', '>', '"', "'", '&', 'script', 'javascript', 'onload', 'onerror']
    text_lower = text.lower()
    for char in dangerous_chars:
        if char in text_lower:
            return False
    return True

# حماية ضد Spam
def is_spam(name, email, message):
    # فحص الرسائل القصيرة جداً
    if len(message) < 10:
        return True
    
    # فحص الروابط المشبوهة
    suspicious_patterns = ['http://', 'https://', 'www.', '.com', '.org', '.net']
    message_lower = message.lower()
    if any(pattern in message_lower for pattern in suspicious_patterns):
        return True
    
    return False

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/contact')
def contact():
    csrf_token = generate_csrf_token()
    return render_template('contact.html', csrf_token=csrf_token)

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/refund')
def refund():
    return render_template('refund.html')

@app.route('/send_message', methods=['POST'])
def send_message():
    if request.method == 'POST':
        # فحص CSRF token
        if request.form.get('csrf_token') != session.get('csrf_token'):
            flash('خطأ في الأمان. يرجى المحاولة مرة أخرى.', 'error')
            return redirect(url_for('contact'))
        
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        subject = request.form.get('subject', '').strip()
        message = request.form.get('message', '').strip()
        
        # فحص صحة المدخلات
        if not all([name, email, message]):
            flash('يرجى ملء جميع الحقول المطلوبة.', 'error')
            return redirect(url_for('contact'))
        
        # فحص صحة البريد الإلكتروني
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            flash('البريد الإلكتروني غير صحيح.', 'error')
            return redirect(url_for('contact'))
        
        # فحص الرسائل المشبوهة
        if is_spam(name, email, message):
            flash('تم رفض الرسالة. يرجى المحاولة مرة أخرى.', 'error')
            return redirect(url_for('contact'))
        
        # فحص المدخلات
        if not all(validate_input(field) for field in [name, email, subject, message]):
            flash('تم رفض الرسالة. يرجى المحاولة مرة أخرى.', 'error')
            return redirect(url_for('contact'))
        
        if name and email and message:
            try:
                msg = Message(
                    subject=f"رسالة جديدة من {name}: {subject}",
                    sender=email,
                    recipients=[config.MAIL_USERNAME],
                    body=f"""
                اسم المرسل: {name}
                البريد الإلكتروني: {email}
                الموضوع: {subject}
                
                الرسالة:
                {message}
                
                الوقت: {time.strftime('%Y-%m-%d %H:%M:%S')}
                IP: {request.remote_addr}
                """
                )
                mail.send(msg)
                flash('تم إرسال رسالتك بنجاح! سنتواصل معك قريباً.', 'success')
                
                # تجديد CSRF token
                session.pop('csrf_token', None)
                
            except Exception as e:
                flash('حدث خطأ في إرسال الرسالة. يرجى المحاولة مرة أخرى.', 'error')
        else:
            flash('يرجى ملء جميع الحقول المطلوبة.', 'error')
    
    return redirect(url_for('contact'))

# حماية إضافية
@app.before_request
def before_request():
    # منع الوصول لملفات معينة
    if request.path.startswith('/.git') or request.path.startswith('/config'):
        return "Access Denied", 403

if __name__ == '__main__':
    app.run(debug=config.DEBUG, host=config.HOST, port=config.PORT)
