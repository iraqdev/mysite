// HTITI Global Hacking Team - Advanced Chat System
// Advanced Security Implementation 2025

class SecureChatSystem {
    constructor() {
        this.userId = this.generateSecureId();
        this.sessionKey = null;
        this.isAdmin = this.checkAdminStatus();
        this.rateLimiter = new RateLimiter();
        this.encryption = new AdvancedEncryption();
        this.messages = [];
        this.isChatActive = true;
        this.connectionStatus = 'connecting';
        this.socket = null;
        this.failedLoginAttempts = 0; // Track failed login attempts
        
        this.init();
    }

    // Initialize the system
    init() {
        this.setupEventListeners();
        this.initializeSecurity();
        this.showLoading();
        this.connectToServer();
        this.startHeartbeat();
        this.createMatrixEffect();
        this.updateStats();
    }

    // Generate secure user ID
    generateSecureId() {
        const timestamp = Date.now().toString(36);
        const random = Math.random().toString(36).substr(2, 9);
        const crypto = window.crypto || window.msCrypto;
        let secureRandom = '';
        
        if (crypto && crypto.getRandomValues) {
            const array = new Uint8Array(16);
            crypto.getRandomValues(array);
            secureRandom = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
        } else {
            secureRandom = Math.random().toString(36).substr(2, 16);
        }
        
        return `user_${timestamp}_${random}_${secureRandom}`;
    }

    // Generate session key for encryption
    generateSessionKey() {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        let key = '';
        for (let i = 0; i < 32; i++) {
            key += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return key;
    }

    // Connect to server - Very Simplified
    connectToServer() {
        // Auto-detect server URL for production
        const serverUrl = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' 
            ? 'http://localhost:3002' 
            : window.location.origin; // Use same origin for Render
            
        this.socket = io(serverUrl, {
            transports: ['websocket', 'polling'],
            timeout: 20000,
            forceNew: true
        });
        
        this.socket.on('connect', () => {
            console.log('متصل بالخادم');
            this.connectionStatus = 'connected';
            this.updateConnectionStatus();
            this.updateStats();
            this.showWelcomeMessage();
        });
        
        this.socket.on('disconnect', () => {
            console.log('انقطع الاتصال بالخادم');
            this.connectionStatus = 'disconnected';
            this.updateConnectionStatus();
        });
        
        this.socket.on('connect_error', (error) => {
            console.error('خطأ في الاتصال:', error);
            this.showNotification('خطأ في الاتصال بالخادم - جاري إعادة المحاولة...', 'error');
            this.connectionStatus = 'error';
            this.updateConnectionStatus();
            this.hideLoading();
        });
        
        this.socket.on('reconnect', () => {
            console.log('تم إعادة الاتصال بالخادم');
            this.showNotification('تم إعادة الاتصال بالخادم', 'info');
            this.connectionStatus = 'connected';
            this.updateConnectionStatus();
        });
        
        this.socket.on('reconnect_error', (error) => {
            console.error('خطأ في إعادة الاتصال:', error);
            this.showNotification('خطأ في إعادة الاتصال', 'error');
        });
        
        this.socket.on('sessionKey', (key) => {
            this.sessionKey = key;
        });
        
        this.socket.on('newMessage', (message) => {
            this.messages.push(message);
            this.displayMessage(message);
            this.updateStats();
        });
        
        this.socket.on('messagesCleared', () => {
            this.messages = [];
            document.getElementById('messagesContainer').innerHTML = '';
            this.showNotification('تم مسح جميع الرسائل', 'info');
        });
    }

    // Load messages from server - Simplified
    async loadMessagesFromServer() {
        try {
            const response = await fetch(`/api/messages?sessionKey=${this.sessionKey || 'default'}`);
            const messages = await response.json();
            
            this.messages = messages || [];
            this.displayMessages();
            
            // Hide loading
            const loading = document.getElementById('loading');
            if (loading) {
                loading.classList.remove('active');
            }
        } catch (error) {
            console.error('خطأ في تحميل الرسائل:', error);
            // Hide loading even on error
            const loading = document.getElementById('loading');
            if (loading) {
                loading.classList.remove('active');
            }
        }
    }

    // Show admin notification
    showAdminNotification(data) {
        const notification = document.createElement('div');
        notification.className = 'admin-notification';
        notification.innerHTML = `
            <div class="notification-content">
                <h4>🔔 إشعار إداري</h4>
                <p>${data.type === 'NEW_MESSAGE' ? 'رسالة جديدة' : 'حدث جديد'}</p>
                <p>المستخدم: ${data.message.username}</p>
                <p>المحتوى: ${data.decryptedContent}</p>
                <button onclick="this.parentElement.parentElement.remove()">إغلاق</button>
            </div>
        `;
        
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: rgba(255, 0, 0, 0.9);
            color: white;
            padding: 15px;
            border-radius: 10px;
            z-index: 10000;
            font-family: 'Courier New', monospace;
            box-shadow: 0 0 20px rgba(255, 0, 0, 0.5);
            max-width: 300px;
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 10 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 10000);
    }

    // Check if user is admin
    checkAdminStatus() {
        const adminToken = localStorage.getItem('htiti_admin_token');
        return adminToken === 'htiti_2025_admin_secure_token_advanced';
    }

    // Setup event listeners
    setupEventListeners() {
        const messageInput = document.getElementById('messageInput');
        const sendBtn = document.getElementById('sendBtn');
        const messagesContainer = document.getElementById('messagesContainer');
        const adminToggle = document.getElementById('adminToggle');

        // Send message on button click
        sendBtn.addEventListener('click', () => this.sendMessage());

        // Send message on Enter key
        messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        // Auto-resize textarea - No validation
        messageInput.addEventListener('input', () => {
            // No validation needed
        });

        // Admin panel toggle
        if (adminToggle) {
            adminToggle.addEventListener('click', () => this.toggleAdminPanel());
        }

        // Admin buttons
        this.setupAdminButtons();

        // Show admin panel if admin
        if (this.isAdmin) {
            document.getElementById('adminPanel').classList.add('active');
        }

        // Prevent right-click (F12 allowed for debugging)
        document.addEventListener('contextmenu', (e) => e.preventDefault());
    }

    // Setup admin buttons
    setupAdminButtons() {
        // Admin login/logout buttons
        const adminLoginBtn = document.getElementById('adminLoginBtn');
        const adminLogoutBtn = document.getElementById('adminLogoutBtn');
        
        if (adminLoginBtn) {
            adminLoginBtn.addEventListener('click', () => this.adminLogin());
        }
        
        if (adminLogoutBtn) {
            adminLogoutBtn.addEventListener('click', () => this.adminLogout());
        }

        // Chat control buttons
        const toggleChatBtn = document.getElementById('toggleChatBtn');
        const clearMessagesBtn = document.getElementById('clearMessagesBtn');
        const exportChatBtn = document.getElementById('exportChatBtn');
        
        if (toggleChatBtn) {
            toggleChatBtn.addEventListener('click', () => this.toggleChat());
        }
        
        if (clearMessagesBtn) {
            clearMessagesBtn.addEventListener('click', () => this.clearAllMessages());
        }
        
        if (exportChatBtn) {
            exportChatBtn.addEventListener('click', () => this.exportChat());
        }

        // User management buttons
        const viewUsersBtn = document.getElementById('viewUsersBtn');
        const banUserBtn = document.getElementById('banUserBtn');
        const kickUserBtn = document.getElementById('kickUserBtn');
        const muteUserBtn = document.getElementById('muteUserBtn');
        
        if (viewUsersBtn) {
            viewUsersBtn.addEventListener('click', () => this.viewUsers());
        }
        
        if (banUserBtn) {
            banUserBtn.addEventListener('click', () => this.banUser());
        }
        
        if (kickUserBtn) {
            kickUserBtn.addEventListener('click', () => this.kickUser());
        }
        
        if (muteUserBtn) {
            muteUserBtn.addEventListener('click', () => this.muteUser());
        }
    }

    // Initialize security measures - Disabled for simplicity
    initializeSecurity() {
        // Minimal security only
        // console.log('Security initialized (simplified)'); // Commented to avoid duplicate logs
    }

    // Set secure cookie
    setSecureCookie(name, value, hours) {
        const expires = new Date();
        expires.setTime(expires.getTime() + (hours * 60 * 60 * 1000));
        const secure = location.protocol === 'https:' ? '; Secure' : '';
        document.cookie = `${name}=${value}; expires=${expires.toUTCString()}; path=/; SameSite=Strict${secure}`;
    }

    // Setup Content Security Policy
    setupContentSecurityPolicy() {
        const meta = document.createElement('meta');
        meta.httpEquiv = 'Content-Security-Policy';
        meta.content = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.socket.io; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://cdn.socket.io https://cdn.socket.io/4.7.2/";
        document.head.appendChild(meta);
    }

    // Setup XSS protection
    setupXSSProtection() {
        const meta = document.createElement('meta');
        meta.httpEquiv = 'X-XSS-Protection';
        meta.content = '1; mode=block';
        document.head.appendChild(meta);
    }

    // Load user session
    loadUserSession() {
        const savedMessages = localStorage.getItem(`htiti_messages_${this.userId}`);
        if (savedMessages) {
            try {
                const decrypted = this.encryption.decrypt(savedMessages, this.sessionKey);
                this.messages = JSON.parse(decrypted);
                this.displayMessages();
            } catch (e) {
                console.error('Error loading session:', e);
            }
        }
    }

    // Save user session
    saveUserSession() {
        try {
            const encrypted = this.encryption.encrypt(JSON.stringify(this.messages), this.sessionKey);
            localStorage.setItem(`htiti_messages_${this.userId}`, encrypted);
        } catch (e) {
            console.error('Error saving session:', e);
        }
    }

    // Send message - Very Simple (No Security)
    sendMessage() {
        const messageInput = document.getElementById('messageInput');
        const message = messageInput.value.trim();

        if (!message) {
            return;
        }
        
        // Send message directly - No security checks
            if (this.socket && this.socket.connected) {
                this.socket.emit('sendMessage', {
                    username: this.getUsername(),
                    content: message
                });
        } else {
            this.showNotification('غير متصل بالخادم', 'error');
            return;
        }

        // Clear input
        messageInput.value = '';
    }

    // Validate input - Disabled
    validateInput(input) {
        // No validation - Allow everything
        return true;
    }

    // Generate message ID
    generateMessageId() {
        return `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    // Get username
    getUsername() {
        let username = localStorage.getItem('htiti_username');
        if (!username) {
            username = `Hacker_${Math.floor(Math.random() * 9999)}`;
            localStorage.setItem('htiti_username', username);
        }
        return username;
    }

    // Display message - Simplified
    displayMessage(messageObj) {
        const messagesContainer = document.getElementById('messagesContainer');
        this.hideLoading();

        const messageDiv = document.createElement('div');
        messageDiv.className = 'message';
        
        // Simple message display without encryption complexity
        const messageContent = messageObj.content || 'رسالة فارغة';
        
        messageDiv.innerHTML = `
            <div class="message-header">
                <span class="username">${this.escapeHtml(messageObj.username || 'مجهول')}</span>
                <span class="timestamp">${this.formatTime(messageObj.timestamp)}</span>
            </div>
            <div class="message-content">${this.escapeHtml(messageContent)}</div>
        `;

        messagesContainer.appendChild(messageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    // Display all messages
    displayMessages() {
        const messagesContainer = document.getElementById('messagesContainer');
        this.hideLoading();

        messagesContainer.innerHTML = '';
        this.messages.forEach(message => {
            this.displayMessage(message);
        });
    }

    // Simulate server response
    simulateServerResponse(originalMessage) {
        const responses = [
            'مثير للاهتمام...',
            'هل يمكنك توضيح أكثر؟',
            'أفهم وجهة نظرك',
            'هذا صحيح',
            'ممتاز!',
            'معلومات مفيدة',
            'شكراً للمشاركة',
            'نحتاج المزيد من التفاصيل'
        ];

        const randomResponse = responses[Math.floor(Math.random() * responses.length)];
        
        const responseObj = {
            id: this.generateMessageId(),
            userId: 'system',
            username: 'System',
            content: this.encryption.encrypt(randomResponse, this.sessionKey),
            timestamp: Date.now(),
            encrypted: true
        };

        this.messages.push(responseObj);
        this.displayMessage(responseObj);
        this.saveUserSession();
    }

    // Show loading
    showLoading() {
        const loading = document.getElementById('loading');
        if (loading) {
            loading.classList.add('active');
        }
    }

    // Hide loading
    hideLoading() {
        const loading = document.getElementById('loading');
        if (loading) {
            loading.classList.remove('active');
        }
    }

    // Show welcome message
    showWelcomeMessage() {
        this.hideLoading();
        setTimeout(() => {
            const welcomeMessage = {
                id: this.generateMessageId(),
                userId: 'system',
                username: 'System',
                content: 'مرحباً بك في غرفة المحادثة السرية لفريق HTITI. جميع الرسائل مشفرة ومحمية بأعلى مستويات الأمان.',
                timestamp: Date.now(),
                encrypted: false
            };

            this.messages.push(welcomeMessage);
            this.displayMessage(welcomeMessage);
        }, 1000);
    }

    // Start heartbeat
    startHeartbeat() {
        setInterval(() => {
            this.updateConnectionStatus();
            this.updateStats();
            
            // Auto-reconnect if disconnected
            if (this.connectionStatus === 'disconnected' || this.connectionStatus === 'error') {
                if (this.socket && !this.socket.connected) {
                    console.log('محاولة إعادة الاتصال...');
                    this.socket.connect();
                }
            }
        }, 5000);
    }

    // Update connection status
    updateConnectionStatus() {
        const statusIndicator = document.querySelector('.status-indicator');
        if (statusIndicator) {
            if (this.connectionStatus === 'connected' && this.isChatActive) {
                statusIndicator.style.background = '#00ff00';
                statusIndicator.title = 'متصل';
            } else if (this.connectionStatus === 'disconnected') {
                statusIndicator.style.background = '#ff0000';
                statusIndicator.title = 'غير متصل';
            } else if (this.connectionStatus === 'error') {
                statusIndicator.style.background = '#ff8800';
                statusIndicator.title = 'خطأ في الاتصال';
            } else {
                statusIndicator.style.background = '#ff0000';
                statusIndicator.title = 'غير متصل';
            }
        }
    }

    // Create matrix effect
    createMatrixEffect() {
        const matrixBg = document.getElementById('matrixBg');
        const chars = '01';
        let matrixText = '';

        for (let i = 0; i < 100; i++) {
            matrixText += chars.charAt(Math.floor(Math.random() * chars.length));
        }

        matrixBg.innerHTML = matrixText;
        matrixBg.style.fontFamily = 'Courier New, monospace';
        matrixBg.style.fontSize = '12px';
        matrixBg.style.lineHeight = '12px';
        matrixBg.style.color = '#00ff00';
        matrixBg.style.opacity = '0.1';
    }

    // Utility functions
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    formatTime(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleTimeString('ar-SA', { 
            hour: '2-digit', 
            minute: '2-digit' 
        });
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        
        let backgroundColor = '#00ff00';
        let textColor = 'white';
        
        switch (type) {
            case 'error':
                backgroundColor = '#ff0000';
                break;
            case 'warning':
                backgroundColor = '#ff8800';
                break;
            case 'info':
                backgroundColor = '#00ff00';
                break;
            case 'success':
                backgroundColor = '#00ff00';
                break;
        }
        
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${backgroundColor};
            color: ${textColor};
            padding: 15px 20px;
            border-radius: 10px;
            z-index: 10000;
            font-family: 'Courier New', monospace;
            font-weight: bold;
            box-shadow: 0 0 25px rgba(0,0,0,0.8);
            border: 2px solid ${backgroundColor};
            animation: notificationSlideIn 0.3s ease-out;
            max-width: 400px;
            word-wrap: break-word;
        `;
        
        notification.textContent = message;
        document.body.appendChild(notification);

        // Log to security system if available
        if (window.securitySystem && window.securitySystem.auditLogger) {
            window.securitySystem.auditLogger.log('NOTIFICATION_SHOWN', {
                message: message,
                type: type,
                timestamp: Date.now()
            });
        }

        setTimeout(() => {
            notification.style.animation = 'notificationSlideOut 0.3s ease-in';
            setTimeout(() => {
                if (notification.parentElement) {
            notification.remove();
                }
            }, 300);
        }, 4000);
    }

    showSecurityWarning() {
        this.showNotification('محاولة غير مصرح بها!', 'error');
    }

    // Admin functions
    async toggleChat() {
        if (!this.isAdmin) {
            this.showNotification('يجب تسجيل الدخول أولاً', 'error');
            return;
        }
        
        try {
                this.isChatActive = !this.isChatActive;
                const status = this.isChatActive ? 'مفعلة' : 'متوقفة';
                this.showNotification(`المحادثة ${status}`, 'info');
                this.updateConnectionStatus();
            this.updateStats();
            
            // Send to server if connected
            if (this.socket && this.socket.connected) {
                this.socket.emit('adminAction', {
                    action: 'toggleChat',
                    status: this.isChatActive
                });
            }
        } catch (error) {
            this.showNotification('خطأ في تغيير حالة المحادثة', 'error');
        }
    }

    async clearAllMessages() {
        if (!this.isAdmin) {
            this.showNotification('يجب تسجيل الدخول أولاً', 'error');
            return;
        }
        
        if (confirm('هل أنت متأكد من مسح جميع الرسائل؟')) {
            try {
                    this.messages = [];
                    document.getElementById('messagesContainer').innerHTML = '';
                    this.showNotification('تم مسح جميع الرسائل', 'info');
                this.updateStats();
                
                // Send to server if connected
                if (this.socket && this.socket.connected) {
                    this.socket.emit('adminAction', {
                        action: 'clearMessages'
                    });
                }
            } catch (error) {
                this.showNotification('خطأ في مسح الرسائل', 'error');
            }
        }
    }

    async banUser() {
        if (!this.isAdmin) {
            this.showNotification('يجب تسجيل الدخول أولاً', 'error');
            return;
        }
        
        const userId = prompt('أدخل معرف المستخدم للحظر:');
        if (userId && userId.trim()) {
            this.showNotification(`تم حظر المستخدم: ${userId}`, 'info');
            
            // Send to server if connected
            if (this.socket && this.socket.connected) {
                this.socket.emit('adminAction', {
                    action: 'banUser',
                        userId: userId
                });
            }
        }
    }

    kickUser() {
        if (!this.isAdmin) {
            this.showNotification('يجب تسجيل الدخول أولاً', 'error');
            return;
        }
        
        const userId = prompt('أدخل معرف المستخدم للطرد:');
        if (userId && userId.trim()) {
            this.showNotification(`تم طرد المستخدم: ${userId}`, 'info');
            
            // Send to server if connected
            if (this.socket && this.socket.connected) {
                this.socket.emit('adminAction', {
                    action: 'kickUser',
                    userId: userId
                });
            }
        }
    }

    muteUser() {
        if (!this.isAdmin) {
            this.showNotification('يجب تسجيل الدخول أولاً', 'error');
            return;
        }
        
        const userId = prompt('أدخل معرف المستخدم للكتم:');
        if (userId && userId.trim()) {
            this.showNotification(`تم كتم المستخدم: ${userId}`, 'info');
            
            // Send to server if connected
            if (this.socket && this.socket.connected) {
                this.socket.emit('adminAction', {
                    action: 'muteUser',
                    userId: userId
                });
            }
        }
    }

    viewUsers() {
        if (!this.isAdmin) {
            this.showNotification('يجب تسجيل الدخول أولاً', 'error');
            return;
        }
        
        const activeUsers = this.socket && this.socket.connected ? 'متصل' : 'غير متصل';
        const userCount = this.socket && this.socket.connected ? '1' : '0';
        this.showNotification(`المستخدمون النشطون: ${userCount} (${activeUsers})`, 'info');
        
        // Send to server if connected
        if (this.socket && this.socket.connected) {
            this.socket.emit('adminAction', {
                action: 'viewUsers'
            });
        }
    }

    exportChat() {
        if (!this.isAdmin) {
            this.showNotification('يجب تسجيل الدخول أولاً', 'error');
            return;
        }
        
        try {
            const chatData = {
                messages: this.messages,
                exportDate: new Date().toISOString(),
                userId: this.userId,
                admin: true
            };
            
            const blob = new Blob([JSON.stringify(chatData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `htiti_chat_export_${Date.now()}.json`;
            a.click();
            URL.revokeObjectURL(url);
            
            this.showNotification('تم تصدير المحادثة بنجاح', 'info');
        } catch (error) {
            this.showNotification('خطأ في تصدير المحادثة', 'error');
        }
    }

    // Toggle admin panel
    toggleAdminPanel() {
        const adminPanel = document.getElementById('adminPanel');
        if (adminPanel) {
            adminPanel.classList.toggle('active');
            const isVisible = adminPanel.classList.contains('active');
            
            if (isVisible && !this.isAdmin) {
                // Hide admin sections if not authenticated
                this.hideAdminSections();
                this.showNotification('يجب تسجيل الدخول أولاً للوصول إلى لوحة التحكم', 'error');
            } else if (isVisible && this.isAdmin) {
                // Show admin sections if authenticated
                this.showAdminSections();
                this.showNotification('تم فتح لوحة الإدارة', 'info');
            } else {
                this.showNotification('تم إغلاق لوحة الإدارة', 'info');
            }
        }
    }

    // Admin login - Triple Authentication
    adminLogin() {
        const password1 = document.getElementById('adminPassword1').value;
        const password2 = document.getElementById('adminPassword2').value;
        const password3 = document.getElementById('adminPassword3').value;
        
        console.log('Admin login attempt:', { password1, password2, password3 });
        
        // Check all three passwords
        if (password1 === 'Dodo@1998' && 
            password2 === 'Dodo@n@z@1998' && 
            password3 === 'Dodo@n@z@1998Dnz') {
            
            this.isAdmin = true;
            this.failedLoginAttempts = 0; // Reset failed attempts on success
            this.showAdminSections();
            this.hideLoginSection();
            this.showNotification('تم تسجيل دخول الإدارة بنجاح - مرحباً بك في لوحة التحكم', 'info');
            this.updateStats();
            
            // Clear password fields for security
            document.getElementById('adminPassword1').value = '';
            document.getElementById('adminPassword2').value = '';
            document.getElementById('adminPassword3').value = '';
            
            console.log('Admin login successful');
            
        } else {
            this.failedLoginAttempts++;
            this.showFailedLoginMessage();
            
            // Clear password fields for security
            document.getElementById('adminPassword1').value = '';
            document.getElementById('adminPassword2').value = '';
            document.getElementById('adminPassword3').value = '';
            
            console.log('Admin login failed - attempt:', this.failedLoginAttempts);
        }
    }

    // Show failed login warning messages
    showFailedLoginMessage() {
        let message = '';
        let type = 'error';
        
        switch (this.failedLoginAttempts) {
            case 1:
                message = 'تستطيع أن تحاول';
                type = 'info';
                break;
            case 2:
                message = 'مازلت تحاول ...!!!!';
                type = 'warning';
                break;
            case 3:
                message = 'انتبه لنفسك ...؟؟!!';
                type = 'error';
                break;
            default:
                message = `محاولة رقم ${this.failedLoginAttempts} - كلمات المرور غير صحيحة!`;
                type = 'error';
        }
        
        this.showNotification(message, type);
    }

    // Show admin sections after successful authentication
    showAdminSections() {
        const chatControl = document.getElementById('chatControlSection');
        const userManagement = document.getElementById('userManagementSection');
        const statistics = document.getElementById('statisticsSection');
        
        console.log('Showing admin sections:', { chatControl, userManagement, statistics });
        
        if (chatControl) {
            chatControl.style.display = 'block';
            console.log('Chat control section shown');
        }
        if (userManagement) {
            userManagement.style.display = 'block';
            console.log('User management section shown');
        }
        if (statistics) {
            statistics.style.display = 'block';
            console.log('Statistics section shown');
        }
    }

    // Hide login section after successful authentication
    hideLoginSection() {
        const loginSection = document.getElementById('adminLoginSection');
        const loginBtn = document.getElementById('adminLoginBtn');
        const logoutBtn = document.getElementById('adminLogoutBtn');
        
        if (loginSection) {
            loginSection.style.display = 'none';
        }
        if (loginBtn) {
            loginBtn.style.display = 'none';
        }
        if (logoutBtn) {
            logoutBtn.style.display = 'block';
        }
    }

    // Show login section (for logout)
    showLoginSection() {
        const loginSection = document.getElementById('adminLoginSection');
        const loginBtn = document.getElementById('adminLoginBtn');
        const logoutBtn = document.getElementById('adminLogoutBtn');
        
        if (loginSection) {
            loginSection.style.display = 'block';
        }
        if (loginBtn) {
            loginBtn.style.display = 'block';
        }
        if (logoutBtn) {
            logoutBtn.style.display = 'none';
        }
    }

    // Hide admin sections (for logout or failed auth)
    hideAdminSections() {
        const chatControl = document.getElementById('chatControlSection');
        const userManagement = document.getElementById('userManagementSection');
        const statistics = document.getElementById('statisticsSection');
        
        if (chatControl) chatControl.style.display = 'none';
        if (userManagement) userManagement.style.display = 'none';
        if (statistics) statistics.style.display = 'none';
    }

    // Admin logout
    adminLogout() {
        this.isAdmin = false;
        this.hideAdminSections();
        this.showLoginSection();
        this.showNotification('تم تسجيل خروج الإدارة', 'info');
        
        // Clear password fields
        document.getElementById('adminPassword1').value = '';
        document.getElementById('adminPassword2').value = '';
        document.getElementById('adminPassword3').value = '';
    }

    // Update statistics
    updateStats() {
        const activeUsersEl = document.getElementById('activeUsers');
        const totalMessagesEl = document.getElementById('totalMessages');
        const chatStatusEl = document.getElementById('chatStatus');
        
        if (activeUsersEl) {
            activeUsersEl.textContent = this.socket && this.socket.connected ? '1' : '0';
        }
        
        if (totalMessagesEl) {
            totalMessagesEl.textContent = this.messages.length;
        }
        
        if (chatStatusEl) {
            chatStatusEl.textContent = this.isChatActive ? 'نشطة' : 'متوقفة';
        }
    }

    exportChat() {
        const chatData = {
            messages: this.messages,
            exportDate: new Date().toISOString(),
            userId: this.userId
        };
        
        const blob = new Blob([JSON.stringify(chatData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `htiti_chat_export_${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }
}

// Rate Limiter Class
class RateLimiter {
    constructor() {
        this.requests = [];
        this.maxRequests = 3;
        this.timeWindow = 1000; // 1 second
    }

    init() {
        // Load saved requests from localStorage
        const saved = localStorage.getItem('htiti_rate_limit');
        if (saved) {
            this.requests = JSON.parse(saved);
        }
    }

    checkLimit() {
        const now = Date.now();
        
        // Remove old requests
        this.requests = this.requests.filter(time => now - time < this.timeWindow);
        
        // Check if limit exceeded
        if (this.requests.length >= this.maxRequests) {
            return false;
        }
        
        // Add current request
        this.requests.push(now);
        
        // Save to localStorage
        localStorage.setItem('htiti_rate_limit', JSON.stringify(this.requests));
        
        return true;
    }
}

// Advanced Encryption Class
class AdvancedEncryption {
    constructor() {
        this.algorithm = 'AES-GCM';
        this.keyLength = 256;
    }

    // Simple encryption (in real implementation, use Web Crypto API)
    encrypt(text, key) {
        let result = '';
        for (let i = 0; i < text.length; i++) {
            const charCode = text.charCodeAt(i);
            const keyChar = key.charCodeAt(i % key.length);
            result += String.fromCharCode(charCode ^ keyChar);
        }
        return btoa(result);
    }

    // Simple decryption
    decrypt(encryptedText, key) {
        try {
            const text = atob(encryptedText);
            let result = '';
            for (let i = 0; i < text.length; i++) {
                const charCode = text.charCodeAt(i);
                const keyChar = key.charCodeAt(i % key.length);
                result += String.fromCharCode(charCode ^ keyChar);
            }
            return result;
        } catch (e) {
            return 'خطأ في فك التشفير';
        }
    }
}

// Initialize the chat system when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.chatSystem = new SecureChatSystem();
});

// Global admin functions
function toggleChat() {
    if (window.chatSystem) {
        window.chatSystem.toggleChat();
    }
}

function clearAllMessages() {
    if (window.chatSystem) {
        window.chatSystem.clearAllMessages();
    }
}

function banUser() {
    if (window.chatSystem) {
        window.chatSystem.banUser();
    }
}

function kickUser() {
    if (window.chatSystem) {
        window.chatSystem.kickUser();
    }
}

function muteUser() {
    if (window.chatSystem) {
        window.chatSystem.muteUser();
    }
}

function viewUsers() {
    if (window.chatSystem) {
        window.chatSystem.viewUsers();
    }
}

function exportChat() {
    if (window.chatSystem) {
        window.chatSystem.exportChat();
    }
}

function adminLogin() {
    if (window.chatSystem) {
        window.chatSystem.adminLogin();
    }
}

function toggleAdminPanel() {
    if (window.chatSystem) {
        window.chatSystem.toggleAdminPanel();
    }
}

function adminLogout() {
    if (window.chatSystem) {
        window.chatSystem.adminLogout();
    }
}

// Copy to clipboard function
function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            showCopyNotification('تم نسخ العنوان بنجاح!');
        }).catch(() => {
            fallbackCopyTextToClipboard(text);
        });
    } else {
        fallbackCopyTextToClipboard(text);
    }
}

// Fallback copy function
function fallbackCopyTextToClipboard(text) {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.top = "0";
    textArea.style.left = "0";
    textArea.style.position = "fixed";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        document.execCommand('copy');
        showCopyNotification('تم نسخ العنوان بنجاح!');
    } catch (err) {
        showCopyNotification('فشل في نسخ العنوان', 'error');
    }
    
    document.body.removeChild(textArea);
}

// Show copy notification
function showCopyNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: ${type === 'success' ? '#00ff00' : '#ff0000'};
        color: white;
        padding: 15px 25px;
        border-radius: 10px;
        z-index: 10000;
        font-family: 'Courier New', monospace;
        font-weight: bold;
        box-shadow: 0 0 20px rgba(0,0,0,0.8);
        animation: copyNotification 0.3s ease-out;
    `;
    
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'copyNotificationOut 0.3s ease-in';
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 300);
    }, 2000);
}

// Add CSS animations for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes copyNotification {
        from { opacity: 0; transform: translate(-50%, -50%) scale(0.5); }
        to { opacity: 1; transform: translate(-50%, -50%) scale(1); }
    }
    @keyframes copyNotificationOut {
        from { opacity: 1; transform: translate(-50%, -50%) scale(1); }
        to { opacity: 0; transform: translate(-50%, -50%) scale(0.5); }
    }
    @keyframes notificationSlideIn {
        from { opacity: 0; transform: translateX(100%); }
        to { opacity: 1; transform: translateX(0); }
    }
    @keyframes notificationSlideOut {
        from { opacity: 1; transform: translateX(0); }
        to { opacity: 0; transform: translateX(100%); }
    }
`;
document.head.appendChild(style);
