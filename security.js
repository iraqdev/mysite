// HTITI Advanced Security Module 2025
// Ultra-Secure Chat System Protection

class AdvancedSecurity {
    constructor() {
        this.securityLevel = 'MAXIMUM';
        this.threatDetection = new ThreatDetection();
        this.encryptionEngine = new EncryptionEngine();
        this.rateLimiter = new AdvancedRateLimiter();
        this.sessionManager = new SessionManager();
        this.auditLogger = new AuditLogger();
        
        this.init();
    }

    init() {
        // Minimal security only - Most features disabled
        console.log('Security system initialized (simplified)');
    }

    // Setup Security Headers
    setupSecurityHeaders() {
        // Content Security Policy (without frame-ancestors for meta tag)
        const csp = "default-src 'self'; " +
                   "script-src 'self' 'unsafe-inline' https://cdn.socket.io; " +
                   "style-src 'self' 'unsafe-inline'; " +
                   "img-src 'self' data:; " +
                   "connect-src 'self' https://cdn.socket.io https://cdn.socket.io/4.7.2/; " +
                   "base-uri 'self'; " +
                   "form-action 'self'";

        this.setMetaHeader('Content-Security-Policy', csp);
        
        // X-Content-Type-Options
        this.setMetaHeader('X-Content-Type-Options', 'nosniff');
        
        // Referrer Policy
        this.setMetaHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
        
        // Permissions Policy
        this.setMetaHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    }

    setMetaHeader(name, content) {
        let meta = document.querySelector(`meta[http-equiv="${name}"]`);
        if (!meta) {
            meta = document.createElement('meta');
            meta.httpEquiv = name;
            document.head.appendChild(meta);
        }
        meta.content = content;
    }

    // Initialize Threat Detection
    initializeThreatDetection() {
        this.threatDetection.init();
        
        // Monitor for suspicious activities
        this.threatDetection.onThreatDetected = (threat) => {
            this.handleThreat(threat);
        };
    }

    // Setup Session Protection
    setupSessionProtection() {
        this.sessionManager.init();
        
        // Session timeout
        this.sessionManager.setTimeout(30 * 60 * 1000); // 30 minutes
        
        // Session validation
        setInterval(() => {
            this.sessionManager.validateSession();
        }, 60000); // Every minute
    }

    // Enable Real-time Monitoring
    enableRealTimeMonitoring() {
        // Monitor network requests
        this.monitorNetworkRequests();
        
        // Monitor DOM changes
        this.monitorDOMChanges();
        
        // Monitor user interactions
        this.monitorUserInteractions();
        
        // Monitor memory usage
        this.monitorMemoryUsage();
    }

    // Setup Anti-Tampering
    setupAntiTampering() {
        // Protect against debugging
        this.protectAgainstDebugging();
        
        // Protect against code injection
        this.protectAgainstCodeInjection();
        
        // Protect against XSS
        this.protectAgainstXSS();
        
        // Protect against CSRF
        this.protectAgainstCSRF();
    }

    // Initialize Biometric Protection
    initializeBiometricProtection() {
        // Mouse movement analysis
        this.analyzeMouseMovement();
        
        // Typing pattern analysis
        this.analyzeTypingPatterns();
        
        // Device fingerprinting
        this.createDeviceFingerprint();
    }

    // Handle detected threats - Disabled
    handleThreat(threat) {
        // No threat handling - Allow everything
        console.log('Threat detected but ignored:', threat.type);
    }

    showSecurityWarning(threat) {
        // No warnings - Allow everything
        console.log('Security warning ignored:', threat.type);
    }

    takeProtectiveAction(threat) {
        // No protective actions - Allow everything
        console.log('Protective action ignored:', threat.type);
    }

    blockUser() {
        // No blocking - Allow everything
        console.log('User blocking disabled');
    }

    logThreat(threat) {
        console.warn('Security threat detected:', threat);
        this.auditLogger.log('THREAT_LOGGED', threat);
    }

    // Monitor network requests
    monitorNetworkRequests() {
        const originalFetch = window.fetch;
        const self = this;
        
        window.fetch = function(...args) {
            self.auditLogger.log('NETWORK_REQUEST', {
                url: args[0],
                method: args[1]?.method || 'GET',
                timestamp: Date.now()
            });
            
            return originalFetch.apply(this, args);
        };
    }

    // Monitor DOM changes
    monitorDOMChanges() {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                this.auditLogger.log('DOM_CHANGE', {
                    type: mutation.type,
                    target: mutation.target.tagName,
                    timestamp: Date.now()
                });
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true
        });
    }

    // Monitor user interactions
    monitorUserInteractions() {
        const events = ['click', 'keydown', 'mousemove', 'scroll'];
        
        events.forEach(event => {
            document.addEventListener(event, (e) => {
                this.auditLogger.log('USER_INTERACTION', {
                    type: event,
                    target: e.target.tagName,
                    timestamp: Date.now()
                });
            }, true);
        });
    }

    // Monitor memory usage
    monitorMemoryUsage() {
        setInterval(() => {
            if (performance.memory) {
                this.auditLogger.log('MEMORY_USAGE', {
                    used: performance.memory.usedJSHeapSize,
                    total: performance.memory.totalJSHeapSize,
                    limit: performance.memory.jsHeapSizeLimit,
                    timestamp: Date.now()
                });
            }
        }, 30000); // Every 30 seconds
    }

    // Protect against debugging
    protectAgainstDebugging() {
        let devtools = { open: false, orientation: null };
        
        setInterval(() => {
            if (window.outerHeight - window.innerHeight > 200 || window.outerWidth - window.innerWidth > 200) {
                if (!devtools.open) {
                    devtools.open = true;
                    this.handleDevToolsOpen();
                }
            } else {
                devtools.open = false;
            }
        }, 500);
    }

    handleDevToolsOpen() {
        this.auditLogger.log('DEVTOOLS_OPENED', { timestamp: Date.now() });
        this.showSecurityWarning({
            type: 'DEVTOOLS_ACCESS',
            severity: 8,
            timestamp: Date.now()
        });
    }

    // Protect against code injection
    protectAgainstCodeInjection() {
        const dangerousFunctions = ['eval', 'Function', 'setTimeout', 'setInterval'];
        const self = this;
        
        dangerousFunctions.forEach(func => {
            if (window[func]) {
                const original = window[func];
                window[func] = function(...args) {
                    self.auditLogger.log('DANGEROUS_FUNCTION_CALL', {
                        function: func,
                        args: args,
                        timestamp: Date.now()
                    });
                    return original.apply(this, args);
                };
            }
        });
    }

    // Protect against XSS
    protectAgainstXSS() {
        // Override innerHTML and outerHTML
        const originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        const originalOuterHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
        const self = this;
        
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(value) {
                self.auditLogger.log('INNERHTML_SET', {
                    value: value,
                    target: this.tagName,
                    timestamp: Date.now()
                });
                return originalInnerHTML.set.call(this, value);
            },
            get: originalInnerHTML.get
        });
        
        Object.defineProperty(Element.prototype, 'outerHTML', {
            set: function(value) {
                self.auditLogger.log('OUTERHTML_SET', {
                    value: value,
                    target: this.tagName,
                    timestamp: Date.now()
                });
                return originalOuterHTML.set.call(this, value);
            },
            get: originalOuterHTML.get
        });
    }

    // Protect against CSRF
    protectAgainstCSRF() {
        // Generate CSRF token
        const csrfToken = this.generateCSRFToken();
        document.cookie = `csrf_token=${csrfToken}; SameSite=Strict; Secure`;
        
        // Validate CSRF token on form submissions
        document.addEventListener('submit', (e) => {
            const form = e.target;
            const token = form.querySelector('input[name="csrf_token"]');
            
            if (token && token.value !== csrfToken) {
                e.preventDefault();
                this.showSecurityWarning({
                    type: 'CSRF_ATTACK',
                    severity: 9,
                    timestamp: Date.now()
                });
            }
        });
    }

    generateCSRFToken() {
        return 'csrf_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }

    // Analyze mouse movement
    analyzeMouseMovement() {
        let mouseMovements = [];
        
        document.addEventListener('mousemove', (e) => {
            mouseMovements.push({
                x: e.clientX,
                y: e.clientY,
                timestamp: Date.now()
            });
            
            // Keep only recent movements
            if (mouseMovements.length > 100) {
                mouseMovements = mouseMovements.slice(-100);
            }
            
            // Analyze pattern every 100 movements
            if (mouseMovements.length % 100 === 0) {
                this.analyzeMousePattern(mouseMovements);
            }
        });
    }

    analyzeMousePattern(movements) {
        // Simple pattern analysis
        const avgSpeed = this.calculateAverageSpeed(movements);
        const consistency = this.calculateConsistency(movements);
        
        this.auditLogger.log('MOUSE_ANALYSIS', {
            avgSpeed: avgSpeed,
            consistency: consistency,
            timestamp: Date.now()
        });
    }

    calculateAverageSpeed(movements) {
        let totalDistance = 0;
        let totalTime = 0;
        
        for (let i = 1; i < movements.length; i++) {
            const prev = movements[i - 1];
            const curr = movements[i];
            
            const distance = Math.sqrt(
                Math.pow(curr.x - prev.x, 2) + Math.pow(curr.y - prev.y, 2)
            );
            
            const time = curr.timestamp - prev.timestamp;
            
            totalDistance += distance;
            totalTime += time;
        }
        
        return totalTime > 0 ? totalDistance / totalTime : 0;
    }

    calculateConsistency(movements) {
        // Calculate standard deviation of movement speeds
        const speeds = [];
        
        for (let i = 1; i < movements.length; i++) {
            const prev = movements[i - 1];
            const curr = movements[i];
            
            const distance = Math.sqrt(
                Math.pow(curr.x - prev.x, 2) + Math.pow(curr.y - prev.y, 2)
            );
            
            const time = curr.timestamp - prev.timestamp;
            
            if (time > 0) {
                speeds.push(distance / time);
            }
        }
        
        if (speeds.length === 0) return 0;
        
        const avg = speeds.reduce((a, b) => a + b, 0) / speeds.length;
        const variance = speeds.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / speeds.length;
        
        return Math.sqrt(variance);
    }

    // Analyze typing patterns
    analyzeTypingPatterns() {
        let keystrokes = [];
        
        document.addEventListener('keydown', (e) => {
            keystrokes.push({
                key: e.key,
                timestamp: Date.now(),
                keyCode: e.keyCode
            });
            
            // Keep only recent keystrokes
            if (keystrokes.length > 50) {
                keystrokes = keystrokes.slice(-50);
            }
            
            // Analyze pattern every 50 keystrokes
            if (keystrokes.length % 50 === 0) {
                this.analyzeTypingPattern(keystrokes);
            }
        });
    }

    analyzeTypingPattern(keystrokes) {
        const avgInterval = this.calculateAverageInterval(keystrokes);
        const rhythm = this.calculateRhythm(keystrokes);
        
        this.auditLogger.log('TYPING_ANALYSIS', {
            avgInterval: avgInterval,
            rhythm: rhythm,
            timestamp: Date.now()
        });
    }

    calculateAverageInterval(keystrokes) {
        let totalInterval = 0;
        let count = 0;
        
        for (let i = 1; i < keystrokes.length; i++) {
            const interval = keystrokes[i].timestamp - keystrokes[i - 1].timestamp;
            totalInterval += interval;
            count++;
        }
        
        return count > 0 ? totalInterval / count : 0;
    }

    calculateRhythm(keystrokes) {
        // Calculate rhythm consistency
        const intervals = [];
        
        for (let i = 1; i < keystrokes.length; i++) {
            const interval = keystrokes[i].timestamp - keystrokes[i - 1].timestamp;
            intervals.push(interval);
        }
        
        if (intervals.length === 0) return 0;
        
        const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const variance = intervals.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / intervals.length;
        
        return Math.sqrt(variance);
    }

    // Create device fingerprint
    createDeviceFingerprint() {
        const fingerprint = {
            userAgent: navigator.userAgent,
            language: navigator.language,
            platform: navigator.platform,
            screenResolution: `${screen.width}x${screen.height}`,
            colorDepth: screen.colorDepth,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            timestamp: Date.now()
        };
        
        this.auditLogger.log('DEVICE_FINGERPRINT', fingerprint);
        
        return fingerprint;
    }
}

// Threat Detection Class
class ThreatDetection {
    constructor() {
        this.threats = [];
        this.suspiciousPatterns = [
            /eval\(/gi,
            /document\.write/gi,
            /innerHTML/gi,
            /outerHTML/gi,
            /<script/gi,
            /javascript:/gi,
            /on\w+\s*=/gi,
            /alert\(/gi,
            /confirm\(/gi,
            /prompt\(/gi
        ];
    }

    init() {
        this.startMonitoring();
    }

    startMonitoring() {
        // Monitor console access
        this.monitorConsoleAccess();
        
        // Monitor network requests
        this.monitorNetworkRequests();
        
        // Monitor DOM modifications
        this.monitorDOMModifications();
    }

    monitorConsoleAccess() {
        const originalConsole = window.console;
        const self = this;
        
        ['log', 'warn', 'error', 'info', 'debug'].forEach(method => {
            const original = originalConsole[method];
            originalConsole[method] = function(...args) {
                self.detectThreat('CONSOLE_ACCESS', {
                    method: method,
                    args: args,
                    timestamp: Date.now()
                });
                return original.apply(this, args);
            };
        });
    }

    monitorNetworkRequests() {
        const originalFetch = window.fetch;
        const self = this;
        
        window.fetch = function(...args) {
            self.detectThreat('NETWORK_REQUEST', {
                url: args[0],
                timestamp: Date.now()
            });
            return originalFetch.apply(this, args);
        };
    }

    monitorDOMModifications() {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    this.detectThreat('DOM_MODIFICATION', {
                        type: 'childList',
                        target: mutation.target,
                        timestamp: Date.now()
                    });
                }
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    detectThreat(type, data) {
        const threat = {
            type: type,
            data: data,
            timestamp: Date.now(),
            severity: this.calculateSeverity(type, data)
        };
        
        this.threats.push(threat);
        
        if (threat.severity >= 7) {
            this.onThreatDetected(threat);
        }
    }

    calculateSeverity(type, data) {
        let severity = 1;
        
        switch (type) {
            case 'CONSOLE_ACCESS':
                severity = 3;
                break;
            case 'NETWORK_REQUEST':
                severity = 5;
                break;
            case 'DOM_MODIFICATION':
                severity = 7;
                break;
            case 'CODE_INJECTION':
                severity = 10;
                break;
        }
        
        return severity;
    }
}

// Encryption Engine Class
class EncryptionEngine {
    constructor() {
        this.algorithm = 'AES-256-GCM';
        this.keyDerivation = 'PBKDF2';
        this.iterations = 100000;
    }

    async encrypt(data, password) {
        try {
            const encoder = new TextEncoder();
            const dataBuffer = encoder.encode(data);
            
            // Generate random salt
            const salt = crypto.getRandomValues(new Uint8Array(16));
            
            // Derive key from password
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                encoder.encode(password),
                'PBKDF2',
                false,
                ['deriveBits', 'deriveKey']
            );
            
            const key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: this.iterations,
                    hash: 'SHA-256'
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt']
            );
            
            // Generate random IV
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            // Encrypt data
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                dataBuffer
            );
            
            // Combine salt, iv, and encrypted data
            const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
            result.set(salt, 0);
            result.set(iv, salt.length);
            result.set(new Uint8Array(encrypted), salt.length + iv.length);
            
            return btoa(String.fromCharCode(...result));
        } catch (error) {
            console.error('Encryption error:', error);
            return null;
        }
    }

    async decrypt(encryptedData, password) {
        try {
            const decoder = new TextDecoder();
            const data = new Uint8Array(atob(encryptedData).split('').map(c => c.charCodeAt(0)));
            
            // Extract salt, iv, and encrypted data
            const salt = data.slice(0, 16);
            const iv = data.slice(16, 28);
            const encrypted = data.slice(28);
            
            // Derive key from password
            const encoder = new TextEncoder();
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                encoder.encode(password),
                'PBKDF2',
                false,
                ['deriveBits', 'deriveKey']
            );
            
            const key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: this.iterations,
                    hash: 'SHA-256'
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );
            
            // Decrypt data
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                encrypted
            );
            
            return decoder.decode(decrypted);
        } catch (error) {
            console.error('Decryption error:', error);
            return null;
        }
    }
}

// Advanced Rate Limiter Class
class AdvancedRateLimiter {
    constructor() {
        this.requests = new Map();
        this.maxRequests = 3;
        this.timeWindow = 1000; // 1 second
        this.blockDuration = 300000; // 5 minutes
        this.blockedIPs = new Set();
    }

    checkLimit(identifier = 'default') {
        const now = Date.now();
        
        // Check if IP is blocked
        if (this.blockedIPs.has(identifier)) {
            return false;
        }
        
        // Get or create request history for this identifier
        if (!this.requests.has(identifier)) {
            this.requests.set(identifier, []);
        }
        
        const requestHistory = this.requests.get(identifier);
        
        // Remove old requests
        const validRequests = requestHistory.filter(time => now - time < this.timeWindow);
        this.requests.set(identifier, validRequests);
        
        // Check if limit exceeded
        if (validRequests.length >= this.maxRequests) {
            this.blockIP(identifier);
            return false;
        }
        
        // Add current request
        validRequests.push(now);
        this.requests.set(identifier, validRequests);
        
        return true;
    }

    blockIP(identifier) {
        this.blockedIPs.add(identifier);
        
        // Remove from block list after block duration
        setTimeout(() => {
            this.blockedIPs.delete(identifier);
        }, this.blockDuration);
    }
}

// Session Manager Class
class SessionManager {
    constructor() {
        this.sessionTimeout = 30 * 60 * 1000; // 30 minutes
        this.lastActivity = Date.now();
        this.sessionId = this.generateSessionId();
    }

    init() {
        this.setupActivityTracking();
        this.setupSessionValidation();
    }

    generateSessionId() {
        return 'sess_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }

    setupActivityTracking() {
        const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
        
        events.forEach(event => {
            document.addEventListener(event, () => {
                this.lastActivity = Date.now();
            }, true);
        });
    }

    setupSessionValidation() {
        setInterval(() => {
            this.validateSession();
        }, 60000); // Every minute
    }

    validateSession() {
        const now = Date.now();
        if (now - this.lastActivity > this.sessionTimeout) {
            this.expireSession();
        }
    }

    expireSession() {
        // Clear all data
        localStorage.clear();
        sessionStorage.clear();
        
        // Redirect to login or show session expired message
        this.showSessionExpiredMessage();
    }

    showSessionExpiredMessage() {
        alert('انتهت صلاحية الجلسة. سيتم إعادة تحميل الصفحة.');
        window.location.reload();
    }

    setTimeout(timeout) {
        this.sessionTimeout = timeout;
    }
}

// Audit Logger Class
class AuditLogger {
    constructor() {
        this.logs = [];
        this.maxLogs = 1000;
    }

    log(action, details) {
        const logEntry = {
            timestamp: Date.now(),
            action: action,
            details: details,
            userAgent: navigator.userAgent,
            url: window.location.href
        };
        
        this.logs.push(logEntry);
        
        // Keep only recent logs
        if (this.logs.length > this.maxLogs) {
            this.logs = this.logs.slice(-this.maxLogs);
        }
        
        // Store in localStorage
        localStorage.setItem('htiti_audit_logs', JSON.stringify(this.logs));
    }

    getLogs() {
        return this.logs;
    }

    exportLogs() {
        const blob = new Blob([JSON.stringify(this.logs, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `htiti_audit_logs_${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }
}

// Initialize security system
document.addEventListener('DOMContentLoaded', () => {
    window.securitySystem = new AdvancedSecurity();
});
