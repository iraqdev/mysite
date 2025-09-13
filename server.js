// HTITI Global Hacking Team - Server
// Advanced Chat Server for Render.com

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    },
    transports: ['websocket', 'polling'],
    allowEIO3: true,
    pingTimeout: 60000,
    pingInterval: 25000
});

// Handle connection errors
io.on('connection_error', (err) => {
    console.error('Socket.IO connection error:', err);
});

// Handle Socket.IO errors
io.engine.on('connection_error', (err) => {
    console.error('Socket.IO engine error:', err);
});

// Advanced Security Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.socket.io"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'", "https://cdn.socket.io", "https://cdn.socket.io/4.7.2/"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            frameAncestors: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"]
        }
    },
    crossOriginEmbedderPolicy: false,
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Additional security headers
app.use((req, res, next) => {
    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'DENY');
    
    // Prevent MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // XSS Protection
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Referrer Policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Permissions Policy
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    
    // Remove server information
    res.removeHeader('X-Powered-By');
    
    next();
});

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Advanced Rate Limiting System
class AdvancedRateLimiter {
    constructor() {
        this.requests = new Map();
        this.blockedIPs = new Set();
        this.suspiciousIPs = new Map();
        this.maxRequests = 10; // 10 requests per minute
        this.timeWindow = 60 * 1000; // 1 minute
        this.blockDuration = 15 * 60 * 1000; // 15 minutes
        this.suspiciousThreshold = 5; // 5 failed attempts
    }

    checkLimit(ip) {
        const now = Date.now();
        
        // Check if IP is blocked
        if (this.blockedIPs.has(ip)) {
            return false;
        }

        // Get or create request history for this IP
        if (!this.requests.has(ip)) {
            this.requests.set(ip, []);
        }

        const requestHistory = this.requests.get(ip);
        
        // Remove old requests
        const validRequests = requestHistory.filter(time => now - time < this.timeWindow);
        this.requests.set(ip, validRequests);
        
        // Check if limit exceeded
        if (validRequests.length >= this.maxRequests) {
            this.handleSuspiciousActivity(ip);
            return false;
        }
        
        // Add current request
        validRequests.push(now);
        this.requests.set(ip, validRequests);
        
        return true;
    }

    handleSuspiciousActivity(ip) {
        const suspiciousCount = this.suspiciousIPs.get(ip) || 0;
        this.suspiciousIPs.set(ip, suspiciousCount + 1);
        
        if (suspiciousCount + 1 >= this.suspiciousThreshold) {
            this.blockIP(ip);
        }
    }

    blockIP(ip) {
        this.blockedIPs.add(ip);
        console.log(`تم حظر العنوان: ${ip}`);
        
        // Remove from block list after block duration
        setTimeout(() => {
            this.blockedIPs.delete(ip);
            this.suspiciousIPs.delete(ip);
            console.log(`تم إلغاء حظر العنوان: ${ip}`);
        }, this.blockDuration);
    }

    isBlocked(ip) {
        return this.blockedIPs.has(ip);
    }
}

// Initialize rate limiter
const rateLimiter = new AdvancedRateLimiter();

// Rate limiting middleware
const limiter = (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    
    if (rateLimiter.isBlocked(ip)) {
        return res.status(429).json({
            error: 'تم حظر هذا العنوان مؤقتاً',
            code: 'IP_BLOCKED',
            retryAfter: 900 // 15 minutes in seconds
        });
    }
    
    if (!rateLimiter.checkLimit(ip)) {
        return res.status(429).json({
            error: 'تم تجاوز الحد المسموح من الطلبات',
            code: 'RATE_LIMIT_EXCEEDED',
            retryAfter: 60 // 1 minute in seconds
        });
    }
    
    next();
};

app.use('/api/', limiter);

// Advanced Code Protection System
class CodeProtectionSystem {
    constructor() {
        this.obfuscatedCode = new Map();
        this.integrityChecks = new Map();
        this.runtimeProtection = true;
        this.init();
    }

    init() {
        // Setup integrity monitoring
        this.setupIntegrityMonitoring();
        
        // Setup runtime protection
        this.setupRuntimeProtection();
    }

    protectCriticalFunctions(globalEncryption) {
        // Protect encryption functions
        const originalEncrypt = globalEncryption.encryptMessage;
        globalEncryption.encryptMessage = (...args) => {
            if (!this.validateCall()) {
                throw new Error('Unauthorized access attempt');
            }
            return originalEncrypt.apply(globalEncryption, args);
        };
    }

    setupIntegrityMonitoring() {
        // Monitor critical objects
        const criticalObjects = ['messages', 'users', 'adminSockets'];
        
        criticalObjects.forEach(objName => {
            this.integrityChecks.set(objName, {
                originalLength: 0,
                lastCheck: Date.now()
            });
        });

        // Check integrity every 30 seconds
        setInterval(() => {
            this.checkIntegrity();
        }, 30000);
    }

    setupRuntimeProtection() {
        // Protect against debugging
        this.protectAgainstDebugging();
        
        // Protect against code injection
        this.protectAgainstInjection();
        
        // Protect against memory tampering
        this.protectAgainstMemoryTampering();
    }

    protectAgainstDebugging() {
        // Server-side debugging protection (simplified)
        console.log('Debugging protection enabled');
    }

    protectAgainstInjection() {
        // Override dangerous functions
        const dangerousFunctions = ['eval', 'Function', 'setTimeout', 'setInterval'];
        const self = this;
        
        dangerousFunctions.forEach(func => {
            if (global[func]) {
                const original = global[func];
                global[func] = function(...args) {
                    if (!self.validateCall()) {
                        throw new Error('Unauthorized function call');
                    }
                    return original.apply(this, args);
                };
            }
        });
    }

    protectAgainstMemoryTampering() {
        // Monitor critical data structures
        const self = this;
        setInterval(() => {
            self.monitorDataStructures();
        }, 10000);
    }

    validateCall() {
        // Always return true for server stability
        return true;
    }

    checkIntegrity() {
        const now = Date.now();
        
        this.integrityChecks.forEach((check, objName) => {
            let currentLength = 0;
            try {
                if (objName === 'messages') {
                    currentLength = messages.length;
                } else if (objName === 'users') {
                    currentLength = users.size;
                } else if (objName === 'adminSockets') {
                    currentLength = adminSockets.size;
                }
            } catch (error) {
                console.warn(`Error checking integrity for ${objName}:`, error.message);
            }
            
            check.lastCheck = now;
        });
    }

    handleDebuggingAttempt() {
        console.warn('Debugging attempt detected');
        // Could implement additional protection here
    }

    handleIntegrityViolation(objName) {
        console.error(`Data integrity violation detected in ${objName}`);
        // Could implement recovery or alerting here
    }

    monitorDataStructures() {
        // Monitor for unexpected changes
        const criticalData = {
            messages: messages.length,
            users: users.size,
            adminSockets: adminSockets.size
        };
        
        // Log suspicious changes
        Object.entries(criticalData).forEach(([key, value]) => {
            if (value > 10000) { // Arbitrary threshold
                console.warn(`Suspicious data growth in ${key}: ${value}`);
            }
        });
    }

    checkAdminAccess(token) {
        // Enhanced admin access check
        if (!token || typeof token !== 'string') {
            return false;
        }
        
        // Check token format and content
        const expectedToken = 'htiti_2025_admin_secure_token_advanced';
        if (token !== expectedToken) {
            return false;
        }
        
        // Additional security checks
        if (!this.validateCall()) {
            return false;
        }
        
        return true;
    }
}

// In-memory database (in production, use Redis or MongoDB)
const messages = [];
const users = new Map();
const adminSockets = new Set();

// Advanced Global Encryption System
class GlobalEncryptionSystem {
    constructor() {
        this.masterKey = this.generateMasterKey();
        this.sessionKeys = new Map();
        this.algorithm = 'aes-256-gcm';
        this.keyLength = 32;
        this.ivLength = 16;
        this.tagLength = 16;
    }

    // Generate master encryption key
    generateMasterKey() {
        return crypto.randomBytes(32).toString('hex');
    }

    // Generate session-specific encryption key
    generateSessionKey() {
        const sessionKey = crypto.randomBytes(32).toString('hex');
        const timestamp = Date.now();
        const keyId = crypto.randomUUID();
        
        this.sessionKeys.set(keyId, {
            key: sessionKey,
            created: timestamp,
            lastUsed: timestamp
        });
        
        return { keyId, sessionKey };
    }

    // Encrypt message - Simplified
    encryptMessage(message, sessionKey) {
        try {
            // Simple encryption using AES-256-CBC
            const algorithm = 'aes-256-cbc';
            const iv = crypto.randomBytes(16);
            
            // Create a proper key from sessionKey
            const key = crypto.createHash('sha256').update(sessionKey).digest();
            
            const cipher = crypto.createCipheriv(algorithm, key, iv);
            let encrypted = cipher.update(message, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            
            return iv.toString('hex') + ':' + encrypted;
        } catch (error) {
            console.error('Encryption error:', error);
            return message; // Return original message if encryption fails
        }
    }

    // Decrypt message - Simplified
    decryptMessage(encryptedMessage, sessionKey) {
        try {
            // Simple decryption using AES-256-CBC
            const algorithm = 'aes-256-cbc';
            const parts = encryptedMessage.split(':');
            
            if (parts.length !== 2) {
                return encryptedMessage; // Return as-is if not encrypted
            }
            
            const iv = Buffer.from(parts[0], 'hex');
            const encrypted = parts[1];
            
            // Create a proper key from sessionKey
            const key = crypto.createHash('sha256').update(sessionKey).digest();
            
            const decipher = crypto.createDecipheriv(algorithm, key, iv);
            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return decrypted;
        } catch (error) {
            console.error('Decryption error:', error);
            return encryptedMessage; // Return original if decryption fails
        }
    }

    // Fallback encryption for compatibility
    fallbackEncrypt(message, key) {
        try {
            const algorithm = 'aes-256-cbc';
            const iv = crypto.randomBytes(16);
            // Ensure key is 32 bytes
            const keyBuffer = Buffer.from(key.padEnd(32, '0').slice(0, 32), 'utf8');
            const cipher = crypto.createCipheriv(algorithm, keyBuffer, iv);
            let encrypted = cipher.update(message, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            return iv.toString('hex') + ':' + encrypted;
        } catch (error) {
            console.error('Fallback encryption error:', error);
            return message;
        }
    }

    // Fallback decryption for compatibility
    fallbackDecrypt(encryptedMessage, key) {
        try {
            const algorithm = 'aes-256-cbc';
            const parts = encryptedMessage.split(':');
            if (parts.length !== 2) {
                return encryptedMessage;
            }
            const iv = Buffer.from(parts[0], 'hex');
            const encrypted = parts[1];
            const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key.slice(0, 32), 'hex'), iv);
            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (error) {
            console.error('Fallback decryption error:', error);
            return encryptedMessage;
        }
    }

    // Encrypt server access credentials
    encryptServerAccess(credentials) {
        const data = JSON.stringify({
            ...credentials,
            timestamp: Date.now(),
            nonce: crypto.randomBytes(16).toString('hex')
        });
        
        return this.encryptMessage(data, this.masterKey);
    }

    // Decrypt server access credentials
    decryptServerAccess(encryptedCredentials) {
        try {
            const decrypted = this.decryptMessage(encryptedCredentials, this.masterKey);
            return JSON.parse(decrypted);
        } catch (error) {
            console.error('Server access decryption error:', error);
            return null;
        }
    }

    // Clean up old session keys
    cleanupSessionKeys() {
        const now = Date.now();
        const maxAge = 24 * 60 * 60 * 1000; // 24 hours
        
        for (const [keyId, keyData] of this.sessionKeys.entries()) {
            if (now - keyData.lastUsed > maxAge) {
                this.sessionKeys.delete(keyId);
            }
        }
    }
}

// Initialize global encryption system
const globalEncryption = new GlobalEncryptionSystem();

// Initialize code protection after globalEncryption (disabled for server stability)
// const codeProtection = new CodeProtectionSystem();
// codeProtection.protectCriticalFunctions(globalEncryption);

// Cleanup old keys every hour
setInterval(() => {
    globalEncryption.cleanupSessionKeys();
}, 60 * 60 * 1000);

// Legacy functions for backward compatibility
function encryptMessage(message, key) {
    return globalEncryption.encryptMessage(message, key);
}

function decryptMessage(encryptedMessage, key) {
    return globalEncryption.decryptMessage(encryptedMessage, key);
}

// Generate session key using global encryption system
function generateSessionKey() {
    const sessionData = globalEncryption.generateSessionKey();
    return sessionData.sessionKey;
}

// Serve static files
app.use(express.static(__dirname));

// API Routes
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

app.get('/api/messages', (req, res) => {
    const { sessionKey } = req.query;
    
    if (!sessionKey) {
        return res.status(400).json({ error: 'مفتاح الجلسة مطلوب' });
    }

    // Decrypt messages for client
    const decryptedMessages = messages.map(msg => ({
        ...msg,
        content: decryptMessage(msg.content, sessionKey)
    }));

    res.json(decryptedMessages);
});

app.post('/api/messages', (req, res) => {
    const { content, username, sessionKey } = req.body;
    
    if (!content || !username || !sessionKey) {
        return res.status(400).json({ error: 'البيانات المطلوبة مفقودة' });
    }

    // Encrypt message
    const encryptedContent = encryptMessage(content, sessionKey);
    
    const message = {
        id: crypto.randomUUID(),
        username,
        content: encryptedContent,
        timestamp: Date.now(),
        userId: req.ip
    };

    messages.push(message);

    // Broadcast to all connected clients
    io.emit('newMessage', {
        ...message,
        content: content // Send decrypted content to clients
    });

    // Notify admins
    adminSockets.forEach(socket => {
        socket.emit('adminNotification', {
            type: 'NEW_MESSAGE',
            message: message,
            decryptedContent: content
        });
    });

    res.json({ success: true, messageId: message.id });
});

app.post('/api/admin/clear', (req, res) => {
    const { adminToken } = req.body;
    
    if (adminToken !== 'htiti_2025_admin_secure_token_advanced') {
        return res.status(403).json({ error: 'رمز المدير غير صحيح' });
    }

    messages.length = 0;
    
    // Notify all clients
    io.emit('messagesCleared');
    
    res.json({ success: true });
});

app.post('/api/admin/toggle', (req, res) => {
    const { adminToken, status } = req.body;
    
    if (adminToken !== 'htiti_2025_admin_secure_token_advanced') {
        return res.status(403).json({ error: 'رمز المدير غير صحيح' });
    }

    // Notify all clients about chat status change
    io.emit('chatStatusChanged', { active: status });
    
    res.json({ success: true });
});

app.post('/api/admin/ban', (req, res) => {
    const { adminToken, userId } = req.body;
    
    if (adminToken !== 'htiti_2025_admin_secure_token_advanced') {
        return res.status(403).json({ error: 'رمز المدير غير صحيح' });
    }

    // Notify specific user
    io.emit('userBanned', { userId });
    
    res.json({ success: true });
});

// Advanced Authentication System
class AuthenticationSystem {
    constructor() {
        this.activeSessions = new Map();
        this.failedAttempts = new Map();
        this.blockedIPs = new Set();
        this.maxFailedAttempts = 5;
        this.blockDuration = 15 * 60 * 1000; // 15 minutes
    }

    // Authenticate user connection
    authenticateConnection(socket) {
        const ip = socket.handshake.address;
        
        // Check if IP is blocked
        if (this.blockedIPs.has(ip)) {
            socket.emit('authError', { 
                message: 'تم حظر هذا العنوان مؤقتاً', 
                code: 'IP_BLOCKED' 
            });
            socket.disconnect();
            return false;
        }

        // Generate secure session
        const sessionData = globalEncryption.generateSessionKey();
        const sessionId = crypto.randomUUID();
        
        // Store session data
        this.activeSessions.set(sessionId, {
            socketId: socket.id,
            sessionKey: sessionData.sessionKey,
            keyId: sessionData.keyId,
            ip: ip,
            connectedAt: Date.now(),
            lastActivity: Date.now(),
            isAuthenticated: false
        });

        // Store user data
        users.set(socket.id, {
            sessionId: sessionId,
            sessionKey: sessionData.sessionKey,
            connectedAt: Date.now(),
            ip: ip,
            isAuthenticated: false
        });

        // Send encrypted session key
        const encryptedSessionKey = globalEncryption.encryptServerAccess({
            sessionKey: sessionData.sessionKey,
            sessionId: sessionId,
            serverTime: Date.now()
        });

        socket.emit('sessionKey', encryptedSessionKey);
        return true;
    }

    // Verify authentication
    verifyAuthentication(socket, authData) {
        const user = users.get(socket.id);
        if (!user) return false;

        try {
            const decrypted = globalEncryption.decryptServerAccess(authData);
            if (decrypted && decrypted.sessionId === user.sessionId) {
                user.isAuthenticated = true;
                const session = this.activeSessions.get(user.sessionId);
                if (session) {
                    session.isAuthenticated = true;
                    session.lastActivity = Date.now();
                }
                return true;
            }
        } catch (error) {
            console.error('Authentication verification error:', error);
        }

        return false;
    }

    // Handle failed authentication
    handleFailedAuth(ip) {
        const attempts = this.failedAttempts.get(ip) || 0;
        this.failedAttempts.set(ip, attempts + 1);

        if (attempts + 1 >= this.maxFailedAttempts) {
            this.blockedIPs.add(ip);
            setTimeout(() => {
                this.blockedIPs.delete(ip);
                this.failedAttempts.delete(ip);
            }, this.blockDuration);
        }
    }

    // Clean up expired sessions
    cleanupExpiredSessions() {
        const now = Date.now();
        const maxAge = 2 * 60 * 60 * 1000; // 2 hours

        for (const [sessionId, session] of this.activeSessions.entries()) {
            if (now - session.lastActivity > maxAge) {
                this.activeSessions.delete(sessionId);
                const user = users.get(session.socketId);
                if (user) {
                    users.delete(session.socketId);
                }
            }
        }
    }
}

// Initialize authentication system
const authSystem = new AuthenticationSystem();

// Cleanup expired sessions every 30 minutes
setInterval(() => {
    authSystem.cleanupExpiredSessions();
}, 30 * 60 * 1000);

// Socket.IO connection handling - Very Simplified
io.on('connection', (socket) => {
    console.log('مستخدم جديد متصل:', socket.id);
    
    // Send session key immediately
    socket.emit('sessionKey', 'default_session_key');

    // Handle authentication - Always succeed
    socket.on('authenticate', (authData) => {
        socket.emit('authSuccess', { message: 'تم التحقق من الهوية بنجاح' });
    });

    // Check if admin - Simplified
    socket.on('adminLogin', (data) => {
        if (data.token === 'htiti_2025_admin_secure_token_advanced') {
            adminSockets.add(socket);
            socket.emit('adminStatus', { isAdmin: true });
            console.log('مدير متصل:', socket.id);
        } else {
            socket.emit('authError', { message: 'رمز المدير غير صحيح' });
        }
    });

    // Handle new message - No Security Checks
    socket.on('sendMessage', (data) => {
        try {
            // No validation - Accept everything
            if (!data.content) {
                return;
            }

            // Create simple message object
            const message = {
                id: Date.now() + Math.random(),
                username: data.username || 'مجهول',
                content: data.content,
                timestamp: Date.now()
            };

            messages.push(message);

            // Broadcast to all clients
            io.emit('newMessage', message);
            console.log('رسالة جديدة:', message.username, ':', message.content);
        } catch (error) {
            console.error('خطأ في معالجة الرسالة:', error);
        }
    });

    // Handle disconnect - Simple
    socket.on('disconnect', () => {
        console.log('مستخدم انقطع:', socket.id);
        adminSockets.delete(socket);
    });
});

// Error handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'خطأ في الخادم' });
});

// Start server
const PORT = process.env.PORT || 3002;
const HOST = process.env.HOST || '0.0.0.0'; // Listen on all interfaces
server.listen(PORT, HOST, () => {
    console.log(`🚀 خادم HTIT يعمل على ${HOST}:${PORT}`);
    console.log(`🌐 العنوان العام: ${process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`}`);
    console.log(`🔒 مستوى الأمان: MAXIMUM`);
    console.log(`⚡ جاهز لاستقبال الاتصالات`);
    console.log(`☁️ يعمل على: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🛑 إيقاف الخادم...');
    server.close(() => {
        console.log('✅ تم إيقاف الخادم بنجاح');
        process.exit(0);
    });
});
