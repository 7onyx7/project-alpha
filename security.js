/**************************************/
/*           security.js              */
/*      SECURITY & MODERATION         */
/*         BANTRHAUS v1.0.0           */
/**************************************/

const validator = require('validator');
const rateLimit = require('express-rate-limit');
const logger = require('./logger');

// In-memory storage for banned IPs and violations
// In production, use Redis or database
const bannedIPs = new Map();
const ipViolations = new Map();

// Security Configuration
const SecurityConfig = {
  // Rate limiting settings
  LOGIN_WINDOW_MS: 15 * 60 * 1000, // 15 minutes
  LOGIN_MAX_ATTEMPTS: 5,
  MESSAGE_WINDOW_MS: 30 * 1000, // 30 seconds
  MESSAGE_MAX_COUNT: 10,
  REGISTER_WINDOW_MS: 60 * 60 * 1000, // 1 hour
  REGISTER_MAX_ATTEMPTS: 3,
  
  // Content validation
  MAX_MESSAGE_LENGTH: 500,
  MAX_USERNAME_LENGTH: 30,
  MIN_USERNAME_LENGTH: 3,
  MAX_ROOM_NAME_LENGTH: 50,
  
  // Session settings
  SESSION_TIMEOUT: 60 * 60 * 1000, // 1 hour
  
  // Age verification
  MINIMUM_AGE: 18,
  
  // IP banning
  IP_BAN_DURATION: 24 * 60 * 60 * 1000, // 24 hours
  MAX_VIOLATIONS_BEFORE_BAN: 3,
  
  // VPN detection
  BLOCK_VPNS: true,
  VPN_CHECK_TIMEOUT: 5000 // 5 seconds
};

// Enhanced Rate Limiters
const createLoginLimiter = () => rateLimit({
  windowMs: SecurityConfig.LOGIN_WINDOW_MS,
  max: SecurityConfig.LOGIN_MAX_ATTEMPTS,
  message: {
    success: false,
    message: 'Too many login attempts. Please try again in 15 minutes.',
    retryAfter: Math.ceil(SecurityConfig.LOGIN_WINDOW_MS / 1000)
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('Login rate limit exceeded', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString()
    });
    res.status(429).json({
      success: false,
      message: 'Too many login attempts. Please try again in 15 minutes.'
    });
  }
});

const createMessageLimiter = () => rateLimit({
  windowMs: SecurityConfig.MESSAGE_WINDOW_MS,
  max: SecurityConfig.MESSAGE_MAX_COUNT,
  message: 'Too many messages. Please slow down.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('Message rate limit exceeded', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString()
    });
    res.status(429).json({
      success: false,
      message: 'Too many messages. Please slow down.'
    });
  }
});

const createRegisterLimiter = () => rateLimit({
  windowMs: SecurityConfig.REGISTER_WINDOW_MS,
  max: SecurityConfig.REGISTER_MAX_ATTEMPTS,
  message: {
    success: false,
    message: 'Too many registration attempts. Please try again in 1 hour.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('Registration rate limit exceeded', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString()
    });
    res.status(429).json({
      success: false,
      message: 'Too many registration attempts. Please try again in 1 hour.'
    });
  }
});

// Content Validation Functions
const validateUsername = (username) => {
  if (!username || typeof username !== 'string') {
    return { valid: false, error: 'Username is required' };
  }
  
  username = username.trim();
  
  if (username.length < SecurityConfig.MIN_USERNAME_LENGTH) {
    return { valid: false, error: `Username must be at least ${SecurityConfig.MIN_USERNAME_LENGTH} characters` };
  }
  
  if (username.length > SecurityConfig.MAX_USERNAME_LENGTH) {
    return { valid: false, error: `Username must be less than ${SecurityConfig.MAX_USERNAME_LENGTH} characters` };
  }
  
  // Check for valid characters (alphanumeric, spaces, underscores, hyphens)
  if (!/^[a-zA-Z0-9\s_-]+$/.test(username)) {
    return { valid: false, error: 'Username contains invalid characters' };
  }
  
  // Check for spam patterns
  if (isSpamContent(username)) {
    return { valid: false, error: 'Username appears to be spam' };
  }
  
  // For inappropriate username filtering, we'll use a third-party service
  // This keeps our codebase clean and compliant with GitHub ToS
  return { valid: true, cleaned: username };
};

const validateMessage = async (message, ip = null) => {
  if (!message || typeof message !== 'string') {
    return { valid: false, error: 'Message is required' };
  }
  
  message = message.trim();
  
  if (message.length === 0) {
    return { valid: false, error: 'Message cannot be empty' };
  }
  
  if (message.length > SecurityConfig.MAX_MESSAGE_LENGTH) {
    return { valid: false, error: `Message must be less than ${SecurityConfig.MAX_MESSAGE_LENGTH} characters` };
  }

  // Check for spam patterns only
  if (isSpamContent(message)) {
    logger.warn('Spam message blocked', { message, ip, timestamp: new Date().toISOString() });
    if (ip) recordViolation(ip, 'spam');
    return { valid: false, error: 'Message appears to be spam' };
  }

  // Use external content moderation service
  try {
    const moderationResult = await checkContentWithExternalService(message, 'message');
    if (!moderationResult.isAppropriate) {
      logger.warn('Inappropriate content blocked by external service', { 
        message, 
        ip, 
        confidence: moderationResult.confidence,
        categories: moderationResult.categories
      });
      if (ip) recordViolation(ip, 'inappropriate_content');
      return { valid: false, error: 'Message violates community guidelines' };
    }
  } catch (error) {
    logger.error('Content moderation check failed', { error: error.message, message });
    // Continue with message if moderation service fails
  }

  return { valid: true, cleaned: message };
};

const validateEmail = (email) => {
  if (!email || typeof email !== 'string') {
    return { valid: false, error: 'Email is required' };
  }
  
  if (!validator.isEmail(email)) {
    return { valid: false, error: 'Invalid email format' };
  }
  
  // Check for disposable email domains
  const disposableDomains = [
    '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
    'mailinator.com', 'temp-mail.org', 'throwaway.email'
  ];
  
  const domain = email.split('@')[1];
  if (disposableDomains.includes(domain)) {
    return { valid: false, error: 'Please use a permanent email address' };
  }
  
  return { valid: true, cleaned: email.toLowerCase() };
};

const validatePassword = (password) => {
  if (!password || typeof password !== 'string') {
    return { valid: false, error: 'Password is required' };
  }
  
  if (password.length < 8) {
    return { valid: false, error: 'Password must be at least 8 characters' };
  }
  
  if (password.length > 128) {
    return { valid: false, error: 'Password is too long' };
  }
  
  // Check for basic complexity
  let score = 0;
  if (/[a-z]/.test(password)) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;
  
  if (score < 2) {
    return { valid: false, error: 'Password must contain at least 2 of: lowercase, uppercase, numbers, symbols' };
  }
  
  // Check for common passwords
  const commonPasswords = [
    'password', '123456', 'password123', 'admin', 'qwerty',
    'letmein', 'welcome', 'monkey', '1234567890'
  ];
  
  if (commonPasswords.includes(password.toLowerCase())) {
    return { valid: false, error: 'Password is too common' };
  }
  
  return { valid: true };
};

// Spam Detection
const isSpamContent = (content) => {
  const spamPatterns = [
    // URL patterns
    /https?:\/\//i,
    /www\./i,
    /\.com/i,
    /\.org/i,
    /\.net/i,
    
    // Repetitive characters
    /(.)\1{4,}/,
    
    // ALL CAPS (more than 70% of characters)
    /^[A-Z\s]{7,}$/,
    
    // Excessive punctuation
    /[!@#$%^&*()]{3,}/,
    
    // Common spam phrases
    /free\s+money/i,
    /click\s+here/i,
    /urgent/i,
    /winner/i,
    /congratulations/i,
    /lottery/i,
    /casino/i,
    /viagra/i,
    /enlargement/i,
    /make\s+money/i,
    /work\s+from\s+home/i
  ];
  
  return spamPatterns.some(pattern => pattern.test(content));
};

// Age Verification
const validateAge = (birthdate) => {
  if (!birthdate) {
    return { valid: false, error: 'Date of birth is required' };
  }
  
  const birth = new Date(birthdate);
  const today = new Date();
  const age = today.getFullYear() - birth.getFullYear();
  const monthDiff = today.getMonth() - birth.getMonth();
  
  if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birth.getDate())) {
    age--;
  }
  
  if (age < SecurityConfig.MINIMUM_AGE) {
    return { valid: false, error: `You must be at least ${SecurityConfig.MINIMUM_AGE} years old to use this service` };
  }
  
  return { valid: true, age };
};

// Report System
const createReport = async (pool, reportData) => {
  const { reporterId, reportedUserId, messageId, reason, content, room } = reportData;
  
  try {
    const result = await pool.query(
      `INSERT INTO reports (reporter_id, reported_user_id, message_id, reason, content, room, status, created_at) 
       VALUES ($1, $2, $3, $4, $5, $6, 'pending', NOW()) 
       RETURNING id`,
      [reporterId, reportedUserId, messageId, reason, content, room]
    );
    
    logger.info('Report created', {
      reportId: result.rows[0].id,
      reporterId,
      reportedUserId,
      reason,
      timestamp: new Date().toISOString()
    });
    
    return { success: true, reportId: result.rows[0].id };
  } catch (error) {
    logger.error('Failed to create report', { error: error.message, reportData });
    return { success: false, error: 'Failed to create report' };
  }
};

// IP Banning System
const banIP = (ip, reason = 'Policy violation', duration = SecurityConfig.IP_BAN_DURATION) => {
  const banExpiry = new Date(Date.now() + duration);
  bannedIPs.set(ip, {
    reason,
    bannedAt: new Date(),
    expiresAt: banExpiry
  });
  
  logger.warn('IP banned', { ip, reason, expiresAt: banExpiry });
  return { success: true, expiresAt: banExpiry };
};

const isIPBanned = (ip) => {
  const ban = bannedIPs.get(ip);
  if (!ban) return false;
  
  // Check if ban has expired
  if (new Date() > ban.expiresAt) {
    bannedIPs.delete(ip);
    return false;
  }
  
  return true;
};

const recordViolation = (ip, violation) => {
  const violations = ipViolations.get(ip) || [];
  violations.push({
    type: violation,
    timestamp: new Date()
  });
  
  // Keep only recent violations (last 24 hours)
  const recent = violations.filter(v => 
    new Date() - v.timestamp < 24 * 60 * 60 * 1000
  );
  
  ipViolations.set(ip, recent);
  
  // Auto-ban if too many violations
  if (recent.length >= SecurityConfig.MAX_VIOLATIONS_BEFORE_BAN) {
    banIP(ip, `Too many violations: ${recent.length}`);
    return true; // IP was banned
  }
  
  return false;
};

// VPN Detection
const checkForVPN = async (ip) => {
  if (!SecurityConfig.BLOCK_VPNS) return { isVPN: false };
  
  try {
    // Simple VPN detection using known VPN IP ranges
    // In production, use a proper VPN detection service
    const vpnRanges = [
      /^10\./, // Private range often used by VPNs
      /^172\.(1[6-9]|2[0-9]|3[01])\./, // Private range
      /^192\.168\./, // Private range
      /^127\./, // Localhost
    ];
    
    const isPrivateIP = vpnRanges.some(range => range.test(ip));
    
    if (isPrivateIP && ip !== '127.0.0.1') {
      logger.warn('Potential VPN detected', { ip });
      return { isVPN: true, reason: 'Private IP range' };
    }
    
    // You can integrate with services like:
    // - IPQualityScore
    // - GetIPIntel
    // - VPNapi.io
    // - ProxyCheck.io
    
    return { isVPN: false };
  } catch (error) {
    logger.error('VPN check failed', { ip, error: error.message });
    return { isVPN: false }; // Allow on error
  }
};

// External Content Moderation
const checkContentWithExternalService = async (content, type = 'message') => {
  try {
    // Placeholder for external moderation service
    // You can integrate with:
    // - Perspective API (Google)
    // - Azure Content Moderator
    // - AWS Comprehend
    // - Sightengine
    // - WebPurify
    
    // Example structure for external API call:
    /*
    const response = await fetch('https://api.moderationservice.com/check', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.MODERATION_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        text: content,
        type: type,
        language: 'en'
      })
    });
    
    const result = await response.json();
    return {
      isAppropriate: result.score < 0.7, // Threshold
      confidence: result.confidence,
      categories: result.categories
    };
    */
    
    // For now, return safe
    return { isAppropriate: true, confidence: 1.0, categories: [] };
  } catch (error) {
    logger.error('External moderation check failed', { error: error.message });
    // Default to allowing content if service fails
    return { isAppropriate: true, confidence: 0.0, categories: [] };
  }
};

// Security Middleware
const securityMiddleware = {
  // IP Ban Check
  checkIPBan: (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    
    if (isIPBanned(ip)) {
      const ban = bannedIPs.get(ip);
      logger.warn('Blocked request from banned IP', { ip, ban });
      return res.status(403).json({
        success: false,
        message: 'Your IP address has been temporarily banned',
        reason: ban.reason,
        expiresAt: ban.expiresAt
      });
    }
    
    next();
  },

  // VPN Check
  checkVPN: async (req, res, next) => {
    if (!SecurityConfig.BLOCK_VPNS) return next();
    
    const ip = req.ip || req.connection.remoteAddress;
    
    try {
      const vpnCheck = await checkForVPN(ip);
      if (vpnCheck.isVPN) {
        recordViolation(ip, 'vpn_usage');
        logger.warn('VPN detected and blocked', { ip, reason: vpnCheck.reason });
        return res.status(403).json({
          success: false,
          message: 'VPN usage is not allowed on this platform'
        });
      }
    } catch (error) {
      logger.error('VPN check failed', { ip, error: error.message });
      // Continue on error
    }
    
    next();
  },

  validateInput: (req, res, next) => {
    // Basic XSS protection
    const sanitizeString = (str) => {
      if (typeof str !== 'string') return str;
      return str
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/<[^>]+>/g, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '')
        .replace(/data:/gi, '')
        .replace(/vbscript:/gi, '');
    };
    
    // Sanitize request body
    if (req.body) {
      for (const key in req.body) {
        if (typeof req.body[key] === 'string') {
          req.body[key] = sanitizeString(req.body[key]);
        }
      }
    }
    
    // Sanitize query parameters
    if (req.query) {
      for (const key in req.query) {
        if (typeof req.query[key] === 'string') {
          req.query[key] = sanitizeString(req.query[key]);
        }
      }
    }
    
    next();
  },
  
  logSuspiciousActivity: (req, res, next) => {
    const userAgent = req.get('User-Agent');
    const ip = req.ip || req.connection.remoteAddress;
    
    // Log potential bot activity
    if (!userAgent || userAgent.length < 20) {
      logger.warn('Suspicious user agent', { userAgent, ip, url: req.originalUrl });
      recordViolation(ip, 'suspicious_user_agent');
    }
    
    next();
  }
};

// Database Schema Creation
const createSecurityTables = async (pool) => {
  try {
    // Reports table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS reports (
        id SERIAL PRIMARY KEY,
        reporter_id INTEGER,
        reported_user_id INTEGER,
        message_id INTEGER,
        reason VARCHAR(100) NOT NULL,
        content TEXT,
        room VARCHAR(100),
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP,
        moderator_notes TEXT
      )
    `);
    
    // Banned users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS banned_users (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        reason TEXT,
        banned_by INTEGER,
        banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE
      )
    `);
    
    // User sessions table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        session_token VARCHAR(255) NOT NULL,
        ip_address INET,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        is_active BOOLEAN DEFAULT TRUE
      )
    `);
    
    // Audit log table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        action VARCHAR(100) NOT NULL,
        details JSONB,
        ip_address INET,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    logger.info('Security tables created successfully');
  } catch (error) {
    logger.error('Failed to create security tables', { error: error.message });
    throw error;
  }
};

module.exports = {
  SecurityConfig,
  validateUsername,
  validateMessage,
  validateEmail,
  validatePassword,
  validateAge,
  createReport,
  securityMiddleware,
  // Database table creation function (call manually when needed)
  createSecurityTables,
  // IP management functions
  banIP,
  isIPBanned,
  recordViolation,
  checkForVPN,
  checkContentWithExternalService,
  // Access to violation tracking
  ipViolations,
  bannedIPs,
  rateLimiters: {
    loginLimiter: createLoginLimiter(),
    messageLimiter: createMessageLimiter(),
    registerLimiter: createRegisterLimiter()
  }
};
