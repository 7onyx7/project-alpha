/**************************************/
/*        enhanced-security.js        */
/*    ENHANCED SECURITY FEATURES      */
/*         BANTRHAUS v1.0.0           */
/**************************************/

const crypto = require('crypto');
const validator = require('validator');
const logger = require('./logger');

// Additional security utilities
class EnhancedSecurity {
  constructor(pool) {
    this.pool = pool;
    this.setupSecurityFeatures();
  }

  setupSecurityFeatures() {
    // Initialize security monitoring
    this.initializeSecurityMonitoring();
  }

  // IP-based threat detection
  async checkSuspiciousIP(ip) {
    try {
      // Check for rapid requests from same IP
      const recentRequests = await this.pool.query(`
        SELECT COUNT(*) FROM audit_log 
        WHERE ip_address = $1 
        AND created_at > NOW() - INTERVAL '1 minute'
      `, [ip]);

      const requestCount = parseInt(recentRequests.rows[0].count);
      
      if (requestCount > 30) {
        logger.warn('Suspicious IP activity detected', { ip, requestCount });
        return { suspicious: true, reason: 'High request rate' };
      }

      // Check for known malicious patterns
      const maliciousPatterns = [
        /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
        /^10\./,
        /^192\.168\./,
        /^172\.(1[6-9]|2\d|3[01])\./
      ];

      return { suspicious: false };
    } catch (error) {
      logger.error('Error checking suspicious IP', { error: error.message, ip });
      return { suspicious: false };
    }
  }

  // Enhanced password validation
  validatePasswordComplexity(password) {
    const checks = {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      numbers: /[0-9]/.test(password),
      symbols: /[!@#$%^&*(),.?":{}|<>]/.test(password),
      noCommon: !this.isCommonPassword(password),
      noRepeated: !this.hasRepeatedCharacters(password)
    };

    const score = Object.values(checks).filter(Boolean).length;
    const strength = score >= 6 ? 'strong' : score >= 4 ? 'medium' : 'weak';

    return {
      valid: score >= 4,
      strength,
      score,
      checks,
      recommendations: this.getPasswordRecommendations(checks)
    };
  }

  isCommonPassword(password) {
    const common = [
      'password', '123456', 'password123', 'admin', 'qwerty',
      'letmein', 'welcome', 'monkey', '1234567890', '12345678',
      'abc123', 'password1', 'iloveyou', 'admin123', 'welcome123'
    ];
    return common.includes(password.toLowerCase());
  }

  hasRepeatedCharacters(password) {
    return /(.)\1{2,}/.test(password);
  }

  getPasswordRecommendations(checks) {
    const recommendations = [];
    if (!checks.length) recommendations.push('Use at least 8 characters');
    if (!checks.uppercase) recommendations.push('Add uppercase letters');
    if (!checks.lowercase) recommendations.push('Add lowercase letters');
    if (!checks.numbers) recommendations.push('Add numbers');
    if (!checks.symbols) recommendations.push('Add special characters');
    if (!checks.noCommon) recommendations.push('Avoid common passwords');
    if (!checks.noRepeated) recommendations.push('Avoid repeated characters');
    return recommendations;
  }

  // Enhanced email validation
  async validateEmailSecurity(email) {
    const basicValidation = validator.isEmail(email);
    if (!basicValidation) {
      return { valid: false, reason: 'Invalid email format' };
    }

    // Check for disposable email services
    const disposableDomains = [
      '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
      'mailinator.com', 'temp-mail.org', 'throwaway.email',
      'yopmail.com', 'dispostable.com', 'fakeinbox.com'
    ];

    const domain = email.split('@')[1].toLowerCase();
    if (disposableDomains.includes(domain)) {
      return { valid: false, reason: 'Disposable email addresses are not allowed' };
    }

    // Check for suspicious patterns
    const suspiciousPatterns = [
      /^\w+\d{4,}@/, // Many numbers at end
      /^[a-z]+\d{8,}@/, // Long number sequences
      /\+.*\+/, // Multiple + signs
      /\.{2,}/ // Multiple dots
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(email)) {
        return { valid: false, reason: 'Email appears suspicious' };
      }
    }

    return { valid: true, domain };
  }

  // Bot detection
  async detectBot(req) {
    const userAgent = req.get('User-Agent') || '';
    const ip = req.ip;
    
    // Check for bot-like user agents
    const botPatterns = [
      /bot/i, /crawler/i, /spider/i, /scraper/i,
      /curl/i, /wget/i, /python/i, /node/i
    ];

    const isBot = botPatterns.some(pattern => pattern.test(userAgent));
    
    // Check for missing common headers
    const hasCommonHeaders = req.get('Accept') && req.get('Accept-Language');
    
    // Check request timing patterns
    const requestTiming = await this.checkRequestTiming(ip);
    
    return {
      isBot: isBot || !hasCommonHeaders || requestTiming.suspicious,
      confidence: this.calculateBotConfidence(isBot, hasCommonHeaders, requestTiming),
      reasons: this.getBotReasons(isBot, hasCommonHeaders, requestTiming)
    };
  }

  async checkRequestTiming(ip) {
    try {
      const recentRequests = await this.pool.query(`
        SELECT created_at FROM audit_log 
        WHERE ip_address = $1 
        AND created_at > NOW() - INTERVAL '1 minute'
        ORDER BY created_at DESC
        LIMIT 5
      `, [ip]);

      if (recentRequests.rows.length < 3) {
        return { suspicious: false };
      }

      // Check if requests are too regular (bot-like)
      const times = recentRequests.rows.map(row => new Date(row.created_at).getTime());
      const intervals = [];
      for (let i = 1; i < times.length; i++) {
        intervals.push(times[i-1] - times[i]);
      }

      const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance = intervals.reduce((a, b) => a + Math.pow(b - avgInterval, 2), 0) / intervals.length;
      
      // Low variance indicates regular timing (bot-like)
      return { suspicious: variance < 1000, variance, avgInterval };
    } catch (error) {
      logger.error('Error checking request timing', { error: error.message, ip });
      return { suspicious: false };
    }
  }

  calculateBotConfidence(isBot, hasCommonHeaders, requestTiming) {
    let confidence = 0;
    if (isBot) confidence += 40;
    if (!hasCommonHeaders) confidence += 30;
    if (requestTiming.suspicious) confidence += 30;
    return Math.min(confidence, 100);
  }

  getBotReasons(isBot, hasCommonHeaders, requestTiming) {
    const reasons = [];
    if (isBot) reasons.push('Bot-like user agent');
    if (!hasCommonHeaders) reasons.push('Missing common headers');
    if (requestTiming.suspicious) reasons.push('Regular request timing');
    return reasons;
  }

  // Session security
  async validateSession(sessionToken, userId) {
    try {
      const session = await this.pool.query(`
        SELECT * FROM user_sessions 
        WHERE session_token = $1 AND user_id = $2 AND is_active = TRUE
      `, [sessionToken, userId]);

      if (session.rows.length === 0) {
        return { valid: false, reason: 'Session not found' };
      }

      const sessionData = session.rows[0];
      
      // Check if session is expired
      if (new Date(sessionData.expires_at) < new Date()) {
        await this.pool.query('UPDATE user_sessions SET is_active = FALSE WHERE id = $1', [sessionData.id]);
        return { valid: false, reason: 'Session expired' };
      }

      // Update last activity
      await this.pool.query('UPDATE user_sessions SET last_activity = NOW() WHERE id = $1', [sessionData.id]);

      return { valid: true, session: sessionData };
    } catch (error) {
      logger.error('Error validating session', { error: error.message, sessionToken, userId });
      return { valid: false, reason: 'Validation error' };
    }
  }

  // Initialize security monitoring
  initializeSecurityMonitoring() {
    // Set up periodic security checks
    setInterval(async () => {
      try {
        await this.cleanupExpiredSessions();
        await this.checkSecurityThreats();
      } catch (error) {
        logger.error('Security monitoring error', { error: error.message });
      }
    }, 5 * 60 * 1000); // Every 5 minutes
  }

  async cleanupExpiredSessions() {
    try {
      const result = await this.pool.query(`
        UPDATE user_sessions 
        SET is_active = FALSE 
        WHERE expires_at < NOW() AND is_active = TRUE
      `);
      
      if (result.rowCount > 0) {
        logger.info('Cleaned up expired sessions', { count: result.rowCount });
      }
    } catch (error) {
      logger.error('Error cleaning up sessions', { error: error.message });
    }
  }

  async checkSecurityThreats() {
    try {
      // Check for repeated failed login attempts
      const failedLogins = await this.pool.query(`
        SELECT ip_address, COUNT(*) as attempts
        FROM audit_log 
        WHERE action = 'login_failed' 
        AND created_at > NOW() - INTERVAL '15 minutes'
        GROUP BY ip_address
        HAVING COUNT(*) > 10
      `);

      for (const row of failedLogins.rows) {
        logger.warn('Potential brute force attack detected', {
          ip: row.ip_address,
          attempts: row.attempts
        });
      }

      // Check for suspicious registration patterns
      const suspiciousRegistrations = await this.pool.query(`
        SELECT ip_address, COUNT(*) as registrations
        FROM audit_log 
        WHERE action = 'account_created' 
        AND created_at > NOW() - INTERVAL '1 hour'
        GROUP BY ip_address
        HAVING COUNT(*) > 5
      `);

      for (const row of suspiciousRegistrations.rows) {
        logger.warn('Suspicious registration pattern detected', {
          ip: row.ip_address,
          registrations: row.registrations
        });
      }
    } catch (error) {
      logger.error('Error checking security threats', { error: error.message });
    }
  }

  // Generate secure tokens
  generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  // Hash sensitive data
  hashData(data, salt = null) {
    if (!salt) salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(data, salt, 10000, 64, 'sha512');
    return { hash: hash.toString('hex'), salt };
  }

  // Verify hashed data
  verifyHashedData(data, hash, salt) {
    const computedHash = crypto.pbkdf2Sync(data, salt, 10000, 64, 'sha512').toString('hex');
    return computedHash === hash;
  }
}

module.exports = EnhancedSecurity;
