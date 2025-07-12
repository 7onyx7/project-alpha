/**************************************/
/*         custom-csrf.js             */
/*      CUSTOM CSRF PROTECTION        */
/*         BANTRHAUS v1.0.0           */
/**************************************/

const crypto = require('crypto');
const logger = require('./logger');

class CustomCSRF {
  constructor() {
    this.tokens = new Map();
    this.secret = process.env.CSRF_SECRET || crypto.randomBytes(32).toString('hex');
    
    // Clean up expired tokens every hour
    setInterval(() => {
      this.cleanupExpiredTokens();
    }, 60 * 60 * 1000);
  }

  generateToken(sessionId = null) {
    const token = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + (60 * 60 * 1000); // 1 hour
    
    // Store token with expiration
    this.tokens.set(token, {
      sessionId,
      expires,
      used: false
    });

    return token;
  }

  validateToken(token, sessionId = null) {
    if (!token) {
      return false;
    }

    const tokenData = this.tokens.get(token);
    if (!tokenData) {
      return false;
    }

    // Check if token is expired
    if (Date.now() > tokenData.expires) {
      this.tokens.delete(token);
      return false;
    }

    // Check if token is already used (one-time use)
    if (tokenData.used) {
      this.tokens.delete(token);
      return false;
    }

    // Check session ID if provided
    if (sessionId && tokenData.sessionId && tokenData.sessionId !== sessionId) {
      return false;
    }

    // Mark token as used
    tokenData.used = true;
    
    // Remove token after short delay to prevent race conditions
    setTimeout(() => {
      this.tokens.delete(token);
    }, 1000);

    return true;
  }

  cleanupExpiredTokens() {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [token, data] of this.tokens.entries()) {
      if (now > data.expires || data.used) {
        this.tokens.delete(token);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      logger.info(`Cleaned up ${cleaned} expired CSRF tokens`);
    }
  }

  middleware() {
    return (req, res, next) => {
      // Generate token for GET requests
      if (req.method === 'GET') {
        const sessionId = req.sessionID || req.ip;
        const token = this.generateToken(sessionId);
        
        // Add token to response locals for templates
        res.locals.csrfToken = token;
        
        // Add method to get token
        req.csrfToken = () => token;
        
        return next();
      }

      // Validate token for state-changing requests
      if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
        const token = req.headers['csrf-token'] || 
                     req.headers['x-csrf-token'] ||
                     req.body._csrf ||
                     req.query._csrf;

        const sessionId = req.sessionID || req.ip;
        
        if (!this.validateToken(token, sessionId)) {
          logger.warn('CSRF token validation failed', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            method: req.method,
            url: req.originalUrl
          });
          
          return res.status(403).json({
            success: false,
            message: 'Invalid or expired security token. Please refresh the page and try again.'
          });
        }
      }

      next();
    };
  }

  // Route to get CSRF token
  getTokenRoute() {
    return (req, res) => {
      const sessionId = req.sessionID || req.ip;
      const token = this.generateToken(sessionId);
      res.json({ csrfToken: token });
    };
  }
}

module.exports = CustomCSRF;
