/**************************************/
/*          admin-auth.js             */
/*       ADMIN AUTHENTICATION         */
/*         BANTRHAUS v1.0.0           */
/**************************************/

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const logger = require('./logger');

// Admin configuration
const AdminConfig = {
  // Default admin credentials (change these immediately)
  DEFAULT_ADMIN_USERNAME: process.env.ADMIN_USERNAME || 'admin',
  DEFAULT_ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || 'bantrhaus_admin_2025!',
  
  // Session settings
  SESSION_DURATION: 24 * 60 * 60 * 1000, // 24 hours
  
  // Security settings
  MAX_LOGIN_ATTEMPTS: 3,
  LOCKOUT_DURATION: 30 * 60 * 1000 // 30 minutes
};

// In-memory admin session storage (use Redis in production)
const adminSessions = new Map();
const loginAttempts = new Map();

class AdminAuth {
  constructor(pool) {
    this.pool = pool;
    this.initializeAdminUser();
  }

  // Initialize default admin user
  async initializeAdminUser() {
    try {
      // Check if admin user exists
      const result = await this.pool.query(
        'SELECT id FROM users WHERE username = $1 AND role = $2',
        [AdminConfig.DEFAULT_ADMIN_USERNAME, 'admin']
      );

      if (result.rows.length === 0) {
        // Create admin user
        const hashedPassword = await bcrypt.hash(AdminConfig.DEFAULT_ADMIN_PASSWORD, 12);
        
        await this.pool.query(`
          INSERT INTO users (username, email, password, role, created_at)
          VALUES ($1, $2, $3, 'admin', NOW())
          ON CONFLICT (username) DO UPDATE SET
            role = 'admin',
            password = $3
        `, [
          AdminConfig.DEFAULT_ADMIN_USERNAME,
          'admin@bantrhaus.local',
          hashedPassword
        ]);

        logger.info('Default admin user created/updated', {
          username: AdminConfig.DEFAULT_ADMIN_USERNAME,
          warning: 'Please change default credentials immediately!'
        });
      }
    } catch (error) {
      logger.error('Failed to initialize admin user', { error: error.message });
    }
  }

  // Check if IP is locked out
  isLockedOut(ip) {
    const attempts = loginAttempts.get(ip);
    if (!attempts) return false;
    
    const { count, lastAttempt } = attempts;
    const timeSinceLastAttempt = Date.now() - lastAttempt;
    
    if (count >= AdminConfig.MAX_LOGIN_ATTEMPTS && timeSinceLastAttempt < AdminConfig.LOCKOUT_DURATION) {
      return true;
    }
    
    // Reset attempts if lockout period has passed
    if (timeSinceLastAttempt >= AdminConfig.LOCKOUT_DURATION) {
      loginAttempts.delete(ip);
    }
    
    return false;
  }

  // Record failed login attempt
  recordFailedAttempt(ip) {
    const attempts = loginAttempts.get(ip) || { count: 0, lastAttempt: 0 };
    attempts.count++;
    attempts.lastAttempt = Date.now();
    loginAttempts.set(ip, attempts);
    
    logger.warn('Admin login attempt failed', { ip, attempts: attempts.count });
  }

  // Reset login attempts on successful login
  resetAttempts(ip) {
    loginAttempts.delete(ip);
  }

  // Authenticate admin login
  async authenticateAdmin(username, password, ip) {
    try {
      // Check if IP is locked out
      if (this.isLockedOut(ip)) {
        return {
          success: false,
          error: 'Too many failed attempts. Please try again later.',
          lockoutRemaining: AdminConfig.LOCKOUT_DURATION
        };
      }

      // Get admin user
      const result = await this.pool.query(
        'SELECT id, username, password FROM users WHERE username = $1 AND role = $2',
        [username, 'admin']
      );

      if (result.rows.length === 0) {
        this.recordFailedAttempt(ip);
        return { success: false, error: 'Invalid admin credentials' };
      }

      const admin = result.rows[0];
      
      // Verify password
      const passwordValid = await bcrypt.compare(password, admin.password);
      if (!passwordValid) {
        this.recordFailedAttempt(ip);
        return { success: false, error: 'Invalid admin credentials' };
      }

      // Reset failed attempts
      this.resetAttempts(ip);

      // Create session token
      const sessionToken = jwt.sign(
        {
          id: admin.id,
          username: admin.username,
          isAdmin: true,
          loginTime: Date.now()
        },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

      // Store session
      adminSessions.set(sessionToken, {
        adminId: admin.id,
        username: admin.username,
        ip,
        loginTime: Date.now(),
        lastActivity: Date.now()
      });

      logger.info('Admin login successful', {
        adminId: admin.id,
        username: admin.username,
        ip
      });

      return {
        success: true,
        token: sessionToken,
        admin: {
          id: admin.id,
          username: admin.username
        }
      };

    } catch (error) {
      logger.error('Admin authentication error', { error: error.message, ip });
      return { success: false, error: 'Authentication failed' };
    }
  }

  // Verify admin session
  verifyAdminSession(token) {
    try {
      // Verify JWT token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      if (!decoded.isAdmin) {
        return { valid: false, error: 'Not an admin token' };
      }

      // Check session exists
      const session = adminSessions.get(token);
      if (!session) {
        return { valid: false, error: 'Session not found' };
      }

      // Check session expiry
      const sessionAge = Date.now() - session.loginTime;
      if (sessionAge > AdminConfig.SESSION_DURATION) {
        adminSessions.delete(token);
        return { valid: false, error: 'Session expired' };
      }

      // Update last activity
      session.lastActivity = Date.now();
      adminSessions.set(token, session);

      return {
        valid: true,
        admin: {
          id: decoded.id,
          username: decoded.username
        }
      };

    } catch (error) {
      logger.warn('Invalid admin token', { error: error.message });
      return { valid: false, error: 'Invalid token' };
    }
  }

  // Admin logout
  logout(token) {
    if (adminSessions.has(token)) {
      const session = adminSessions.get(token);
      adminSessions.delete(token);
      
      logger.info('Admin logout', {
        username: session.username,
        sessionDuration: Date.now() - session.loginTime
      });
    }
  }

  // Get active admin sessions
  getActiveSessions() {
    const sessions = [];
    const now = Date.now();
    
    for (const [token, session] of adminSessions) {
      const sessionAge = now - session.loginTime;
      if (sessionAge <= AdminConfig.SESSION_DURATION) {
        sessions.push({
          username: session.username,
          ip: session.ip,
          loginTime: new Date(session.loginTime),
          lastActivity: new Date(session.lastActivity),
          sessionAge: Math.floor(sessionAge / 1000 / 60) // minutes
        });
      } else {
        // Clean up expired sessions
        adminSessions.delete(token);
      }
    }
    
    return sessions;
  }

  // Middleware to protect admin routes
  requireAdmin() {
    return (req, res, next) => {
      const token = req.headers.authorization?.split(' ')[1] || req.cookies.adminToken;
      
      if (!token) {
        return res.status(401).json({
          success: false,
          error: 'Admin authentication required'
        });
      }

      const verification = this.verifyAdminSession(token);
      if (!verification.valid) {
        return res.status(401).json({
          success: false,
          error: verification.error
        });
      }

      req.admin = verification.admin;
      next();
    };
  }

  // Middleware to redirect unauthenticated users to login
  requireAdminPage() {
    return (req, res, next) => {
      const token = req.cookies.adminToken;
      
      if (!token) {
        return res.redirect('/admin/login');
      }

      const verification = this.verifyAdminSession(token);
      if (!verification.valid) {
        res.clearCookie('adminToken');
        return res.redirect('/admin/login');
      }

      req.admin = verification.admin;
      next();
    };
  }
}

module.exports = { AdminAuth, AdminConfig };
