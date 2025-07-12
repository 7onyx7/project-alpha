/**************************************/
/*         moderation.js              */
/*       MODERATION SYSTEM            */
/*         BANTRHAUS v1.0.0           */
/**************************************/

const express = require('express');
const router = express.Router();
const { validateUsername, validateMessage, createReport } = require('./security');
const logger = require('./logger');

// Moderation Dashboard Routes
class ModerationSystem {
  constructor(pool) {
    this.pool = pool;
    this.setupRoutes();
  }

  setupRoutes() {
    // Get pending reports
    router.get('/reports', async (req, res) => {
      try {
        const result = await this.pool.query(`
          SELECT r.*, u1.username as reporter_username, u2.username as reported_username
          FROM reports r
          LEFT JOIN users u1 ON r.reporter_id = u1.id
          LEFT JOIN users u2 ON r.reported_user_id = u2.id
          WHERE r.status = 'pending'
          ORDER BY r.created_at DESC
          LIMIT 50
        `);
        
        res.json({ success: true, reports: result.rows });
      } catch (error) {
        logger.error('Failed to fetch reports', { error: error.message });
        res.status(500).json({ success: false, error: 'Failed to fetch reports' });
      }
    });

    // Handle report (approve/reject)
    router.put('/reports/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const { action, moderatorNotes, banUser, banDuration } = req.body;
        
        // Update report status
        await this.pool.query(
          'UPDATE reports SET status = $1, moderator_notes = $2, resolved_at = NOW() WHERE id = $3',
          [action, moderatorNotes, id]
        );
        
        // If action is to ban the user
        if (action === 'approved' && banUser) {
          const report = await this.pool.query('SELECT * FROM reports WHERE id = $1', [id]);
          if (report.rows.length > 0) {
            const userId = report.rows[0].reported_user_id;
            const expiresAt = banDuration ? new Date(Date.now() + banDuration * 60 * 60 * 1000) : null;
            
            await this.pool.query(
              'INSERT INTO banned_users (user_id, reason, banned_at, expires_at) VALUES ($1, $2, NOW(), $3)',
              [userId, moderatorNotes, expiresAt]
            );
          }
        }
        
        res.json({ success: true, message: 'Report handled successfully' });
      } catch (error) {
        logger.error('Failed to handle report', { error: error.message });
        res.status(500).json({ success: false, error: 'Failed to handle report' });
      }
    });

    // Get banned users
    router.get('/banned-users', async (req, res) => {
      try {
        const result = await this.pool.query(`
          SELECT bu.*, u.username
          FROM banned_users bu
          JOIN users u ON bu.user_id = u.id
          WHERE bu.is_active = TRUE
          ORDER BY bu.banned_at DESC
        `);
        
        res.json({ success: true, bannedUsers: result.rows });
      } catch (error) {
        logger.error('Failed to fetch banned users', { error: error.message });
        res.status(500).json({ success: false, error: 'Failed to fetch banned users' });
      }
    });

    // Unban user
    router.put('/banned-users/:id/unban', async (req, res) => {
      try {
        const { id } = req.params;
        
        await this.pool.query(
          'UPDATE banned_users SET is_active = FALSE WHERE id = $1',
          [id]
        );
        
        res.json({ success: true, message: 'User unbanned successfully' });
      } catch (error) {
        logger.error('Failed to unban user', { error: error.message });
        res.status(500).json({ success: false, error: 'Failed to unban user' });
      }
    });

    // Get audit log
    router.get('/audit-log', async (req, res) => {
      try {
        const result = await this.pool.query(`
          SELECT al.*, u.username
          FROM audit_log al
          LEFT JOIN users u ON al.user_id = u.id
          ORDER BY al.created_at DESC
          LIMIT 100
        `);
        
        res.json({ success: true, logs: result.rows });
      } catch (error) {
        logger.error('Failed to fetch audit log', { error: error.message });
        res.status(500).json({ success: false, error: 'Failed to fetch audit log' });
      }
    });

    // Get moderation statistics
    router.get('/stats', async (req, res) => {
      try {
        const stats = await this.getModerationStats();
        res.json({ success: true, stats });
      } catch (error) {
        logger.error('Failed to fetch moderation stats', { error: error.message });
        res.status(500).json({ success: false, error: 'Failed to fetch stats' });
      }
    });

    return router;
  }

  async getModerationStats() {
    const [
      totalReports,
      pendingReports,
      resolvedReports,
      bannedUsers,
      totalUsers,
      activeUsers
    ] = await Promise.all([
      this.pool.query('SELECT COUNT(*) FROM reports'),
      this.pool.query('SELECT COUNT(*) FROM reports WHERE status = \'pending\''),
      this.pool.query('SELECT COUNT(*) FROM reports WHERE status != \'pending\''),
      this.pool.query('SELECT COUNT(*) FROM banned_users WHERE is_active = TRUE'),
      this.pool.query('SELECT COUNT(*) FROM users'),
      this.pool.query('SELECT COUNT(*) FROM user_sessions WHERE is_active = TRUE AND expires_at > NOW()')
    ]);

    return {
      totalReports: parseInt(totalReports.rows[0].count),
      pendingReports: parseInt(pendingReports.rows[0].count),
      resolvedReports: parseInt(resolvedReports.rows[0].count),
      bannedUsers: parseInt(bannedUsers.rows[0].count),
      totalUsers: parseInt(totalUsers.rows[0].count),
      activeUsers: parseInt(activeUsers.rows[0].count)
    };
  }

  // Check if user is banned
  async isUserBanned(userId) {
    try {
      const result = await this.pool.query(`
        SELECT * FROM banned_users 
        WHERE user_id = $1 AND is_active = TRUE 
        AND (expires_at IS NULL OR expires_at > NOW())
      `, [userId]);
      
      return result.rows.length > 0;
    } catch (error) {
      logger.error('Failed to check ban status', { error: error.message, userId });
      return false;
    }
  }

  // Log user action
  async logUserAction(userId, action, details, req) {
    try {
      let ip = '0.0.0.0';
      let userAgent = 'Unknown';
      
      // Handle both Express req objects and custom objects from Socket.IO
      if (req) {
        if (req.ip) {
          // Regular Express request
          ip = req.ip;
          userAgent = req.get ? req.get('User-Agent') || 'Unknown' : 'Unknown';
        } else if (typeof req === 'object') {
          // Custom object from Socket.IO or manual call
          ip = req.ip || '0.0.0.0';
          userAgent = req.userAgent || 'Socket.IO Client';
        }
      }
      
      // Ensure details is always an object
      const detailsObj = typeof details === 'object' ? details : { info: details };
      
      // Add timestamp and additional context
      const enrichedDetails = {
        ...detailsObj,
        timestamp: new Date().toISOString(),
        source: req && req.ip ? 'express' : 'socket'
      };
      
      await this.pool.query(
        'INSERT INTO audit_log (user_id, action, details, ip_address, user_agent) VALUES ($1, $2, $3, $4, $5)',
        [userId, action, JSON.stringify(enrichedDetails), ip, userAgent]
      );
      
      logger.info("User action logged successfully", { 
        userId, 
        action, 
        ip, 
        userAgent 
      });
    } catch (error) {
      logger.error('Failed to log user action', { 
        error: error.message, 
        stack: error.stack,
        userId, 
        action,
        details: typeof details === 'object' ? JSON.stringify(details) : details,
        reqType: req ? typeof req : 'undefined'
      });
    }
  }

  // Auto-moderate message
  async autoModerateMessage(message, userId, room, reqContext = null) {
    const validation = await validateMessage(message);
    
    if (!validation.valid) {
      if (userId) {
        await this.logUserAction(userId, 'message_blocked', {
          reason: validation.error,
          originalMessage: message,
          room
        }, reqContext || { ip: '0.0.0.0', userAgent: 'Auto-Moderation' });
      }
      return { allowed: false, reason: validation.error };
    }

    // Skip spam detection for anonymous users (userId might be null)
    if (userId) {
      // Check for repeated messages (spam detection)
      try {
        const recentMessages = await this.pool.query(`
          SELECT COUNT(*) FROM messages 
          WHERE username = (SELECT username FROM users WHERE id = $1) 
          AND message = $2 
          AND timestamp > NOW() - INTERVAL '5 minutes'
        `, [userId, validation.cleaned]);

        if (parseInt(recentMessages.rows[0].count) >= 3) {
          await this.logUserAction(userId, 'spam_detected', {
            message: validation.cleaned,
            room
          }, reqContext || { ip: '0.0.0.0', userAgent: 'Spam-Detection' });
          return { allowed: false, reason: 'Duplicate message detected' };
        }
      } catch (error) {
        logger.error('Error checking for spam', { error: error.message, userId });
        // Continue even if spam check fails
      }
    }

    return { allowed: true, cleanedMessage: validation.cleaned };
  }

  getRoutes() {
    return router;
  }
}

module.exports = ModerationSystem;
