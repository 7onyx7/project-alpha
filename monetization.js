/**************************************/
/*         monetization.js            */
/*      MONETIZATION SYSTEM           */
/*         BANTRHAUS v1.0.0           */
/**************************************/

const express = require('express');
const router = express.Router();
const logger = require('./logger');

// Monetization Configuration
const MonetizationConfig = {
  // Premium Features
  PREMIUM_MONTHLY_PRICE: 4.99,
  PREMIUM_YEARLY_PRICE: 49.99,
  
  // Profile Customization
  PROFILE_ART_PRICE: 1.99,
  CUSTOM_ANIMATION_PRICE: 2.99,
  CUSTOM_EMOJI_PACK_PRICE: 0.99,
  PREMIUM_THEMES_PRICE: 1.49,
  
  // Chat Enhancements
  MESSAGE_REACTIONS_PRICE: 0.99,
  CUSTOM_FONTS_PRICE: 1.99,
  MESSAGE_EFFECTS_PRICE: 2.49,
  PRIORITY_CHAT_PRICE: 3.99,
  
  // Room Features
  PRIVATE_ROOMS_PRICE: 2.99,
  CUSTOM_ROOM_THEMES_PRICE: 1.99,
  ROOM_MODERATION_TOOLS_PRICE: 4.99,
  
  // Business Features
  BUSINESS_MONTHLY_PRICE: 19.99,
  BRANDED_ROOMS_PRICE: 9.99,
  ANALYTICS_DASHBOARD_PRICE: 14.99,
  
  // Ad Revenue
  AD_REVENUE_SHARE: 0.70, // 70% to creators, 30% to platform
  MINIMUM_PAYOUT: 10.00
};

class MonetizationSystem {
  constructor(pool) {
    this.pool = pool;
    this.setupRoutes();
  }

  async setupRoutes() {
    // Get user's premium status
    router.get('/premium-status/:userId', async (req, res) => {
      try {
        const { userId } = req.params;
        const result = await this.pool.query(`
          SELECT ps.*, u.username 
          FROM premium_subscriptions ps
          JOIN users u ON ps.user_id = u.id
          WHERE ps.user_id = $1 AND ps.is_active = TRUE
        `, [userId]);
        
        if (result.rows.length > 0) {
          const subscription = result.rows[0];
          res.json({
            success: true,
            isPremium: true,
            subscription: {
              type: subscription.subscription_type,
              expiresAt: subscription.expires_at,
              features: this.getPremiumFeatures(subscription.subscription_type)
            }
          });
        } else {
          res.json({ success: true, isPremium: false, features: this.getFreeFeatures() });
        }
      } catch (error) {
        logger.error('Error checking premium status', { error: error.message, userId: req.params.userId });
        res.status(500).json({ success: false, error: 'Failed to check premium status' });
      }
    });

    // Purchase premium subscription
    router.post('/purchase-premium', async (req, res) => {
      try {
        const { userId, subscriptionType, paymentToken } = req.body;
        
        // In a real implementation, you'd integrate with Stripe, PayPal, etc.
        // For now, we'll simulate the purchase
        const expiresAt = new Date();
        if (subscriptionType === 'monthly') {
          expiresAt.setMonth(expiresAt.getMonth() + 1);
        } else if (subscriptionType === 'yearly') {
          expiresAt.setFullYear(expiresAt.getFullYear() + 1);
        }

        await this.pool.query(`
          INSERT INTO premium_subscriptions (user_id, subscription_type, expires_at, payment_token)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (user_id) 
          DO UPDATE SET 
            subscription_type = $2,
            expires_at = $3,
            payment_token = $4,
            is_active = TRUE,
            updated_at = NOW()
        `, [userId, subscriptionType, expiresAt, paymentToken]);

        logger.info('Premium subscription purchased', { userId, subscriptionType });
        res.json({ success: true, message: 'Premium subscription activated!' });
      } catch (error) {
        logger.error('Error purchasing premium', { error: error.message });
        res.status(500).json({ success: false, error: 'Failed to process purchase' });
      }
    });

    // Purchase profile customization
    router.post('/purchase-customization', async (req, res) => {
      try {
        const { userId, itemType, itemId, price } = req.body;
        
        // Verify user has sufficient balance or process payment
        const balanceResult = await this.pool.query('SELECT balance FROM user_wallets WHERE user_id = $1', [userId]);
        const balance = balanceResult.rows[0]?.balance || 0;
        
        if (balance < price) {
          return res.status(400).json({ success: false, error: 'Insufficient balance' });
        }

        // Deduct balance and add item to user's inventory
        await this.pool.query('BEGIN');
        
        await this.pool.query(
          'UPDATE user_wallets SET balance = balance - $1 WHERE user_id = $2',
          [price, userId]
        );
        
        await this.pool.query(
          'INSERT INTO user_inventory (user_id, item_type, item_id, purchased_at) VALUES ($1, $2, $3, NOW())',
          [userId, itemType, itemId]
        );
        
        await this.pool.query('COMMIT');
        
        logger.info('Customization item purchased', { userId, itemType, itemId, price });
        res.json({ success: true, message: 'Item purchased successfully!' });
      } catch (error) {
        await this.pool.query('ROLLBACK');
        logger.error('Error purchasing customization', { error: error.message });
        res.status(500).json({ success: false, error: 'Failed to process purchase' });
      }
    });

    // Get marketplace items
    router.get('/marketplace', async (req, res) => {
      try {
        const items = {
          profileArt: [
            { id: 'art_001', name: 'Neon Glow', price: MonetizationConfig.PROFILE_ART_PRICE, preview: '/assets/art/neon-glow.png' },
            { id: 'art_002', name: 'Galaxy Theme', price: MonetizationConfig.PROFILE_ART_PRICE, preview: '/assets/art/galaxy.png' },
            { id: 'art_003', name: 'Minimalist', price: MonetizationConfig.PROFILE_ART_PRICE, preview: '/assets/art/minimal.png' }
          ],
          animations: [
            { id: 'anim_001', name: 'Typing Sparkles', price: MonetizationConfig.CUSTOM_ANIMATION_PRICE, preview: '/assets/anims/sparkles.gif' },
            { id: 'anim_002', name: 'Wave Effect', price: MonetizationConfig.CUSTOM_ANIMATION_PRICE, preview: '/assets/anims/wave.gif' }
          ],
          themes: [
            { id: 'theme_001', name: 'Dark Mode Pro', price: MonetizationConfig.PREMIUM_THEMES_PRICE, preview: '/assets/themes/dark-pro.png' },
            { id: 'theme_002', name: 'Colorful Gradient', price: MonetizationConfig.PREMIUM_THEMES_PRICE, preview: '/assets/themes/gradient.png' }
          ],
          emojiPacks: [
            { id: 'emoji_001', name: 'Cute Animals', price: MonetizationConfig.CUSTOM_EMOJI_PACK_PRICE, preview: '/assets/emoji/animals.png' },
            { id: 'emoji_002', name: 'Tech Icons', price: MonetizationConfig.CUSTOM_EMOJI_PACK_PRICE, preview: '/assets/emoji/tech.png' }
          ]
        };
        
        res.json({ success: true, items });
      } catch (error) {
        logger.error('Error fetching marketplace', { error: error.message });
        res.status(500).json({ success: false, error: 'Failed to fetch marketplace' });
      }
    });

    // Ad revenue tracking
    router.post('/ad-impression', async (req, res) => {
      try {
        const { userId, adId, revenue } = req.body;
        
        await this.pool.query(`
          INSERT INTO ad_impressions (user_id, ad_id, revenue, created_at)
          VALUES ($1, $2, $3, NOW())
        `, [userId, adId, revenue]);
        
        // Add to user's balance (their share of ad revenue)
        const userShare = revenue * MonetizationConfig.AD_REVENUE_SHARE;
        await this.pool.query(`
          INSERT INTO user_wallets (user_id, balance) 
          VALUES ($1, $2)
          ON CONFLICT (user_id) 
          DO UPDATE SET balance = user_wallets.balance + $2
        `, [userId, userShare]);
        
        res.json({ success: true });
      } catch (error) {
        logger.error('Error tracking ad impression', { error: error.message });
        res.status(500).json({ success: false, error: 'Failed to track ad' });
      }
    });

    return router;
  }

  getPremiumFeatures(subscriptionType) {
    const features = {
      adFree: true,
      customThemes: true,
      messageReactions: true,
      prioritySupport: true,
      extendedMessageHistory: true,
      customFonts: true
    };

    if (subscriptionType === 'yearly') {
      features.exclusiveEmojis = true;
      features.earlyAccess = true;
      features.premiumAnimations = true;
    }

    return features;
  }

  getFreeFeatures() {
    return {
      basicChat: true,
      standardThemes: true,
      basicEmojis: true,
      limitedMessageHistory: true
    };
  }

  // Database setup for monetization tables
  async createMonetizationTables() {
    try {
      // Premium subscriptions table
      await this.pool.query(`
        CREATE TABLE IF NOT EXISTS premium_subscriptions (
          id SERIAL PRIMARY KEY,
          user_id INTEGER UNIQUE NOT NULL,
          subscription_type VARCHAR(20) NOT NULL,
          expires_at TIMESTAMP NOT NULL,
          payment_token VARCHAR(255),
          is_active BOOLEAN DEFAULT TRUE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // User inventory for purchased items
      await this.pool.query(`
        CREATE TABLE IF NOT EXISTS user_inventory (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL,
          item_type VARCHAR(50) NOT NULL,
          item_id VARCHAR(100) NOT NULL,
          purchased_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          is_active BOOLEAN DEFAULT TRUE
        )
      `);

      // User wallets for ad revenue and purchases
      await this.pool.query(`
        CREATE TABLE IF NOT EXISTS user_wallets (
          id SERIAL PRIMARY KEY,
          user_id INTEGER UNIQUE NOT NULL,
          balance DECIMAL(10,2) DEFAULT 0.00,
          total_earned DECIMAL(10,2) DEFAULT 0.00,
          total_spent DECIMAL(10,2) DEFAULT 0.00,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Ad impressions tracking
      await this.pool.query(`
        CREATE TABLE IF NOT EXISTS ad_impressions (
          id SERIAL PRIMARY KEY,
          user_id INTEGER,
          ad_id VARCHAR(100) NOT NULL,
          revenue DECIMAL(8,4) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);

      logger.info('Monetization tables created successfully');
    } catch (error) {
      logger.error('Failed to create monetization tables', { error: error.message });
      throw error;
    }
  }

  getRoutes() {
    return router;
  }
}

module.exports = { MonetizationSystem, MonetizationConfig };
