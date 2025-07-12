#!/usr/bin/env node

// Database setup script for Bantrhaus
require('dotenv').config();
const { Pool } = require('pg');
const { createSecurityTables } = require('./security');
const logger = require('./logger');

// Connect to the database
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

async function setupDatabase() {
  try {
    logger.info('Starting database setup...');

    // Create security tables
    await createSecurityTables(pool);
    logger.info('Security tables created successfully');
    
    // Create monetization tables if they don't exist
    if (require.resolve('./monetization')) {
      try {
        const { MonetizationSystem } = require('./monetization');
        await MonetizationSystem.createTables(pool);
        logger.info('Monetization tables created successfully');
      } catch (error) {
        logger.error('Failed to create monetization tables', { error: error.message });
      }
    }

    // Check if audit_log table exists
    const result = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'audit_log'
      );
    `);

    if (!result.rows[0].exists) {
      logger.info('Creating audit_log table...');
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
      logger.info('audit_log table created successfully');
    } else {
      logger.info('audit_log table already exists');
    }

    // Verify all required tables exist
    const requiredTables = [
      'users', 
      'messages', 
      'profiles', 
      'activity_logs', 
      'password_reset_tokens', 
      'reports', 
      'banned_users', 
      'user_sessions', 
      'audit_log'
    ];
    
    for (const table of requiredTables) {
      const tableExists = await pool.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_schema = 'public' 
          AND table_name = $1
        );
      `, [table]);
      
      if (!tableExists.rows[0].exists) {
        logger.warn(`Table ${table} does not exist`);
        
        if (table === 'users') {
          logger.info('Creating users table...');
          await pool.query(`
            CREATE TABLE users (
              id SERIAL PRIMARY KEY,
              username VARCHAR(255) NOT NULL UNIQUE,
              password VARCHAR(255) NOT NULL,
              email VARCHAR(255) UNIQUE,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              role VARCHAR(50) DEFAULT 'user',
              first_name VARCHAR(255),
              last_name VARCHAR(255)
            );
          `);
          logger.info('users table created successfully');
        }
        
        if (table === 'messages') {
          logger.info('Creating messages table...');
          await pool.query(`
            CREATE TABLE messages (
              id SERIAL PRIMARY KEY,
              room VARCHAR(255) NOT NULL,
              username VARCHAR(255) NOT NULL,
              message TEXT NOT NULL,
              timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room);
            CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
          `);
          logger.info('messages table created successfully');
        }
        
        if (table === 'profiles') {
          logger.info('Creating profiles table...');
          await pool.query(`
            CREATE TABLE profiles (
              id SERIAL PRIMARY KEY,
              user_id INTEGER REFERENCES users(id),
              bio TEXT,
              profile_picture VARCHAR(255)
            );
          `);
          logger.info('profiles table created successfully');
        }
        
        if (table === 'activity_logs') {
          logger.info('Creating activity_logs table...');
          await pool.query(`
            CREATE TABLE activity_logs (
              id SERIAL PRIMARY KEY,
              user_id INTEGER REFERENCES users(id),
              activity VARCHAR(255),
              timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
          `);
          logger.info('activity_logs table created successfully');
        }
        
        if (table === 'password_reset_tokens') {
          logger.info('Creating password_reset_tokens table...');
          await pool.query(`
            CREATE TABLE password_reset_tokens (
              id SERIAL PRIMARY KEY,
              user_id INTEGER REFERENCES users(id),
              token TEXT NOT NULL,
              expires_at TIMESTAMP NOT NULL,
              used BOOLEAN DEFAULT FALSE,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
          `);
          logger.info('password_reset_tokens table created successfully');
        }
      } else {
        logger.info(`Table ${table} exists`);
      }
    }

    logger.info('Database setup completed successfully');
  } catch (error) {
    logger.error('Error setting up database', { error: error.message });
  } finally {
    await pool.end();
  }
}

setupDatabase().catch(err => {
  logger.error('Unhandled error in setup script', { error: err.message });
  process.exit(1);
});
