@echo off
echo === Bantrhaus Database Setup ===
echo.
echo This script will help you set up the required database tables.
echo Make sure your PostgreSQL database is running and configured in your .env file.
echo.

REM Check if Node.js is available
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Node.js is not installed
    exit /b 1
)

REM Check if .env file exists
if not exist ".env" (
    echo Error: .env file not found
    echo Please create a .env file with your database configuration
    exit /b 1
)

echo Creating database tables...

REM Create tables
node -e "const { Pool } = require('pg'); const { createSecurityTables } = require('./security'); require('dotenv').config(); const pool = new Pool({ host: process.env.DB_HOST, user: process.env.DB_USER, database: process.env.DB_NAME, password: process.env.DB_PASSWORD, port: process.env.DB_PORT, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false }); async function setupDatabase() { try { console.log('Creating security tables...'); await createSecurityTables(pool); console.log('Creating users table...'); await pool.query('CREATE TABLE IF NOT EXISTS users ( id SERIAL PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL, email VARCHAR(255) UNIQUE, first_name VARCHAR(255), last_name VARCHAR(255), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, role VARCHAR(50) DEFAULT \'user\' )'); console.log('Creating messages table...'); await pool.query('CREATE TABLE IF NOT EXISTS messages ( id SERIAL PRIMARY KEY, room VARCHAR(100) NOT NULL, username VARCHAR(50) NOT NULL, message TEXT NOT NULL, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, edited_at TIMESTAMP, is_deleted BOOLEAN DEFAULT FALSE )'); console.log('Creating activity logs table...'); await pool.query('CREATE TABLE IF NOT EXISTS activity_logs ( id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), action VARCHAR(100) NOT NULL, details JSONB, ip_address VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP )'); console.log('Creating profiles table...'); await pool.query('CREATE TABLE IF NOT EXISTS profiles ( id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), bio TEXT, profile_picture VARCHAR(255) )'); console.log('Creating rooms table...'); await pool.query('CREATE TABLE IF NOT EXISTS rooms ( id SERIAL PRIMARY KEY, name VARCHAR(100) UNIQUE NOT NULL, description TEXT, is_private BOOLEAN DEFAULT FALSE, owner_id INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, max_users INTEGER DEFAULT 100 )'); console.log('Creating password reset tokens table...'); await pool.query('CREATE TABLE IF NOT EXISTS password_reset_tokens ( id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), token TEXT NOT NULL, expires_at TIMESTAMP NOT NULL, used BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP )'); console.log('✅ Database setup complete!'); console.log(''); console.log('Next steps:'); console.log('1. Review the security settings in security.js'); console.log('2. Configure external content moderation service'); console.log('3. Set up VPN detection service (optional)'); console.log('4. Configure payment processor for monetization'); console.log('5. Run: npm start'); } catch (error) { console.error('❌ Database setup failed:', error.message); process.exit(1); } finally { await pool.end(); } } setupDatabase();"

echo.
echo === Setup Instructions ===
echo.
echo IMPORTANT SECURITY NOTES:
echo 1. IP Banning: Automatic IP banning is enabled for violations
echo 2. VPN Blocking: Currently basic - integrate with a VPN detection service
echo 3. Content Moderation: Configure external service in security.js
echo 4. Database: Tables are NOT auto-created - run this script manually
echo.
echo MONETIZATION SETUP:
echo 1. Configure payment processor (Stripe, PayPal, etc.)
echo 2. Set up ad serving platform
echo 3. Customize premium features in simple-monetization.js
echo.
echo EXTERNAL SERVICES TO CONFIGURE:
echo 1. Content Moderation: Perspective API, Azure Content Moderator
echo 2. VPN Detection: IPQualityScore, GetIPIntel, ProxyCheck.io
echo 3. Payment Processing: Stripe, PayPal, Square
echo 4. Ad Network: Google AdSense, Media.net
echo.
pause
