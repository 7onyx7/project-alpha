/**
 * Clear IP Ban Script
 * 
 * This script clears the IP ban for localhost testing
 */

const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
});

async function clearIPBan() {
  try {
    // Clear IP bans from database
    const result = await pool.query('DELETE FROM ip_bans WHERE ip = $1', ['::1']);
    console.log('✅ Cleared IP ban for ::1 (localhost)');
    
    const result2 = await pool.query('DELETE FROM ip_bans WHERE ip = $1', ['127.0.0.1']);
    console.log('✅ Cleared IP ban for 127.0.0.1 (localhost)');
    
    // Clear violations
    const result3 = await pool.query('DELETE FROM ip_violations WHERE ip = $1', ['::1']);
    console.log('✅ Cleared IP violations for ::1 (localhost)');
    
    const result4 = await pool.query('DELETE FROM ip_violations WHERE ip = $1', ['127.0.0.1']);
    console.log('✅ Cleared IP violations for 127.0.0.1 (localhost)');
    
    console.log('🎉 All IP bans and violations cleared for localhost');
    
  } catch (error) {
    console.error('❌ Error clearing IP ban:', error);
  } finally {
    await pool.end();
  }
}

clearIPBan();
