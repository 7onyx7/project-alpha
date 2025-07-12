/**
 * Database Check Script
 * 
 * This script verifies database connection and checks critical tables and users.
 * Run this to diagnose login issues related to database configuration.
 */

require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const logger = console;

// Create a connection pool
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 5000,
});

async function checkDatabase() {
  try {
    console.log('🔍 Database Connection Check');
    console.log('============================');
    
    // Test the connection
    const connectionResult = await pool.query('SELECT NOW()');
    if (connectionResult.rows && connectionResult.rows.length > 0) {
      console.log('✅ Database connection successful');
      console.log(`   Connected to: ${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`);
    }
    
    // Check if users table exists
    try {
      console.log('\n🔍 Checking Users Table');
      const tableCheck = await pool.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_schema = 'public' 
          AND table_name = 'users'
        );
      `);
      
      if (tableCheck.rows[0].exists) {
        console.log('✅ Users table exists');
        
        // Check users table schema
        const schemaCheck = await pool.query(`
          SELECT column_name, data_type 
          FROM information_schema.columns 
          WHERE table_name = 'users'
          ORDER BY ordinal_position;
        `);
        
        console.log('   Schema:');
        schemaCheck.rows.forEach(column => {
          console.log(`   - ${column.column_name} (${column.data_type})`);
        });
        
        // Check if we have the password column
        const hasPasswordColumn = schemaCheck.rows.some(col => col.column_name === 'password');
        if (hasPasswordColumn) {
          console.log('✅ Password column found in users table');
        } else {
          console.log('❌ Password column missing from users table');
          console.log('   This will prevent logins from working properly');
        }
        
        // Check if we have the role column for admin checks
        const hasRoleColumn = schemaCheck.rows.some(col => col.column_name === 'role');
        if (hasRoleColumn) {
          console.log('✅ Role column found in users table');
        } else {
          console.log('⚠️ Role column not found - admin features may not work');
        }
      } else {
        console.log('❌ Users table does not exist!');
        console.log('   Run setup-database.js to create the required tables');
      }
    } catch (error) {
      console.log('❌ Error checking users table:', error.message);
    }
    
    // Check for admin user
    try {
      console.log('\n🔍 Checking Admin User');
      const adminCheck = await pool.query(`
        SELECT id, username, email, role 
        FROM users 
        WHERE username = 'admin' OR role = 'admin'
        LIMIT 1;
      `);
      
      if (adminCheck.rows.length > 0) {
        const admin = adminCheck.rows[0];
        console.log('✅ Admin user found:');
        console.log(`   Username: ${admin.username}`);
        console.log(`   Email: ${admin.email}`);
        console.log(`   Role: ${admin.role || 'N/A'}`);
      } else {
        console.log('❌ No admin user found');
        console.log('   You may need to run setup-database.js or initialize the admin user');
      }
    } catch (error) {
      console.log('❌ Error checking admin user:', error.message);
    }
    
    // Check for any users
    try {
      console.log('\n🔍 Checking User Accounts');
      const userCount = await pool.query('SELECT COUNT(*) FROM users;');
      
      if (userCount.rows[0].count > 0) {
        console.log(`✅ Found ${userCount.rows[0].count} user accounts`);
        
        // List a few users for verification
        const sampleUsers = await pool.query(`
          SELECT id, username, email, role, created_at
          FROM users
          ORDER BY created_at DESC
          LIMIT 5;
        `);
        
        if (sampleUsers.rows.length > 0) {
          console.log('   Recent users:');
          sampleUsers.rows.forEach(user => {
            console.log(`   - ${user.username} (${user.email || 'no email'}) | Role: ${user.role || 'regular'}`);
          });
        }
      } else {
        console.log('❌ No user accounts found in the database');
      }
    } catch (error) {
      console.log('❌ Error checking user accounts:', error.message);
    }
    
    // Check for other required tables
    try {
      console.log('\n🔍 Checking Other Required Tables');
      const tablesCheck = await pool.query(`
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_name IN ('messages', 'password_reset_tokens', 'audit_log', 'banned_ips');
      `);
      
      const requiredTables = ['messages', 'password_reset_tokens', 'audit_log', 'banned_ips'];
      const foundTables = tablesCheck.rows.map(row => row.table_name);
      
      requiredTables.forEach(table => {
        if (foundTables.includes(table)) {
          console.log(`✅ Table '${table}' exists`);
        } else {
          console.log(`❌ Missing table: '${table}'`);
        }
      });
    } catch (error) {
      console.log('❌ Error checking required tables:', error.message);
    }
    
    console.log('\n📝 Summary of Findings:');
    console.log('1. Ensure all required tables exist (run setup-database.js if needed)');
    console.log('2. Verify the "users" table has the required columns (username, password, role)');
    console.log('3. Check that user passwords are stored properly as bcrypt hashes');
    console.log('4. If you changed the admin password, ensure it was updated correctly');
    
  } catch (error) {
    console.error('❌ Database check failed:', error);
    console.error('   Check your database connection parameters in .env');
  } finally {
    // Close the pool
    await pool.end();
  }
}

// Run the check
checkDatabase().catch(console.error);
