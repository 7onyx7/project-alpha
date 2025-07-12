/**
 * Login Test Script
 * 
 * This script tests the login functionality directly by attempting to:
 * 1. Authenticate with the admin credentials
 * 2. Verify the bcrypt hash format in the database
 * 3. Test password comparison directly
 */

require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Create a database connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
});

// Test credentials (modify these to test with your actual username/password)
const TEST_USERNAME = 'admin';
const TEST_PASSWORD = 'admin123!';

/**
 * Test the login process step by step
 */
async function testLogin() {
  try {
    console.log('🔍 Login Function Test');
    console.log('=====================');
    console.log(`Testing login with username: ${TEST_USERNAME}`);
    
    // Step 1: Look up the user
    console.log('\n👤 Step 1: Finding user in database');
    const userResult = await pool.query(
      "SELECT * FROM users WHERE username = $1", 
      [TEST_USERNAME]
    );
    
    if (userResult.rows.length === 0) {
      console.log(`❌ User '${TEST_USERNAME}' not found in the database`);
      return;
    }
    
    const user = userResult.rows[0];
    console.log('✅ User found in database:');
    console.log(`   ID: ${user.id}`);
    console.log(`   Username: ${user.username}`);
    console.log(`   Role: ${user.role || 'not set'}`);
    
    // Step 2: Check the password hash format
    console.log('\n🔒 Step 2: Checking password hash format');
    
    const storedHash = user.password;
    console.log(`   Stored hash: ${storedHash ? storedHash.substring(0, 10) + '...' : 'none'}`);
    
    if (!storedHash) {
      console.log('❌ No password hash found for this user');
      return;
    }
    
    if (!storedHash.startsWith('$2')) {
      console.log('❌ Password hash does not appear to be a valid bcrypt hash');
      console.log('   Bcrypt hashes should start with "$2a$", "$2b$", or "$2y$"');
      return;
    }
    
    console.log('✅ Password hash appears to be in the correct bcrypt format');
    
    // Step 3: Test password comparison
    console.log('\n🔑 Step 3: Testing password comparison');
    console.log(`   Comparing '${TEST_PASSWORD}' with stored hash`);
    
    try {
      const isMatch = await bcrypt.compare(TEST_PASSWORD, storedHash);
      
      if (isMatch) {
        console.log('✅ Password comparison successful!');
        
        // Generate a JWT like the server would
        const token = jwt.sign(
          { id: user.id, username: user.username },
          process.env.JWT_SECRET,
          { expiresIn: "1h" }
        );
        
        console.log('🎟️  JWT token generated successfully');
      } else {
        console.log('❌ Password does not match');
        console.log('   The password you provided is incorrect for this user');
        
        // Provide test command to update password
        console.log('\n💡 To reset the admin password to "admin123!", run:');
        const updateCmd = `node -e "const bcrypt = require('bcrypt'); const { Pool } = require('pg'); require('dotenv').config(); async function resetPassword() { const hash = await bcrypt.hash('admin123!', 10); const pool = new Pool({ user: process.env.DB_USER, host: process.env.DB_HOST, database: process.env.DB_NAME, password: process.env.DB_PASSWORD, port: process.env.DB_PORT }); await pool.query('UPDATE users SET password = $1 WHERE username = $2', [hash, 'admin']); console.log('Password updated successfully!'); await pool.end(); } resetPassword().catch(console.error);"`;
        console.log(updateCmd);
      }
    } catch (error) {
      console.log('❌ Error during password comparison:', error.message);
      if (error.message.includes('Invalid salt version')) {
        console.log('   The stored password hash is in an invalid format');
      }
    }
    
    // Step 4: Check for missing tables that might cause other issues
    console.log('\n📊 Step 4: Checking for banned_ips table');
    
    const tableExists = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'banned_ips'
      );
    `);
    
    if (!tableExists.rows[0].exists) {
      console.log('⚠️ The banned_ips table is missing');
      console.log('   This might cause errors in the security middleware');
      console.log('   You should run setup-database.js to create all required tables');
    } else {
      console.log('✅ banned_ips table exists');
    }
    
    console.log('\n📝 Summary:');
    console.log('1. If password comparison failed, update the password using the command above');
    console.log('2. If tables are missing, run the setup-database.js script');
    console.log('3. Make sure DB_SSL is set to false for local development');
    
  } catch (error) {
    console.error('❌ Error testing login:', error);
  } finally {
    await pool.end();
  }
}

// Run the test
testLogin().catch(console.error);
