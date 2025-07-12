#!/usr/bin/env node

/**
 * Password Reset Testing Script
 * 
 * This script tests the password reset functionality of the Bantrhaus application.
 * It simulates a user requesting a password reset, retrieving the token,
 * and setting a new password.
 */

require('dotenv').config();
const fetch = require('node-fetch');
const { Pool } = require('pg');
const readline = require('readline');

// Create readline interface for user input
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// Database connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// Base URL for API calls
const BASE_URL = process.env.NODE_ENV === 'production' 
  ? 'https://your-production-url.com' 
  : 'http://localhost:3000';

async function main() {
  try {
    console.log('🔑 BANTRHAUS PASSWORD RESET TESTER 🔑');
    console.log('======================================');
    console.log('This script will test the password reset flow.\n');
    
    // Get user email
    const email = await askQuestion('Enter email address to test: ');
    
    console.log('\n1️⃣ Testing password reset request...');
    
    // Step 1: Request password reset
    const resetResponse = await fetch(`${BASE_URL}/api/auth/forgot-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    
    const resetResult = await resetResponse.json();
    console.log('Response:', resetResult);
    
    if (!resetResult.success) {
      console.error('❌ Password reset request failed');
      process.exit(1);
    }
    
    console.log('✅ Password reset request successful');
    
    // Step 2: Retrieve the token from the database (this would normally be sent via email)
    console.log('\n2️⃣ Retrieving reset token from database...');
    
    const tokenResult = await pool.query(
      'SELECT u.username, prt.token, prt.expires_at FROM password_reset_tokens prt ' +
      'JOIN users u ON u.id = prt.user_id ' +
      'WHERE u.email = $1 AND prt.used = FALSE AND prt.expires_at > NOW() ' +
      'ORDER BY prt.created_at DESC LIMIT 1',
      [email]
    );
    
    if (tokenResult.rows.length === 0) {
      console.error('❌ No valid reset token found for this email');
      process.exit(1);
    }
    
    const { username, token, expires_at } = tokenResult.rows[0];
    console.log(`✅ Found reset token for user: ${username}`);
    console.log(`Token expires at: ${expires_at}`);
    console.log(`Reset URL: ${BASE_URL}/reset-password?token=${token}`);
    
    // Step 3: Use the token to reset the password
    console.log('\n3️⃣ Testing password reset completion...');
    
    const newPassword = await askQuestion('Enter new password: ');
    
    const completeResponse = await fetch(`${BASE_URL}/reset-password-complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, newPassword })
    });
    
    const completeResult = await completeResponse.json();
    console.log('Response:', completeResult);
    
    if (!completeResult.success) {
      console.error('❌ Password reset completion failed');
      process.exit(1);
    }
    
    console.log('✅ Password reset completed successfully');
    
    // Step 4: Verify login with new password
    console.log('\n4️⃣ Verifying login with new password...');
    
    const loginResponse = await fetch(`${BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password: newPassword })
    });
    
    const loginResult = await loginResponse.json();
    
    if (loginResponse.ok && loginResult.success) {
      console.log('✅ Login successful with new password');
      console.log('\n🎉 Password reset flow tested successfully! 🎉');
    } else {
      console.error('❌ Login failed with new password');
      console.error('Error:', loginResult.message);
    }
    
  } catch (error) {
    console.error('Error during testing:', error);
  } finally {
    rl.close();
    await pool.end();
  }
}

// Helper function to ask questions
function askQuestion(question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer);
    });
  });
}

// Run the main function
main().catch(console.error);
