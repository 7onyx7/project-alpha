#!/usr/bin/env node

/**
 * Email Service Test Script
 * 
 * This script tests the email service by sending a test email.
 * It's useful for verifying that your email configuration is working correctly.
 */

require('dotenv').config();
const emailService = require('../email-service');

// Create a test reset link
const baseUrl = process.env.NODE_ENV === 'production' 
  ? process.env.BASE_URL || 'https://bantrhaus.com' 
  : 'http://localhost:3000';
  
const testToken = 'test-token-' + Date.now();
const resetLink = `${baseUrl}/reset-password?token=${testToken}`;

async function testEmailService() {
  try {
    console.log('🔧 BANTRHAUS EMAIL SERVICE TESTER 🔧');
    console.log('=====================================');
    
    // Check if email configuration exists
    if (process.env.NODE_ENV !== 'production' && !process.env.EMAIL_HOST) {
      console.log('ℹ️ No email configuration found in .env file');
      console.log('ℹ️ Using Ethereal Email for testing');
    } else {
      console.log('ℹ️ Using configured email service:');
      console.log(`   Host: ${process.env.EMAIL_HOST}`);
      console.log(`   Port: ${process.env.EMAIL_PORT}`);
      console.log(`   User: ${process.env.EMAIL_USER}`);
    }
    
    console.log('\n📧 Sending test password reset email...');
    
    const result = await emailService.sendPasswordResetEmail({
      to: 'test@example.com',
      username: 'TestUser',
      resetLink: resetLink
    });
    
    console.log('✅ Test email sent!');
    
    if (result.messageId) {
      console.log(`📨 Message ID: ${result.messageId}`);
    }
    
    if (result.preview) {
      console.log(`🔗 Preview URL: ${result.preview}`);
      console.log('   (Open this URL to view the test email)');
    }
    
    console.log('\n✅ Email service is working correctly!');
    
  } catch (error) {
    console.error('❌ Error testing email service:', error);
    process.exit(1);
  }
}

testEmailService();
