#!/usr/bin/env node

/**
 * Test Email Service for Bantrhaus
 * 
 * This script tests the email functionality of the application.
 * It sends a test email to verify the email service is working correctly.
 */

require('dotenv').config();
const emailService = require('./email-service');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

async function testEmail() {
  try {
    console.log('🔧 BANTRHAUS EMAIL SERVICE TEST 🔧');
    console.log('=================================');
    
    // Ask for email address
    const email = await askQuestion('Enter recipient email address: ');
    
    console.log('\nSending test email...');
    
    // Send a test email
    const result = await emailService.sendEmail({
      to: email,
      subject: 'Bantrhaus Email Test',
      text: 'This is a test email from Bantrhaus to verify email functionality.',
      html: '<h1>Bantrhaus Email Test</h1><p>This is a test email from Bantrhaus to verify email functionality.</p>'
    });
    
    if (result.messageId) {
      console.log('✅ Email sent successfully!');
      console.log(`Message ID: ${result.messageId}`);
      
      // If preview URL is available (using Ethereal)
      if (result.preview) {
        console.log(`\n📧 View the email at: ${result.preview}`);
      }
    } else {
      console.log('❌ Email delivery failed without error.');
    }
  } catch (error) {
    console.error('❌ Error sending email:', error);
    console.log('\nCheck your .env file for proper email configuration:');
    console.log('- EMAIL_HOST: SMTP server hostname');
    console.log('- EMAIL_PORT: SMTP server port (usually 587 or 465)');
    console.log('- EMAIL_USER: Your email username/address');
    console.log('- EMAIL_PASS: Your email password or app password');
    console.log('- EMAIL_FROM: Sender email address');
    
    if (!process.env.EMAIL_HOST) {
      console.log('\nNote: In development mode without email config, Ethereal test accounts will be used.');
    }
  } finally {
    rl.close();
  }
}

async function testPasswordReset() {
  try {
    console.log('🔑 BANTRHAUS PASSWORD RESET EMAIL TEST 🔑');
    console.log('=========================================');
    
    // Ask for email address and username
    const email = await askQuestion('Enter recipient email address: ');
    const username = await askQuestion('Enter username: ');
    
    console.log('\nSending password reset email...');
    
    // Create a test reset link
    const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
    const resetLink = `${baseUrl}/reset-password?token=test-token-${Date.now()}`;
    
    // Send a password reset email
    const result = await emailService.sendPasswordResetEmail({
      to: email,
      username: username,
      resetLink: resetLink
    });
    
    if (result.messageId) {
      console.log('✅ Password reset email sent successfully!');
      console.log(`Message ID: ${result.messageId}`);
      
      // If preview URL is available (using Ethereal)
      if (result.preview) {
        console.log(`\n📧 View the email at: ${result.preview}`);
      }
    } else {
      console.log('❌ Email delivery failed without error.');
    }
  } catch (error) {
    console.error('❌ Error sending password reset email:', error);
    console.log('\nCheck your .env file for proper email configuration:');
    console.log('- EMAIL_HOST: SMTP server hostname');
    console.log('- EMAIL_PORT: SMTP server port (usually 587 or 465)');
    console.log('- EMAIL_USER: Your email username/address');
    console.log('- EMAIL_PASS: Your email password or app password');
    console.log('- EMAIL_FROM: Sender email address');
    
    if (!process.env.EMAIL_HOST) {
      console.log('\nNote: In development mode without email config, Ethereal test accounts will be used.');
    }
  } finally {
    rl.close();
  }
}

function askQuestion(question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer);
    });
  });
}

async function main() {
  console.log('Choose an email test:');
  console.log('1. Basic Email Test');
  console.log('2. Password Reset Email Test');
  
  const choice = await askQuestion('Enter your choice (1 or 2): ');
  
  if (choice === '1') {
    await testEmail();
  } else if (choice === '2') {
    await testPasswordReset();
  } else {
    console.log('Invalid choice. Exiting...');
    rl.close();
  }
}

main().catch(console.error);
