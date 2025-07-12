/**
 * Email Service for Bantrhaus
 * 
 * This module provides functionality for sending emails through SMTP.
 */

const nodemailer = require('nodemailer');
const logger = require('./logger');

// Environment variables needed:
// EMAIL_HOST - SMTP host (e.g., smtp.gmail.com)
// EMAIL_PORT - SMTP port (e.g., 587)
// EMAIL_USER - Email username/address
// EMAIL_PASS - Email password or app password
// EMAIL_FROM - Sender email address (usually same as EMAIL_USER)

/**
 * Initialize email transport based on environment
 */
const getTransport = () => {
  // In development, use a test account
  if (process.env.NODE_ENV !== 'production' && !process.env.EMAIL_HOST) {
    logger.info('Using ethereal email testing account for development');
    
    // Create a test account at ethereal.email
    return new Promise((resolve, reject) => {
      nodemailer.createTestAccount()
        .then(testAccount => {
          const transport = nodemailer.createTransport({
            host: 'smtp.ethereal.email',
            port: 587,
            secure: false,
            auth: {
              user: testAccount.user,
              pass: testAccount.pass,
            },
          });
          
          logger.info(`Ethereal Email: ${testAccount.user}`);
          resolve(transport);
        })
        .catch(error => {
          logger.error('Failed to create test email account', { error });
          reject(error);
        });
    });
  }
  
  // In production, use configured SMTP service
  const transport = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT || '587', 10),
    secure: process.env.EMAIL_PORT === '465', // true for 465, false for other ports
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
  
  return Promise.resolve(transport);
};

/**
 * Send an email
 * 
 * @param {Object} options - Email options
 * @param {string} options.to - Recipient email
 * @param {string} options.subject - Email subject
 * @param {string} options.text - Plain text email body
 * @param {string} options.html - HTML email body (optional)
 * @returns {Promise<Object>} Email send result
 */
const sendEmail = async (options) => {
  try {
    const transport = await getTransport();
    
    const mailOptions = {
      from: process.env.EMAIL_FROM || '"Bantrhaus" <no-reply@bantrhaus.com>',
      to: options.to,
      subject: options.subject,
      text: options.text,
    };
    
    if (options.html) {
      mailOptions.html = options.html;
    }
    
    const info = await transport.sendMail(mailOptions);
    
      // If using Ethereal in development, log preview URL
    if (info.messageId && info.preview) {
      logger.info(`Email preview: ${info.preview}`);
      
      // Also log to console for easier access
      if (process.env.NODE_ENV !== 'production') {
        console.log('\n=============== EMAIL PREVIEW ===============');
        console.log(`View email at: ${info.preview}`);
        console.log('=============================================\n');
      }
    }
    
    return info;
  } catch (error) {
    logger.error('Error sending email', { error: error.message, to: options.to });
    throw error;
  }
};

/**
 * Send a password reset email
 * 
 * @param {Object} options - Email options
 * @param {string} options.to - Recipient email
 * @param {string} options.username - User's username
 * @param {string} options.resetLink - Password reset link
 * @returns {Promise<Object>} Email send result
 */
const sendPasswordResetEmail = async (options) => {
  const subject = 'Reset Your Bantrhaus Password';
  
  const text = `
Hello ${options.username},

You recently requested to reset your password for your Bantrhaus account. 
Click the link below to reset it:

${options.resetLink}

If you did not request a password reset, please ignore this email or contact support if you have concerns.

This link will expire in 1 hour.

Thanks,
The Bantrhaus Team
  `.trim();
  
  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {
      font-family: Arial, sans-serif;
      line-height: 1.6;
      color: #333;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
      border: 1px solid #ddd;
      border-radius: 5px;
    }
    .button {
      display: inline-block;
      padding: 10px 20px;
      background-color: #4A90E2;
      color: white;
      text-decoration: none;
      border-radius: 5px;
      margin: 20px 0;
    }
    .footer {
      margin-top: 30px;
      font-size: 12px;
      color: #999;
    }
  </style>
</head>
<body>
  <div class="container">
    <h2>Reset Your Bantrhaus Password</h2>
    <p>Hello ${options.username},</p>
    <p>You recently requested to reset your password for your Bantrhaus account. Click the button below to reset it:</p>
    
    <p><a href="${options.resetLink}" class="button">Reset Your Password</a></p>
    
    <p>If the button doesn't work, copy and paste this link into your browser:</p>
    <p><a href="${options.resetLink}">${options.resetLink}</a></p>
    
    <p>If you did not request a password reset, please ignore this email or contact support if you have concerns.</p>
    
    <p>This link will expire in 1 hour.</p>
    
    <p>Thanks,<br>The Bantrhaus Team</p>
    
    <div class="footer">
      <p>This email was sent to ${options.to}. If you'd prefer not to receive these types of emails, you can <a href="#">unsubscribe</a>.</p>
    </div>
  </div>
</body>
</html>
  `.trim();
  
  return sendEmail({
    to: options.to,
    subject,
    text,
    html,
  });
};

module.exports = {
  sendEmail,
  sendPasswordResetEmail,
};
