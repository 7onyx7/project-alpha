# Password Reset Functionality

## Overview

The password reset functionality in Bantrhaus allows users to reset their passwords if they've forgotten them. This document outlines the technical details of how this feature works.

## Flow

1. User clicks "Forgot Password" on the login page
2. A modal appears asking for their email address
3. System sends a password reset token (in production, this would be emailed)
4. User clicks the reset link and is taken to the reset password page
5. User enters a new password and confirms it
6. Password is updated if the token is valid

## Technical Implementation

### Database Structure

The password reset functionality uses the `password_reset_tokens` table:

```sql
CREATE TABLE password_reset_tokens (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  token TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Server-Side Endpoints

#### 1. Request Password Reset

**Endpoint:** `POST /api/auth/forgot-password`

**Purpose:** Generates a password reset token and stores it in the database

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "message": "If this email exists in our system, a password reset link has been sent."
}
```

**Security Measures:**
- Rate limiting to prevent brute force attacks
- Generic response message regardless of whether the email exists (prevents email enumeration)
- Tokens expire after 1 hour
- All attempts are logged in the audit_log table

#### 2. Reset Password Page

**Endpoint:** `GET /reset-password`

**Purpose:** Serves the password reset HTML page with the token as a query parameter

#### 3. Complete Password Reset

**Endpoint:** `POST /reset-password-complete`

**Purpose:** Validates the token and updates the user's password

**Request Body:**
```json
{
  "token": "jwt-token-here",
  "newPassword": "new-password-here"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Your password has been reset successfully"
}
```

**Security Measures:**
- Tokens can only be used once
- Password complexity validation
- Token validation including expiration check
- All password resets are logged in the audit_log table

### Client-Side Implementation

The client-side implementation consists of:

1. A "Forgot Password" link on the login page
2. A modal form to enter the email address
3. A dedicated reset password page that accepts the token via query parameter
4. JavaScript to handle form submission and validation

## Security Considerations

- Tokens are JWT-based with a short expiration time
- Password complexity is enforced
- Rate limiting is applied to prevent abuse
- All actions are logged for audit purposes
- Tokens are single-use only
- Generic error messages to prevent user enumeration

## Testing

To test the password reset functionality:

1. Click "Forgot Password" on the login page
2. Enter a valid email address
3. In development mode, the token will be logged to the console
4. Use the token in the URL: `/reset-password?token=your-token-here`
5. Enter a new password and submit
6. Verify you can log in with the new password

## Future Enhancements

- Email delivery system for sending reset links
- Enhanced rate limiting per user/IP
- CAPTCHA integration for password reset requests
- Account lockout after multiple failed reset attempts
- Password history to prevent reuse of old passwords
