# Bantrhaus Project - TODO List

*Last Updated: July 11, 2025*

## Password Reset Functionality
- [x] Debug error occurring during password reset process
- [x] Check token generation and handling in the flow
- [x] Verify password reset endpoints functionality
- [x] Add email sending for password reset links
- [x] Implement password visibility toggle
- [x] Add real-time password validation
- [ ] Complete end-to-end testing of the reset flow

## Admin Authentication Fixes
- [x] Complete migration from is_admin to role='admin'
- [ ] Test admin login and permissions thoroughly
- [ ] Verify admin password change functionality 

## Database Schema Alignment
- [x] Ensure consistent use of column names (password vs password_hash)
- [x] Check for remaining instances of is_admin
- [ ] Consider creating a database migration script
- [x] Update setup scripts to match current schema
- [x] Document current database schema

## Security Enhancements
- [ ] Implement rate limiting for password reset requests
- [ ] Set up proper email verification for resets
- [ ] Ensure CSRF protection across all forms

## User Experience
- [ ] Improve error messaging
- [ ] Enhance styling of forgot password modal and reset page
- [ ] Add password strength indicators and requirements

## Testing
- [ ] Create test cases for password reset flow
- [ ] Test admin authentication thoroughly
- [ ] Verify error handling in all cases

## Documentation
- [ ] Document password reset implementation
- [ ] Update API documentation for new endpoints
- [ ] Add code comments explaining security measures

## Deployment Preparation
- [ ] Set up environment variables for production
- [ ] Configure email service for reset emails
- [ ] Implement monitoring for password reset attempts
