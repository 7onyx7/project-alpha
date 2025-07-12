# Changelog

## [1.0.5] - 2025-07-11
### Added
- Implemented email service for password reset links
- Added password visibility toggle on reset password page
- Enhanced password validation with real-time feedback
- Added password strength meter on reset page

## [1.0.4] - 2025-07-11
  - Added "Forgot Password" button to login page
  - Created password reset token system
  - Added password reset routes and endpoints
  - Created reset password page with password strength meter
- Enhanced database schema documentation
- Created comprehensive security tables
  - Added audit_log table for tracking sensitive operations
  - Added banned_users table for moderation
  - Added reports table for user reporting
  - Added user_sessions table for session management
- Added password reset testing script
- Updated README with new security features
- Created detailed password reset documentation

### Fixed
- Fixed API endpoint for password reset to follow RESTful conventions
- Fixed server initialization issues with AdminAuth
- Ensured environment variables include NODE_ENV
- Added error logging for password reset process

### Security
- Implemented token-based password reset with expiration
- Added rate limiting for password reset requests
- Created audit logging for password reset operations
- Implemented secure token validation and single-use tokens

## [1.0.3] - 2025-07-11
### Changed
- Renamed project from "Project Alpha" to "Bantrhaus"
- Updated all references in code, HTML, and documentation
- Updated package.json name and keywords
- Updated HTML titles and headers
- Updated CDN setup guide with new domain name references

## [1.0.2] - 2025-07-10
### Added
- Created deployment guide in README.md
- Set up Procfile for Heroku deployment
- Added CDN setup guide with Cloudflare and jsDelivr options
- Added minification scripts for JS and CSS
- Improved error logging with structured information
- Enhanced environment variable validation
- Created .gitignore patterns for minified files

### Fixed
- Removed duplicate csurf import in server.js
- Eliminated redundant sanitization of database query results
- Updated console.error calls to use logger instead
- Enhanced error messages for better user experience

### Pending
- Actual deployment to production
- CDN implementation
- Redis caching
- Docker containerization
- CI/CD pipeline

## [1.0.1] - 2025-07-05
### Added
- Integrated Winston for structured logging (console and file)
- Integrated Sentry for error monitoring and alerting
- Improved error handler middleware for diagnostics
- Updated project audit status log to reflect new progress

### Fixed
- Logger and Sentry initialization issues
- Ensured .gitignore excludes sensitive and log files

### Pending
- Comprehensive integration and E2E tests
- Performance monitoring and usage analytics
- Accessibility and internationalization
- Legal/compliance documentation

## [1.0.0] - 2025-07-04
### Added
- Core chat functionality (real-time messaging, room pairing, message persistence)
- Frontend UI/UX improvements (system messages, tab switching support)
- Security enhancements (rate limiting, CSRF protection, security headers)

### Fixed
- Tab switching disconnect issue
- Duplicate socket event handlers

### Pending
- Comprehensive testing (unit, integration, E2E)
- Monitoring and analytics
- Accessibility and internationalization
- Legal/compliance documentation
