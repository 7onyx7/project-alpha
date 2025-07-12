/**************************************/
/*         security-status.js         */
/*       SECURITY STATUS CHECKER      */
/*         BANTRHAUS v1.0.0           */
/**************************************/

const logger = require('./logger');

class SecurityStatusChecker {
  constructor() {
    this.checks = [];
    this.initializeChecks();
  }

  initializeChecks() {
    this.checks = [
      {
        name: 'Environment Variables',
        category: 'configuration',
        check: () => this.checkEnvironmentVariables(),
        critical: true
      },
      {
        name: 'Database Security',
        category: 'database',
        check: () => this.checkDatabaseSecurity(),
        critical: true
      },
      {
        name: 'Rate Limiting',
        category: 'security',
        check: () => this.checkRateLimiting(),
        critical: true
      },
      {
        name: 'Content Filtering',
        category: 'moderation',
        check: () => this.checkContentFiltering(),
        critical: true
      },
      {
        name: 'Age Verification',
        category: 'legal',
        check: () => this.checkAgeVerification(),
        critical: true
      },
      {
        name: 'SSL/HTTPS',
        category: 'security',
        check: () => this.checkSSL(),
        critical: true
      },
      {
        name: 'Input Sanitization',
        category: 'security',
        check: () => this.checkInputSanitization(),
        critical: true
      },
      {
        name: 'Session Security',
        category: 'security',
        check: () => this.checkSessionSecurity(),
        critical: false
      },
      {
        name: 'Logging and Monitoring',
        category: 'monitoring',
        check: () => this.checkLoggingAndMonitoring(),
        critical: false
      },
      {
        name: 'Legal Documents',
        category: 'legal',
        check: () => this.checkLegalDocuments(),
        critical: true
      }
    ];
  }

  checkEnvironmentVariables() {
    const requiredVars = ['DB_USER', 'DB_PASSWORD', 'DB_HOST', 'DB_NAME', 'DB_PORT', 'JWT_SECRET'];
    const missing = requiredVars.filter(varName => !process.env[varName]);
    
    if (missing.length > 0) {
      return {
        status: 'fail',
        message: `Missing environment variables: ${missing.join(', ')}`,
        recommendation: 'Set all required environment variables in your .env file'
      };
    }

    // Check JWT secret strength
    if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
      return {
        status: 'warning',
        message: 'JWT secret is too short',
        recommendation: 'Use a JWT secret with at least 32 characters'
      };
    }

    return {
      status: 'pass',
      message: 'All required environment variables are set'
    };
  }

  checkDatabaseSecurity() {
    const checks = [];
    
    // Check for default credentials
    if (process.env.DB_PASSWORD === 'password' || process.env.DB_PASSWORD === '123456') {
      checks.push('Database password appears to be default or weak');
    }

    // Check for SSL in production
    if (process.env.NODE_ENV === 'production' && !process.env.DB_SSL) {
      checks.push('Database SSL not configured for production');
    }

    if (checks.length > 0) {
      return {
        status: 'warning',
        message: checks.join(', '),
        recommendation: 'Use strong database credentials and enable SSL in production'
      };
    }

    return {
      status: 'pass',
      message: 'Database security configuration looks good'
    };
  }

  checkRateLimiting() {
    // This is a basic check - in a real implementation, you'd check the actual middleware
    try {
      const rateLimitConfig = require('./security').rateLimiters;
      if (rateLimitConfig && rateLimitConfig.loginLimiter) {
        return {
          status: 'pass',
          message: 'Rate limiting is configured and active'
        };
      }
    } catch (error) {
      return {
        status: 'fail',
        message: 'Rate limiting not properly configured',
        recommendation: 'Implement rate limiting for login, registration, and messaging'
      };
    }

    return {
      status: 'warning',
      message: 'Rate limiting configuration could not be verified'
    };
  }

  checkContentFiltering() {
    try {
      const security = require('./security');
      if (security.profanityFilter && security.validateMessage) {
        return {
          status: 'pass',
          message: 'Content filtering is active'
        };
      }
    } catch (error) {
      return {
        status: 'fail',
        message: 'Content filtering not configured',
        recommendation: 'Implement profanity filtering and content validation'
      };
    }

    return {
      status: 'fail',
      message: 'Content filtering not found'
    };
  }

  checkAgeVerification() {
    const fs = require('fs');
    const path = require('path');
    
    try {
      const ageVerificationPath = path.join(__dirname, 'public', 'age-verification.html');
      if (fs.existsSync(ageVerificationPath)) {
        return {
          status: 'pass',
          message: 'Age verification page exists'
        };
      }
    } catch (error) {
      // File check failed
    }

    return {
      status: 'fail',
      message: 'Age verification not implemented',
      recommendation: 'Implement age verification before allowing access to chat'
    };
  }

  checkSSL() {
    if (process.env.NODE_ENV === 'production') {
      // In production, this should be handled by the hosting platform
      return {
        status: 'warning',
        message: 'SSL/HTTPS must be configured at the hosting platform level',
        recommendation: 'Ensure your hosting platform (Heroku, etc.) provides SSL certificates'
      };
    }

    return {
      status: 'pass',
      message: 'SSL not required in development mode'
    };
  }

  checkInputSanitization() {
    try {
      const security = require('./security');
      if (security.securityMiddleware && security.securityMiddleware.validateInput) {
        return {
          status: 'pass',
          message: 'Input sanitization middleware is active'
        };
      }
    } catch (error) {
      return {
        status: 'fail',
        message: 'Input sanitization not configured',
        recommendation: 'Implement input sanitization middleware'
      };
    }

    return {
      status: 'fail',
      message: 'Input sanitization not found'
    };
  }

  checkSessionSecurity() {
    // Basic check for session configuration
    if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 32) {
      return {
        status: 'pass',
        message: 'Session security is configured'
      };
    }

    return {
      status: 'warning',
      message: 'Session security could be improved',
      recommendation: 'Set a strong SESSION_SECRET and configure secure session options'
    };
  }

  checkLoggingAndMonitoring() {
    try {
      const logger = require('./logger');
      if (logger && logger.info) {
        return {
          status: 'pass',
          message: 'Logging system is active'
        };
      }
    } catch (error) {
      return {
        status: 'warning',
        message: 'Logging system not found',
        recommendation: 'Implement comprehensive logging for security monitoring'
      };
    }

    return {
      status: 'warning',
      message: 'Logging system could not be verified'
    };
  }

  checkLegalDocuments() {
    try {
      const legal = require('./legal');
      if (legal.termsOfService && legal.privacyPolicy && legal.communityGuidelines) {
        return {
          status: 'pass',
          message: 'Legal documents are available'
        };
      }
    } catch (error) {
      return {
        status: 'fail',
        message: 'Legal documents not found',
        recommendation: 'Create Terms of Service, Privacy Policy, and Community Guidelines'
      };
    }

    return {
      status: 'fail',
      message: 'Legal documents not configured'
    };
  }

  async runAllChecks() {
    const results = {
      timestamp: new Date().toISOString(),
      overall: 'pass',
      critical_issues: 0,
      warnings: 0,
      passed: 0,
      failed: 0,
      checks: []
    };

    for (const check of this.checks) {
      try {
        const result = await check.check();
        const checkResult = {
          name: check.name,
          category: check.category,
          critical: check.critical,
          ...result
        };

        results.checks.push(checkResult);

        // Count results
        if (result.status === 'pass') {
          results.passed++;
        } else if (result.status === 'fail') {
          results.failed++;
          if (check.critical) {
            results.critical_issues++;
          }
        } else if (result.status === 'warning') {
          results.warnings++;
        }

      } catch (error) {
        logger.error(`Security check failed: ${check.name}`, { error: error.message });
        results.checks.push({
          name: check.name,
          category: check.category,
          critical: check.critical,
          status: 'error',
          message: `Check failed: ${error.message}`
        });
        results.failed++;
      }
    }

    // Determine overall status
    if (results.critical_issues > 0) {
      results.overall = 'critical';
    } else if (results.failed > 0) {
      results.overall = 'warning';
    } else if (results.warnings > 0) {
      results.overall = 'warning';
    }

    return results;
  }

  async getSecurityReport() {
    const results = await this.runAllChecks();
    
    logger.info('Security check completed', {
      overall: results.overall,
      critical_issues: results.critical_issues,
      warnings: results.warnings,
      passed: results.passed,
      failed: results.failed
    });

    return results;
  }

  getDeploymentReadiness() {
    return this.runAllChecks().then(results => {
      const criticalIssues = results.checks.filter(check => 
        check.critical && (check.status === 'fail' || check.status === 'error')
      );

      return {
        ready: criticalIssues.length === 0,
        criticalIssues,
        recommendations: criticalIssues.map(issue => ({
          check: issue.name,
          recommendation: issue.recommendation || 'Fix this critical issue before deployment'
        }))
      };
    });
  }
}

module.exports = SecurityStatusChecker;
