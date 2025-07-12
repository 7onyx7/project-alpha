/**************************************/
/*            server.js               */
/*          BANTRHAUS v1.0.0          */
/**************************************/

require("dotenv").config();
const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const cors = require("cors");
const http = require("http");
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const expressSanitizer = require('express-sanitizer');
const cookieParser = require('cookie-parser');
const logger = require('./logger');
const Sentry = require("@sentry/node");
const CustomCSRF = require('./custom-csrf');
const { 
  SecurityConfig, 
  validateUsername, 
  validateMessage, 
  validateEmail, 
  validatePassword, 
  validateAge,
  createReport,
  securityMiddleware,
  createSecurityTables,
  banIP,
  isIPBanned,
  recordViolation,
  checkForVPN,
  ipViolations,
  bannedIPs,
  rateLimiters 
} = require('./security');
const ModerationSystem = require('./moderation');
const { termsOfService, privacyPolicy, communityGuidelines } = require('./legal');
const EnhancedSecurity = require('./enhanced-security');
const DeploymentSecurity = require('./deployment-security');
const { AdminAuth } = require('./admin-auth');
const { MonetizationSystem, MonetizationConfig } = require('./monetization');
const SimpleMonetization = require('./simple-monetization');

Sentry.init({
  enabled: false,
  tracesSampleRate: 1.0,
});

/*
let open;
(async () => {
  open = (await import("open")).default;
})();
*/

// Check required environment variables
['DB_USER', 'DB_PASSWORD', 'DB_HOST', 'DB_NAME', 'DB_PORT', 'JWT_SECRET'].forEach((key) => {
  if (!process.env[key]) {
    logger.error(`Missing required environment variable: ${key}`);
    throw new Error(`Missing required environment variable: ${key}`);
  }
});

const app = express();
const port = process.env.PORT || 3000;
const isDevelopment = process.env.NODE_ENV !== 'production';
const corsOrigin = isDevelopment ? "http://localhost:3000" : process.env.CORS_ORIGIN || "*";

// Initialize security systems
let moderationSystem;
let enhancedSecurity;
let csrfProtection;
let adminAuth;

/*********************/
/* Global Middleware */
/*********************/
if (Sentry.Handlers && Sentry.Handlers.requestHandler) {
  app.use(Sentry.Handlers.requestHandler());
}
app.use(express.json()); // Parse JSON bodies
app.use(cors({ origin: corsOrigin, credentials: true }));
app.use(cookieParser()); // Add cookie parser before CSRF
app.use(express.static(path.join(__dirname, "public")));

// Security middleware
app.use(securityMiddleware.validateInput);
app.use(securityMiddleware.logSuspiciousActivity);
// app.use(securityMiddleware.checkIPBan);  // Temporarily disabled for testing
// app.use(securityMiddleware.checkVPN);   // Temporarily disabled for testing

// Enhanced security middleware
app.use(async (req, res, next) => {
  if (enhancedSecurity) {
    // Check for suspicious IP
    const ipCheck = await enhancedSecurity.checkSuspiciousIP(req.ip);
    if (ipCheck.suspicious) {
      logger.warn('Suspicious IP detected', { ip: req.ip, reason: ipCheck.reason });
      return res.status(429).json({ 
        success: false, 
        message: 'Too many requests. Please try again later.' 
      });
    }

    // Bot detection for sensitive routes
    if (req.path.includes('/register') || req.path.includes('/login')) {
      const botCheck = await enhancedSecurity.detectBot(req);
      if (botCheck.isBot && botCheck.confidence > 70) {
        logger.warn('Bot detected', { ip: req.ip, reasons: botCheck.reasons });
        return res.status(403).json({ 
          success: false, 
          message: 'Access denied. Please complete verification.' 
        });
      }
    }
  }
  next();
});

// Age verification redirect
app.use((req, res, next) => {
  // Skip age verification for API routes, static files, and auth routes
  if (req.path.startsWith('/api/') || 
      req.path.startsWith('/legal/') ||
      req.path.includes('.') ||
      req.path === '/age-verification.html' ||
      req.path === '/csrf-token' ||
      req.path === '/reset-password' ||
      req.path === '/reset-password.html' ||
      req.path === '/reset-password-complete' ||
      req.path === '/login' ||
      req.path === '/register' ||
      req.path === '/logout' ||
      req.path === '/') {  // Allow home page access
    return next();
  }
  
  // Check if user has verified age
  const ageVerified = req.cookies.ageVerified;
  if (!ageVerified) {
    logger.info('Age verification required for:', { path: req.path, ip: req.ip });
    return res.redirect('/age-verification.html');
  }
  
  next();
});

app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"));
});

// Apply security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "ws:", "wss:"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

// Enhanced rate limiting (temporarily disabled for testing)
// app.use('/api/', rateLimiters.loginLimiter);
// app.use('/login', rateLimiters.loginLimiter);
// app.use('/register', rateLimiters.registerLimiter);

// Also apply a more lenient limit to all routes
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300, // Higher limit for general routes
  message: "Too many requests from this IP, please try again later."
});
app.use(generalLimiter);

// Enable CSRF protection
app.use((req, res, next) => {
  if (csrfProtection) {
    csrfProtection.middleware()(req, res, next);
  } else {
    next();
  }
});

app.get('/csrf-token', (req, res) => {
  if (csrfProtection) {
    csrfProtection.getTokenRoute()(req, res);
  } else {
    res.json({ csrfToken: 'csrf-not-initialized' });
  }
});

app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ 
      success: false, 
      message: 'Your session has expired or is invalid. Please refresh the page and try again.' 
    });
  }
  next(err);
});

// Apply input sanitization
app.use(expressSanitizer());

const morgan = require('morgan');

app.use(morgan('combined', {
  stream: {
    write: (message) => {
      logger.info(message.trim());
    },
  },
}));

const compression = require('compression');
app.use(compression()); // Compress responses

// CSRF error handling (commented out for now)
// app.use((err, req, res, next) => {
//   if (err.code === 'EBADCSRFTOKEN') {
//     return res.status(403).json({ success: false, message: 'Invalid CSRF token.' });
//   }
//   next(err);
// });

/***************/
/* DB Settings */
/***************/
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
  max: 20, // Maximum number of clients
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Security initialization (manual database setup required)
(async () => {
  try {
    // Note: Database tables must be created manually before running in production
    // Run: node -e "require('./security').createSecurityTables(pool)"
    
    moderationSystem = new ModerationSystem(pool);
    enhancedSecurity = new EnhancedSecurity(pool);
    csrfProtection = new CustomCSRF();
    adminAuth = new AdminAuth(pool);
    
    logger.info('Security modules initialized (database tables must be created manually)');
    
    // Run deployment security checks in development
    if (process.env.NODE_ENV !== 'production') {
      logger.info('Running security audit...');
      await DeploymentSecurity.runPreDeploymentChecks(pool);
    }
  } catch (error) {
    logger.error('Failed to initialize security systems', { error: error.message });
  }
})();

/**************************************/
/* Helper Functions                   */
/**************************************/
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Access token is required!",
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      const message = err.name === "TokenExpiredError" 
        ? "Your session has expired. Please log in again."
        : "Invalid token.";
      return res.status(403).json({ success: false, message });
    }
    
    logger.info("Received Token:", token);
    req.user = user;
    next();
  });
}

// Admin authentication middleware
function authenticateAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies?.adminToken;
  
  if (!adminAuth) {
    return res.status(500).json({ success: false, message: 'Admin system not initialized' });
  }
  
  const verification = adminAuth.verifyAdminSession(token);
  if (!verification.valid) {
    return res.status(401).json({ success: false, message: verification.error || 'Admin authentication required' });
  }
  
  req.admin = verification.admin;
  next();
}

// Check if user is admin (for client-side display)
function checkAdminStatus(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
  
  if (!token) {
    req.isAdmin = false;
    return next();
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    
    // Check if user is admin by looking up their role in the database
    pool.query("SELECT role FROM users WHERE id = $1", [decoded.id])
      .then(result => {
        if (result.rows.length > 0) {
          req.isAdmin = result.rows[0].role === 'admin';
        } else {
          req.isAdmin = false;
        }
        next();
      })
      .catch(err => {
        logger.error("Error checking admin status", { error: err.message, userId: decoded.id });
        req.isAdmin = false;
        next();
      });
  } catch (err) {
    req.isAdmin = false;
    next();
  }
}

/********************************/
/*       Login endpoint         */
/********************************/
app.post("/login", async (req, res) => {
  let { username, password } = req.body;
  
  // Log the incoming request details
  logger.info("POST /login route hit", { 
    username: username || "undefined", 
    hasPassword: !!password,
    ip: req.ip,
    userAgent: req.get('User-Agent') || 'Unknown'
  });

  // Check if required fields are provided
  if (!username || !password) {
    logger.warn("Login attempt with missing credentials", { 
      username: username || "missing", 
      password: password ? "provided" : "missing",
      ip: req.ip 
    });
    return res.status(400).json({
      success: false,
      message: "Username and password are required."
    });
  }
  
  // Enhanced validation
  const usernameValidation = validateUsername(username);
  if (!usernameValidation.valid) {
    logger.warn("Login attempt with invalid username", { 
      username, 
      error: usernameValidation.error,
      ip: req.ip 
    });
    return res.status(400).json({
      success: false,
      message: usernameValidation.error
    });
  }
  username = usernameValidation.cleaned;

  try {
    // Check if user exists
    logger.info("Checking if user exists in database", { username });
    const userResult = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    
    if (userResult.rows.length === 0) {
      logger.warn("Login attempt for non-existent user", { username, ip: req.ip });
      return res.status(401).json({ 
        success: false, 
        message: "Invalid username or password." 
      });
    }

    const user = userResult.rows[0];
    logger.info("User found in database", { 
      userId: user.id, 
      username: user.username,
      hasPassword: !!user.password 
    });
    
    // Check if user is banned
    if (moderationSystem) {
      try {
        const isBanned = await moderationSystem.isUserBanned(user.id);
        if (isBanned) {
          logger.warn("Login attempt for banned user", { 
            userId: user.id, 
            username: user.username, 
            ip: req.ip 
          });
          return res.status(403).json({
            success: false,
            message: "Your account has been suspended. Contact support for more information."
          });
        }
      } catch (banCheckError) {
        logger.error("Error checking ban status", { 
          error: banCheckError.message, 
          userId: user.id, 
          username: user.username 
        });
      }
    }

    // Verify password
    logger.info("Verifying password for user", { username });
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      logger.warn("Login attempt with incorrect password", { 
        userId: user.id, 
        username: user.username, 
        ip: req.ip 
      });
      
      // Log failed login attempt
      if (moderationSystem) {
        try {
          await moderationSystem.logUserAction(user.id, 'login_failed', { 
            ip: req.ip,
            reason: 'incorrect_password'
          }, req);
        } catch (logError) {
          logger.error("Error logging failed login attempt", { 
            error: logError.message, 
            userId: user.id, 
            username: user.username 
          });
        }
      }
      
      return res.status(401).json({ 
        success: false, 
        message: "Invalid username or password." 
      });
    }

    // Generate the JWT
    logger.info("Password verified, generating JWT", { username });
    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Log successful login
    if (moderationSystem) {
      try {
        await moderationSystem.logUserAction(user.id, 'login_success', { 
          ip: req.ip,
          userAgent: req.get('User-Agent') || 'Unknown'
        }, req);
      } catch (logError) {
        logger.error("Error logging successful login", { 
          error: logError.message, 
          userId: user.id, 
          username: user.username 
        });
      }
    }

    // Set age verification cookie (if user is logged in, assume verified)
    res.cookie('ageVerified', 'true', { 
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production'
    });

    logger.info("Login successful", { 
      userId: user.id, 
      username: user.username, 
      ip: req.ip 
    });

    return res.status(200).json({
      success: true,
      message: "Login successful!",
      token,
      username: user.username,
      userId: user.id,
      role: user.role || 'user'
    });
  } catch (err) {
    logger.error("Database error during login", { 
      error: err.message, 
      stack: err.stack,
      username: username || "undefined",
      ip: req.ip 
    });
    
    return res.status(500).json({ 
      success: false, 
      message: "Internal server error!" 
    });
  }
});

/**********************************/
/*       Logout endpoint          */
/**********************************/

app.post("/logout", (req, res) => {
  return res.status(200).json({
    success: true,
    message: "Logout successful!",
  });

})

/**********************************/
/*      Register endpoint         */
/**********************************/
app.post("/register", async (req, res) => {
  const { firstName, lastName, email, username, password, birthdate } = req.body;

  // Enhanced validation with security checks
  const usernameValidation = validateUsername(username);
  if (!usernameValidation.valid) {
    return res.status(400).json({
      success: false,
      message: usernameValidation.error
    });
  }

  const emailValidation = enhancedSecurity 
    ? await enhancedSecurity.validateEmailSecurity(email)
    : validateEmail(email);
  if (!emailValidation.valid) {
    return res.status(400).json({
      success: false,
      message: emailValidation.error
    });
  }

  const passwordValidation = enhancedSecurity 
    ? enhancedSecurity.validatePasswordComplexity(password)
    : validatePassword(password);
  if (!passwordValidation.valid) {
    return res.status(400).json({
      success: false,
      message: passwordValidation.recommendations?.[0] || passwordValidation.error
    });
  }

  // Age verification
  if (birthdate) {
    const ageValidation = validateAge(birthdate);
    if (!ageValidation.valid) {
      return res.status(400).json({
        success: false,
        message: ageValidation.error
      });
    }
  }

  logger.info("POST /register route hit", {
    username: usernameValidation.cleaned,
    email: emailValidation.cleaned,
    ip: req.ip
  });

  // Basic checks for required fields
  if (!firstName || !lastName || !emailValidation.cleaned || !usernameValidation.cleaned || !password) {
    return res.status(400).json({
      success: false,
      message: "All fields are required!",
    });
  }

  try {
    const userExists = await pool.query(
      "SELECT * FROM users WHERE username = $1 OR email = $2",
      [usernameValidation.cleaned, emailValidation.cleaned]
    );

    if (userExists.rows.length > 0) {
      const existingUser = userExists.rows[0];
      const conflictField = existingUser.username === usernameValidation.cleaned ? "username" : "email";
      return res.status(409).json({
        success: false,
        message: `The ${conflictField} is already in use!`,
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const result = await pool.query(
      "INSERT INTO users (first_name, last_name, email, username, password, created_at) VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING id, first_name, last_name, email, username",
      [req.sanitize(firstName), req.sanitize(lastName), emailValidation.cleaned, usernameValidation.cleaned, hashedPassword]
    );

    const newUser = result.rows[0];
    
    // Log registration
    if (moderationSystem) {
      await moderationSystem.logUserAction(newUser.id, 'account_created', { ip: req.ip }, req);
    }

    // Set age verification cookie
    res.cookie('ageVerified', 'true', { 
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production'
    });

    return res.status(201).json({
      success: true,
      message: "User created successfully!",
      user: {
        id: newUser.id,
        firstName: newUser.first_name,
        lastName: newUser.last_name,
        email: newUser.email,
        username: newUser.username
      },
    });
  } catch (err) {
    logger.error("Error querying the database:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error!",
    });
  }
});

/********************************/
/* GET /chat - Fetch Chat Users */
/********************************/
app.get("/chat", async (req, res) => {
  let username;

  // Check if Authorization Header Exists
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const userResult = await pool.query(
        "SELECT username FROM users WHERE id = $1",
         [decoded.id]
      );

      if (userResult.rows.length > 0) {
        username = userResult.rows[0].username;
        
        return res.status(200).json({
          success: true,
          username,
        });
      } 
      else {
        return res
        .status(401)
        .json({ success: false, message: "Invalid user." });
      }
    } catch (err) {
      return res
      .status(403)
      .json({ success: false, message: "Invalid or expired token." });
    }
  } else {
    
     // Anonymous user scenario
     if (req.query.username) {
      // If the frontend passed a username, decode it
      username = decodeURIComponent(req.query.username);
    } else {
      // Otherwise, fallback to the old Anon_xxxx
      username = `Anon_${Math.floor(1000 + Math.random() * 9000)}`;
    }
  }

  return res.status(200).json({
    success: true,
    username, // Send the assigned username
  });

});

/********************************/
/*       API Routes             */
/********************************/

// Report submission endpoint
app.post("/api/report", async (req, res) => {
  try {
    const { reportedUsername, reason, details, messageContent, room } = req.body;
    
    if (!reportedUsername || !reason || !details) {
      return res.status(400).json({
        success: false,
        message: "Username, reason, and details are required"
      });
    }

    // Get reported user ID
    const userResult = await pool.query("SELECT id FROM users WHERE username = $1", [reportedUsername]);
    const reportedUserId = userResult.rows.length > 0 ? userResult.rows[0].id : null;

    // Create report
    const result = await createReport(pool, {
      reporterId: null, // Anonymous reports for now
      reportedUserId,
      messageId: null,
      reason,
      content: `${details}\n\nMessage: ${messageContent || 'N/A'}`,
      room
    });

    if (result.success) {
      logger.info('Report submitted', { 
        reportedUsername, 
        reason, 
        ip: req.ip,
        reportId: result.reportId 
      });
      
      res.json({ success: true, message: "Report submitted successfully" });
    } else {
      res.status(500).json({ success: false, message: result.error });
    }
  } catch (error) {
    logger.error('Error processing report', { error: error.message });
    res.status(500).json({ success: false, message: "Failed to submit report" });
  }
});

// Age verification endpoint
app.post("/api/age-verify", (req, res) => {
  const { birthdate, confirmed } = req.body;
  
  if (!confirmed) {
    return res.status(400).json({
      success: false,
      message: "Age confirmation is required"
    });
  }

  if (birthdate) {
    const ageValidation = validateAge(birthdate);
    if (!ageValidation.valid) {
      return res.status(400).json({
        success: false,
        message: ageValidation.error
      });
    }
  }

  // Set age verification cookie
  res.cookie('ageVerified', 'true', { 
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  });

  res.json({ success: true, message: "Age verified successfully" });
});

// Legal documents
app.get("/legal/terms", (req, res) => {
  res.set('Content-Type', 'text/plain');
  res.send(termsOfService);
});

app.get("/legal/privacy", (req, res) => {
  res.set('Content-Type', 'text/plain');
  res.send(privacyPolicy);
});

app.get("/legal/guidelines", (req, res) => {
  res.set('Content-Type', 'text/plain');
  res.send(communityGuidelines);
});

// Monetization routes (protected)
if (moderationSystem) {
  app.use('/api/moderation', moderationSystem.getRoutes());
}

// Simple monetization endpoints
app.get('/api/premium/features', (req, res) => {
  res.json({
    success: true,
    features: SimpleMonetization.premiumFeatures
  });
});

app.post('/api/premium/purchase', authenticateToken, (req, res) => {
  const { feature } = req.body;
  const userId = req.user.id;
  
  const paymentLink = SimpleMonetization.generatePaymentLink(feature, userId);
  if (!paymentLink) {
    return res.status(400).json({
      success: false,
      message: 'Invalid feature'
    });
  }
  
  res.json({
    success: true,
    paymentLink
  });
});

// Moderation dashboard (admin only)
app.get('/admin/moderation', authenticateAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'moderation-dashboard.html'));
});

// Security report endpoint
app.get('/admin/security-report', async (req, res) => {
  try {
    const report = DeploymentSecurity.generateSecurityReport(pool);
    res.json({ success: true, report });
  } catch (error) {
    logger.error('Error generating security report', { error: error.message });
    res.status(500).json({ success: false, error: 'Failed to generate security report' });
  }
});

/************************/
/* CREATE HTTP SERVER   */
/************************/
const server = http.createServer(app);

/****************************/
/* SETUP SOCKET.IO on SERVER*/
/****************************/
const onlineUsers = {};

const { Server } = require("socket.io");
const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
  },
});

io.use((socket, next) => {
  // Enhanced sanitization function - still basic but more thorough
  socket.sanitize = (data) => {
      if (!data) return data;
      if (typeof data === 'string') {
        // More thorough XSS protection - removes script content too
        return data
          .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
          .replace(/<[^>]+>/g, '')
          .replace(/javascript:/gi, '')
          .replace(/on\w+=/gi, '');
      }
      if (typeof data === 'object') {
        const sanitized = {};
        for (const key in data) {
          sanitized[key] = typeof data[key] === 'string'
            ? data[key]
              .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
              .replace(/<[^>]+>/g, '')
              .replace(/javascript:/gi, '')
              .replace(/on\w+=/gi, '')
            : data[key];
        }
        return sanitized;
      }
      return data;
  }; 
  next();
});

const activeRooms = {}; // Tracks rooms and their users

io.on("connection", (socket) => {
    console.log(`User connected: ${socket.id}`);

    socket.on("userJoined", (data) => {
        const sanitized = socket.sanitize(data);
        const username = sanitized.username;
        let room = sanitized.room;

        if (!username) {
            console.error("User joined without a username!");
            return;
        }

        // If user specified a room, check if it exists and has space
        if (room && activeRooms[room]) {
            // If room is full, create a new one
            if (activeRooms[room].length >= 2) {
                room = `room_${Date.now()}_${Math.floor(Math.random() * 1000)}`;
                activeRooms[room] = [];
            }
        } 
        // If room doesn't exist or no room was specified, try to pair with someone
        else {
            // Look for a room with exactly one user
            let foundRoom = null;
            for (let [roomName, users] of Object.entries(activeRooms)) {
                if (users.length === 1) {
                    foundRoom = roomName;
                    break;
                }
            }

            // If no room with 1 user found, create a new one
            if (foundRoom) {
                room = foundRoom;
            } else {
                room = room || `room_${Date.now()}_${Math.floor(Math.random() * 1000)}`;
                activeRooms[room] = [];
            }
        }

        // Check if the room is full
        if (activeRooms[room]?.length >= 2) {
            socket.emit("roomFull", { room });
            return;
        }

        // Initialize room if it doesn't exist
        if (!activeRooms[room]) {
            activeRooms[room] = [];
        }

        // Join the room
        socket.join(room);
        activeRooms[room].push({ id: socket.id, username });
        onlineUsers[socket.id] = { username, room };

        console.log(`${username} joined ${room}`);

        // Notify users in the room
        io.to(room).emit("userJoined", { username, room });
        io.to(room).emit("updateUserList", activeRooms[room].map((user) => user.username));

        // 🔹 Notify if waiting for a partner
        if (activeRooms[room].length === 1) {
            io.to(room).emit("waitingForPartner", { message: "Waiting for a partner to join..." });
        }

        // If room is full (2 users), notify them
        if (activeRooms[room].length === 2) {
            io.to(room).emit("roomReady", { room });
        }
    });

    socket.on("chatMessage", async (data) => {
        const userInfo = onlineUsers[socket.id];
        if (!userInfo) return;
        
        const { room } = userInfo;
        const clientIP = socket.handshake.address;

        const sanitized = socket.sanitize(data);
        const originalMessage = sanitized.message;
        const sanitizedUsername = sanitized.username;

        // First validate message with our security system
        const messageValidation = await validateMessage(originalMessage, clientIP);
        if (!messageValidation.valid) {
            socket.emit("messageBlocked", { 
                reason: messageValidation.error,
                originalMessage: originalMessage 
            });
            logger.warn("Message validation failed", { 
                username: sanitizedUsername, 
                message: originalMessage, 
                reason: messageValidation.error,
                ip: clientIP,
                room 
            });
            return;
        }

        // Enhanced message validation and moderation
        if (moderationSystem) {
            // Get user ID if available
            let userId = null;
            try {
                const userResult = await pool.query("SELECT id FROM users WHERE username = $1", [sanitizedUsername]);
                if (userResult.rows.length > 0) {
                    userId = userResult.rows[0].id;
                    
                    // Check if user is banned
                    if (await moderationSystem.isUserBanned(userId)) {
                        socket.emit("error", { message: "Your account has been suspended." });
                        return;
                    }
                }
            } catch (err) {
                logger.error("Error checking user status:", err);
            }

            // Auto-moderate the message
            const reqContext = { 
                ip: socket.handshake.address || '0.0.0.0', 
                userAgent: 'Socket.IO Client' 
            };
            const moderationResult = await moderationSystem.autoModerateMessage(
                messageValidation.cleaned, 
                userId, 
                room, 
                reqContext
            );
            
            if (!moderationResult.allowed) {
                socket.emit("messageBlocked", { 
                    reason: moderationResult.reason,
                    originalMessage: originalMessage 
                });
                logger.warn("Message blocked", { 
                    username: sanitizedUsername, 
                    message: originalMessage, 
                    reason: moderationResult.reason,
                    room 
                });
                return;
            }
            
            // Use the cleaned message
            const cleanedMessage = moderationResult.cleanedMessage;
            
            try {
                await pool.query(
                    "INSERT INTO messages (room, username, message, timestamp) VALUES ($1, $2, $3, NOW())",
                    [room, sanitizedUsername, cleanedMessage]
                );
                
                // Log message for moderation purposes
                if (userId) {
                    await moderationSystem.logUserAction(userId, 'message_sent', {
                        room,
                        message: cleanedMessage,
                        originalMessage: originalMessage !== cleanedMessage ? originalMessage : null
                    }, { 
                        ip: socket.handshake.address,
                        userAgent: socket.handshake.headers['user-agent'] || 'Socket.IO Client' 
                    });
                }
            } catch (err) {
                logger.error("Error saving message to database:", {
                    error: err.message,
                    stack: err.stack,
                    room: room,
                    username: sanitizedUsername
                });
            }

            // Emit the cleaned message
            io.to(room).emit("chatMessage", {
                username: sanitizedUsername,
                message: cleanedMessage,
                room,
                timestamp: new Date().toISOString()
            });
            console.log(`Emitting message to room ${room}: ${sanitizedUsername}: ${cleanedMessage}`);
        } else {
            // Fallback to original behavior if moderation system not available
            try {
                await pool.query(
                    "INSERT INTO messages (room, username, message) VALUES ($1, $2, $3)",
                    [room, sanitizedUsername, originalMessage]
                );
            } catch (err) {
                logger.error("Error saving message to database:", {
                    error: err.message,
                    stack: err.stack,
                    room: room,
                    username: sanitizedUsername
                });
            }
            
            io.to(room).emit("chatMessage", {
                username: sanitizedUsername,
                message: originalMessage,
                room
            });
            console.log(`Emitting fallback message to room ${room}: ${sanitizedUsername}: ${originalMessage}`);
        }
    });

    
    socket.on("userDisconnected", () => {
        const userInfo = onlineUsers[socket.id];
        if (!userInfo) return;
    
        const { username, room } = userInfo;
        console.log(`${username} left ${room}`);
    
        // Notify the remaining user in the room
        socket.to(room).emit("chatEnded", { username });
    
        // Remove user from tracking
        socket.leave(room);
        delete onlineUsers[socket.id];
        if (activeRooms[room]) {
            activeRooms[room] = activeRooms[room].filter(user => user.id !== socket.id);
        
            if (activeRooms[room].length === 0) {
                delete activeRooms[room];
            } else {
                io.to(room).emit("updateUserList", activeRooms[room].map(user => user.username));
            }
        }
    });
    
    
    socket.on("disconnect", () => {
        // When a disconnect happens, don't immediately remove the user
        // Instead, start a timeout to check if they reconnect
        const userInfo = onlineUsers[socket.id];
        if (!userInfo) return;
    
        const { username, room } = userInfo;
        console.log(`${username} disconnected from ${room} - waiting to see if they return...`);
        
        // Set a flag that this user is in a "disconnecting" state
        if (userInfo) {
            userInfo.disconnecting = true;
            
            // Give the user some time to reconnect (e.g., if they're just switching tabs)
            setTimeout(() => {
                // After the timeout, check if the user is still in the disconnecting state
                if (onlineUsers[socket.id] && onlineUsers[socket.id].disconnecting) {
                    console.log(`${username} did not reconnect, removing from room ${room}`);
                    
                    // Notify remaining user in the room
                    socket.to(room).emit("chatEnded", { username });
                    
                    // Remove user from tracking
                    socket.leave(room);
                    delete onlineUsers[socket.id];
                    
                    if (activeRooms[room]) {
                        activeRooms[room] = activeRooms[room].filter(user => user.id !== socket.id);
                    
                        if (activeRooms[room].length === 0) {
                            delete activeRooms[room];
                        } else {
                            io.to(room).emit("updateUserList", activeRooms[room].map(user => user.username));
                        }
                    }
                }
            }, 5000); // Wait 5 seconds before considering the user truly disconnected
        }
    });
    
    // Handle user reconnection
    socket.on("userReconnected", (data) => {
        const sanitized = socket.sanitize(data);
        const username = sanitized.username;
        const room = sanitized.room;
        if (onlineUsers[socket.id] && onlineUsers[socket.id].disconnecting) {
            console.log(`${username} reconnected to ${room}`);
            onlineUsers[socket.id].disconnecting = false;
        }
    });
});

app.get("/messages/:room", async (req, res) => {
    // Sanitize the room parameter
    const room = req.sanitize(req.params.room);

    try {
      const result = await pool.query(
        "SELECT username, message, timestamp FROM messages WHERE room = $1 ORDER BY timestamp ASC LIMIT 100",
        [room]
      );

      console.log(`Retrieved ${result.rows.length} messages for room ${room}`);
      
      // Simply return the query results - no need to re-sanitize data from the database
      res.json({ success: true, messages: result.rows });
    } catch (err) {
      logger.error("Error fetching messages:", {
        error: err.message,
        stack: err.stack,
        room: room
      });
      res.status(500).json({ success: false, message: "Error: Failed to fetch messages" });
    }
});

if (Sentry.Handlers && Sentry.Handlers.errorHandler) {
  app.use(Sentry.Handlers.errorHandler());
}

app.get('/debug-sentry', (req, res) => {
  throw new Error("This is a test error for Sentry!");
});

app.use((err, req, res, next) => {
  logger.error('Unhandled error: %o', {
    error: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip
  });