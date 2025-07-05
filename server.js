/**************************************/
/*            server.js               */
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
const csurf = require('csurf');
const expressSanitizer = require('express-sanitizer');
const cookieParser = require('cookie-parser');
const logger = require('./logger');
const Sentry = require("@sentry/node");

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
const app = express();
const port = 3000;

/*********************/
/* Global Middleware */
/*********************/
if (Sentry.Handlers && Sentry.Handlers.requestHandler) {
  app.use(Sentry.Handlers.requestHandler());
}
app.use(express.json()); // Parse JSON bodies
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(cookieParser()); // Add cookie parser before CSRF
app.use(express.static(path.join(__dirname, "public")));
app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"));
});

// Apply security headers
app.use(helmet());

// Apply rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later."
});
app.use(limiter);

// CSRF is disabled for now - will be implemented with proper frontend integration
// app.use(csurf({ cookie: true }));

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
});

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
      return res.status(403).json({
        success: false,
        message: "Invalid or expired token",
      });
    }
    logger.info("Received Token:", token);
    req.user = user;
    next();
  });
}

/********************************/
/*       Login endpoint         */
/********************************/
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  logger.info("POST /login route hit with data:", { username, password });

  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);

    if (result.rows.length === 0) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid username or password." });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid username or password." });
    }

    // Generate the JWT
    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    return res.status(200).json({
      success: true,
      message: "Login successful!",
      token,
    });
  } catch (err) {
    logger.error("Error querying the database:", err);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error!" });
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
  const { firstName, lastName, email, username, password } = req.body;
  logger.info("POST /register route hit with data:", {
    firstName,
    lastName,
    email,
    username,
    password,
  });

  // Basic checks
  if (!firstName || !lastName || !email || !username || !password) {
    return res.status(400).json({
      success: false,
      message: "All fields are required!",
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      success: false,
      message: "Password must be at least 6 characters.",
    });
  }

  // Email pattern check
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res
      .status(400)
      .json({ success: false, message: "Invalid email format." });
  }

  try {
    const userExists = await pool.query(
      "SELECT * FROM users WHERE username = $1 OR email = $2",
      [username, email]
    );

    if (userExists.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Username already exists!",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (first_name, last_name, email, username, password) VALUES ($1, $2, $3, $4, $5) RETURNING id, first_name, last_name, email, username",
      [firstName, lastName, email, username, hashedPassword]
    );

    const newUser = result.rows[0];
    return res.status(201).json({
      success: true,
      message: "User created successfully!",
      user: newUser,
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

const activeRooms = {}; // Tracks rooms and their users

io.on("connection", (socket) => {
    console.log(`User connected: ${socket.id}`);

    socket.on("userJoined", (data) => {
        const { username, room: requestedRoom } = data;
        let room = requestedRoom;

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
        try {
            await pool.query(
                "INSERT INTO messages (room, username, message) VALUES ($1, $2, $3)",
                [room, data.username, data.message]
            );
        } catch (err) {
            console.error("Error saving message to database:", err);
        }
        io.to(room).emit("chatMessage", data);
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
        const { username, room } = data;
        if (onlineUsers[socket.id] && onlineUsers[socket.id].disconnecting) {
            console.log(`${username} reconnected to ${room}`);
            onlineUsers[socket.id].disconnecting = false;
        }
    });
});

app.get("/messages/:room", async (req, res) => {
    const { room } = req.params;
    try {
      const result = await pool.query(
        "SELECT username, message, timestamp FROM messages WHERE room = $1 ORDER BY timestamp ASC LIMIT 100",
        [room]
      );
      res.json({ success: true, messages: result.rows });
    } catch (err) {
      console.error("Error fetching messages:", err);
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

  // Send a response to the client
  res.status(500).json({
    success: false,
    message: 'An unexpected error occurred'
  });
});

// Only start the server if this file is run directly
if (require.main === module) {
  server.listen(port, async () => {
    logger.info(`Server is running at http://localhost:${port}`);
    try {
      const { default: open } = await import("open");
      open(`http://localhost:${port}`);
    } catch (err) {
      logger.info("Browser open failed, but server is running");
    }
  });
}

// Export the app for testing
module.exports = app;