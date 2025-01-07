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

let open;
(async () => {
  open = (await import("open")).default;
})();

const app = express();
const port = 3000;

/*********************/
/* Global Middleware */
/*********************/
app.use(express.json()); // Parse JSON bodies
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(express.static(path.join(__dirname, "public")));

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
    console.log("Received Token:", token);
    req.user = user;
    next();
  });
}

/********************************/
/*       Login endpoint         */
/********************************/
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  console.log("POST /login route hit with data:", { username, password });

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
    console.error("Error querying the database:", err);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error!" });
  }
});

/**********************************/
/*      Register endpoint         */
/**********************************/
app.post("/register", async (req, res) => {
  const { firstName, lastName, email, username, password } = req.body;
  console.log("POST /register route hit with data:", {
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
    console.error("Error querying the database:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error!",
    });
  }
});

/********************************/
/* GET /chat - Fetch Chat Users */
/********************************/
app.get("/chat", authenticateToken, async (req, res) => {
  try {
    // Fetch usernames of logged-in users from your database or session store
    const result = await pool.query("SELECT username FROM users");
    if (result.rows.length > 0) {
      return res.status(200).json({
        success: true,
        users: result.rows, // Send user list to the client
      });
    } else {
      return res.status(404).json({
        success: false,
        message: "No users found",
      });
    }
  } catch (err) {
    console.error("Error querying the database:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
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

// Example: Basic Chat
io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);

  socket.on("chatMessage", (message) => {
    io.emit("chatMessage", { message });
  });

  // If you want a user list, define "onlineUsers" here or outside
  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});

app.listen(port, async () => {
  console.log(`Server is running at http://localhost:${port}`);

  // Dynamically import `open` and call it here
  const { default: open } = await import("open");
  open(`http://localhost:${port}`);
});
