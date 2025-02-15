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
app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"));
});


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

    socket.on("userJoined", (username) => {
        if (!username) {
            console.error("User joined without a username!");
            return;
        }

        let room = null;

        // Check if an available room has only 1 user
        for (let [roomName, users] of Object.entries(activeRooms)) {
            if (users.length === 1) {
                room = roomName;
                break;
            }
        }

        // If no available room, create a new one
        if (!room) {
            room = `room_${socket.id}`;
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

        // If room is full (2 users), notify them
        if (activeRooms[room].length === 2) {
            io.to(room).emit("roomReady", { room });
        }

        socket.on("chatMessage", (data) => {
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
          activeRooms[room] = activeRooms[room].filter(user => user.id !== socket.id);
      
          if (activeRooms[room].length === 0) {
              delete activeRooms[room];
          }
      
          io.to(room).emit("updateUserList", activeRooms[room]?.map(user => user.username) || []);
        });
      
      socket.on("disconnect", () => {
          const userInfo = onlineUsers[socket.id];
          if (!userInfo) return;
      
          const { username, room } = userInfo;
          console.log(`${username} disconnected from ${room}`);
      
          // Notify remaining user in the room
          socket.to(room).emit("chatEnded", { username });
      
          // Remove user from tracking
          socket.leave(room);
          delete onlineUsers[socket.id];
          activeRooms[room] = activeRooms[room].filter(user => user.id !== socket.id);
      
          if (activeRooms[room].length === 0) {
              delete activeRooms[room];
          }
      
          // 🔹 Update the user list
          io.to(room).emit("updateUserList", activeRooms[room]?.map(user => user.username || []));
      });
    });
});


server.listen(port, async () => {
  console.log(`Server is running at http://localhost:${port}`);
  const { default: open } = await import("open");
  open(`http://localhost:${port}`);
});
