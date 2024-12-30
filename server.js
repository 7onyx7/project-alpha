/**************************************/
/* server.js (located at project root) */
/**************************************/

require('dotenv').config();

const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const open = require('open').default; // Use `.default` to access the function
const jwt = require('jsonwebtoken');  // JWT library

const express = require('express');
const path = require('path');
const app = express();
const port = 3000;

/*********************/
/* Global Middleware */
/*********************/
app.use(express.json()); // Parse JSON bodies

// Middleware to verify the JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization']; // "Authorization" header
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token is required!' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }
    console.log('Received Token:', token);
    req.user = user; // Attach the decoded user info to req
    next();
  });
};

// Serve the frontend from the "public" folder
app.use(express.static(path.join(__dirname, 'public')));

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

/********************************/
/* 1) Existing "login" endpoint */
/********************************/
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('POST /login route hit with data:', { username, password });

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid username or password.' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      // Generate the JWT token
      const token = jwt.sign(
        { id: user.id, username: user.username },  // Payload
        process.env.JWT_SECRET,                    // Secret key
        { expiresIn: '1h' }                        // Expiry time
      );

      return res.status(200).json({
        success: true,
        message: 'Login successful!',
        token, // <-- The JWT token
      });
    } else {
      return res.status(401).json({ success: false, message: 'Invalid username or password.' });
    }
  } catch (err) {
    console.error('Error querying the database:', err);
    return res.status(500).json({ success: false, message: 'Internal server error!' });
  }
});

/**********************************/
/* 2) Existing "register" endpoint */
/**********************************/
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  console.log('POST /register route hit with data:', { username, password });

  try {
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password are required!' });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters long!' });
    }

    const userExists = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (userExists.rows.length > 0) {
      return res.status(409).json({ success: false, message: 'Username already exists!' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *',
      [username, hashedPassword]
    );

    const user = result.rows[0];
    delete user.password; // Remove password field from the response

    return res.status(201).json({ success: true, message: 'User created successfully!', user });
  } catch (err) {
    console.error('Error querying the database:', err);
    return res.status(500).json({ success: false, message: 'Internal server error!' });
  }
});

/***********************************************************/
/* 3) REMOVE / COMMENT OUT THIS PROTECTED /dashboard route */
/***********************************************************/
//
// app.get('/dashboard', authenticateToken, async (req, res) => {
//   try {
//     const userId = req.user.id; // from token
//     const result = await pool.query('SELECT username FROM users WHERE id = $1', [userId]);
//
//     if (result.rows.length > 0) {
//       res.status(200).json({ success: true, message: 'Welcome to your dashboard!', user: result.rows[0] });
//     } else {
//       res.status(404).json({ success: false, message: 'User not found' });
//     }
//   } catch (err) {
//     console.error('Error querying the database:', err);
//     res.status(500).json({ success: false, message: 'Internal server error' });
//   }
// });

/****************************************************************************/
/* 4) Public route serving the "dashboard.html" file itself. */
/****************************************************************************/
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

/*****************************************************************************************/
/* 5) Protected API route to actually fetch user data for the dashboard. */
/*****************************************************************************************/
app.get('/api/dashboard-data', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id; // from the decoded JWT
    const result = await pool.query('SELECT username FROM users WHERE id = $1', [userId]);

    if (result.rows.length > 0) {
      return res.status(200).json({
        success: true,
        message: 'Fetched dashboard data successfully!',
        user: result.rows[0],
      });
    } else {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
  } catch (err) {
    console.error('Error querying the database:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

/*****************/
/* Start the App */
/*****************/
app.listen(port, async () => {
  console.log(`Server is running at http://localhost:${port}`);
  await open(`http://localhost:${port}`);
});
