const express = require('express');
const { Pool } = require('pg'); // PostgreSQL library
const app = express();
const port = 3000;

// Middleware to parse JSON requests
app.use(express.json());

// PostgreSQL Connection Pool
const pool = new Pool({
    user: 'postgres',        // Replace with your PostgreSQL username
    host: 'localhost',
    database: 'project_alpha', // Replace with your database name
    password: 'your_password', // Replace with your PostgreSQL password
    port: 5432,              // Default PostgreSQL port
});

// Test route
app.get('/', (req, res) => {
    res.send('Express server is running!');
});

// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const query = `
            SELECT * FROM users 
            WHERE username = $1 AND password = $2
        `;
        const result = await pool.query(query, [username, password]);

        if (result.rows.length > 0) {
            res.status(200).json({ success: true, message: 'Login successful!' });
        } else {
            res.status(401).json({ success: false, message: 'Invalid username or password.' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Internal server error.' });
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});
