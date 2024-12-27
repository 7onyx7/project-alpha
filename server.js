require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const path = require('path');
const open = require('open').default; // Use `.default` to access the function



const app = express();
const port = 3000;

// Middleware
app.use(express.json()); // Parse JSON bodies

// Serve the frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});


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
            res.status(200).json({ success: true, message: 'Login successful!' });
        } else {
            res.status(401).json({ success: false, message: 'Invalid username or password.' });
        }
    } catch (err) {
        console.error('Error querying the database:', err);
        res.status(500).json({ success: false, message: 'Internal server error!' });
    }
});

app.listen(port, async () => {
    console.log(`Server is running at http://localhost:${port}`);
    await open(`http://localhost:${port}`);
});
