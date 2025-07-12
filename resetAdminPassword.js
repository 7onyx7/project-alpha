// resetAdminPassword.js
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
require('dotenv').config();

async function resetPassword() {
  // Generate hash for 'admin123!'
  const hash = await bcrypt.hash('admin123!', 10);
  console.log('Generated password hash for "admin123!"');
  
  // Connect to database using .env variables
  const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
  });
  
  // Update admin user password
  try {
    const result = await pool.query(
      'UPDATE users SET password = $1 WHERE username = $2 RETURNING id', 
      [hash, 'admin']
    );
    
    if (result.rows.length > 0) {
      console.log(`✅ Admin password updated successfully to "admin123!"`);
      console.log(`User ID: ${result.rows[0].id}`);
    } else {
      console.log('⚠️ No admin user found. Creating one...');
      
      // Try to create admin user if doesn't exist
      const insertResult = await pool.query(
        'INSERT INTO users (username, password, email, role) VALUES ($1, $2, $3, $4) RETURNING id',
        ['admin', hash, 'admin@bantrhaus.com', 'admin']
      );
      
      console.log(`✅ Admin user created with ID: ${insertResult.rows[0].id}`);
    }
  } catch (error) {
    console.error('❌ Database error:', error.message);
    
    // Print more detailed error information
    console.log('\nDatabase connection info:');
    console.log(`- Host: ${process.env.DB_HOST}`);
    console.log(`- Database: ${process.env.DB_NAME}`);
    console.log(`- User: ${process.env.DB_USER}`);
    console.log(`- Port: ${process.env.DB_PORT}`);
    console.log(`- SSL: ${process.env.DB_SSL}`);
    
    // Check if the database exists
    try {
      const checkDb = new Pool({
        user: process.env.DB_USER,
        host: process.env.DB_HOST,
        password: process.env.DB_PASSWORD,
        port: process.env.DB_PORT,
        database: 'postgres', // Connect to default database
        ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
      });
      
      const dbResult = await checkDb.query(
        "SELECT datname FROM pg_database WHERE datname = $1",
        [process.env.DB_NAME]
      );
      
      if (dbResult.rows.length === 0) {
        console.error(`❌ Database '${process.env.DB_NAME}' does not exist.`);
      }
      
      await checkDb.end();
    } catch (dbError) {
      console.error('❌ Could not connect to PostgreSQL server:', dbError.message);
    }
  }
  
  // Close pool
  await pool.end();
}

// Run the function
resetPassword().catch(error => {
  console.error('❌ Uncaught error:', error);
  process.exit(1);
});
