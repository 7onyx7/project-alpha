# Bantrhaus Database Schema

Current schema as of July 11, 2025.

## Tables

### Users Table
```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  role VARCHAR(50) DEFAULT 'user',
  first_name VARCHAR(255),
  last_name VARCHAR(255)
);
```

### Messages Table
```sql
CREATE TABLE messages (
  id SERIAL PRIMARY KEY,
  room VARCHAR(255) NOT NULL,
  username VARCHAR(255) NOT NULL,
  message TEXT NOT NULL,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_messages_room ON messages(room);
CREATE INDEX idx_messages_timestamp ON messages(timestamp);
```

### Profiles Table
```sql
CREATE TABLE profiles (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  bio TEXT,
  profile_picture VARCHAR(255)
);
```

### Activity Logs Table
```sql
CREATE TABLE activity_logs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  activity VARCHAR(255),
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Password Reset Tokens Table
```sql
CREATE TABLE password_reset_tokens (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  token TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Security Tables

#### Reports Table
```sql
CREATE TABLE reports (
  id SERIAL PRIMARY KEY,
  reporter_id INTEGER,
  reported_user_id INTEGER,
  message_id INTEGER,
  reason VARCHAR(100) NOT NULL,
  content TEXT,
  room VARCHAR(100),
  status VARCHAR(20) DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  resolved_at TIMESTAMP,
  moderator_notes TEXT
);
```

#### Banned Users Table
```sql
CREATE TABLE banned_users (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL,
  reason TEXT,
  banned_by INTEGER,
  banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP,
  is_active BOOLEAN DEFAULT TRUE
);
```

#### User Sessions Table
```sql
CREATE TABLE user_sessions (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL,
  session_token VARCHAR(255) NOT NULL,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  is_active BOOLEAN DEFAULT TRUE
);
```

#### Audit Log Table
```sql
CREATE TABLE audit_log (
  id SERIAL PRIMARY KEY,
  user_id INTEGER,
  action VARCHAR(100) NOT NULL,
  details JSONB,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Key Points

1. Admin authentication uses the `role` column with value 'admin', not an is_admin boolean flag
2. Passwords are stored in the `password` column, not password_hash
3. All timestamps use TIMESTAMP WITHOUT TIME ZONE

## Database Maintenance

To create the required tables:

```bash
# Connect to PostgreSQL
psql -U postgres

# Create the database if it doesn't exist
CREATE DATABASE bantrhaus;

# Connect to the database
\c bantrhaus

# Create the tables (if not already created)
# Run the SQL statements above to create each table
```
