@echo off
REM PostgreSQL connection script for Bantrhaus
REM This script allows running PostgreSQL commands without typing the password

set PGPASSWORD=password

if "%1"=="list" (
  echo Listing all databases:
  psql -U postgres -l
  goto end
)

if "%1"=="check-admin" (
  echo Checking admin users:
  psql -U postgres -d bantrhaus -c "SELECT id, username, email FROM users WHERE username='admin';"
  goto end
)

if "%1"=="add-admin" (
  echo Adding is_admin column if it doesn't exist:
  psql -U postgres -d bantrhaus -c "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;"
  echo Setting admin flag for the admin user:
  psql -U postgres -d bantrhaus -c "UPDATE users SET is_admin = TRUE WHERE username = 'admin';"
  goto end
)

if "%1"=="rename-db" (
  echo Disconnecting all users from old database:
  psql -U postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='project_alpha';"
  echo Renaming database to bantrhaus:
  psql -U postgres -c "ALTER DATABASE project_alpha RENAME TO bantrhaus;"
  goto end
)

if "%1"=="show-tables" (
  echo Listing all tables in bantrhaus database:
  psql -U postgres -d bantrhaus -c "\dt"
  goto end
)

if "%1"=="query" (
  echo Running custom query: %2
  psql -U postgres -d bantrhaus -c "%2"
  goto end
)

if "%1"=="shell" (
  echo Opening PostgreSQL shell:
  psql -U postgres -d bantrhaus
  goto end
)

echo Available commands:
echo   db-tools list         - List all databases
echo   db-tools check-admin  - Check admin users
echo   db-tools add-admin    - Add is_admin column and set admin flag
echo   db-tools rename-db    - Rename project_alpha to bantrhaus
echo   db-tools show-tables  - Show all tables in database
echo   db-tools query "SQL"  - Run a custom SQL query
echo   db-tools shell        - Open PostgreSQL shell

:end
set PGPASSWORD=
