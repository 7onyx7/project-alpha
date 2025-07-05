# Project Alpha

## Description
A production-ready real-time chat application with room pairing, message persistence, and robust user management.

## Features
- Real-time messaging using Socket.IO
- Automatic room pairing (2 users per room)
- Message persistence with PostgreSQL
- Tab switching and reconnection handling
- Secure authentication with JWT
- Input sanitization and CSRF protection
- Rate limiting and security headers

## Setup

### Prerequisites
- Node.js (v16 or higher)
- PostgreSQL

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/project-alpha.git
   ```
2. Navigate to the project directory:
   ```bash
   cd project-alpha
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Set up the database:
   - Create a PostgreSQL database.
   - Add your database credentials to a `.env` file:
     ```plaintext
     DB_USER=yourusername
     DB_PASSWORD=yourpassword
     DB_HOST=localhost
     DB_NAME=project_alpha
     DB_PORT=5432
     JWT_SECRET=yourjwtsecret
     ```
5. Start the server:
   ```bash
   npm start
   ```

### Usage
1. Open your browser and navigate to `http://localhost:3000`.
2. Register or log in to start chatting.
3. Join a room and start messaging.

## Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request with a detailed description of your changes.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
