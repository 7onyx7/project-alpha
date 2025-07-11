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
This project is licensed under a proprietary license. See the [LICENSE](LICENSE) file for details.

## Deployment

### Heroku Deployment
1. Create a Heroku account at [heroku.com](https://heroku.com)
2. Install the Heroku CLI and login:
   ```bash
   npm install -g heroku
   heroku login
   ```
3. Initialize a Git repository (if not already done):
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   ```
4. Create a Heroku app:
   ```bash
   heroku create project-alpha-app-unique-name
   ```
5. Add the PostgreSQL add-on:
   ```bash
   heroku addons:create heroku-postgresql:hobby-dev
   ```
6. Set your JWT secret:
   ```bash
   heroku config:set JWT_SECRET=your_secure_jwt_secret_here
   ```
7. Push your code to Heroku:
   ```bash
   git push heroku main
   ```
8. Access your app at the provided Heroku URL.

### CDN Setup
Follow the instructions in [cdn-setup-guide.md](cdn-setup-guide.md) to set up a CDN for your static assets.

### SSL/HTTPS
Heroku automatically provides SSL certificates for all apps on the `*.herokuapp.com` domain. If you're using a custom domain, follow Heroku's instructions to add your own SSL certificate.

### Database Scaling
If you need to scale your database:
1. Upgrade your PostgreSQL plan in the Heroku dashboard
2. Consider implementing connection pooling
3. Optimize your queries and add appropriate indexes

### Monitoring
1. Enable application monitoring:
   ```bash
   heroku addons:create newrelic:wayne
   ```
2. Set up Sentry for error tracking (already configured in the code)
