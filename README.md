# Authentication Workflow API

A complete authentication system built with Node.js, Express, and MongoDB, featuring email verification and password reset functionality.

## Features

- User registration with email verification
- JWT-based authentication
- Password reset functionality
- Email notifications
- Secure password handling
- Cookie-based authentication
- Profile management

## Prerequisites

Before you begin, ensure you have met the following requirements:

- Node.js installed (v14.0.0 or higher)
- MongoDB Atlas account for database
- Gmail account for sending emails (with App Password configured)

## Installation

1. Clone the repository:

```bash
    git clone https://github.com/tarifi79/Auth-Workflow
    cd auth-workflow
```

2. Install dependencies:

```bash
    npm install
```

3. Create a .env file in the root directory:

```javascript
    PORT=3000
    MONGOD_URI=mongodb+srv://<username>:<password>@cluster0.xxxxx.mongodb.net/your-database-name
    JWT_SECRET=your_super_secret_key_here
    EMAIL_USER=your.email@gmail.com
    EMAIL_PASS=your_app_password
    NODE_ENV=development
```

4. Run the app

```bash
    npm start
```

## MongoDB Atlas Setup

1. Create a MongoDB Atlas account at https://www.mongodb.com/cloud/atlas
2. Create a new cluster (free tier available)
3. Click "Connect" on your cluster
4. Choose "Connect your application"
5. Copy the connection string
6. Replace `<username>`, `<password>`, and `your-database-name` with your values
7. Ensure your IP address is whitelisted in Atlas Network Acces

## API Endpoints

### Authentication Routes

```plaintext
    POST /api/v1/auth/register
    - Register a new user
    - Body: { name, email, password }

    POST /api/v1/auth/login
    - Login user
    - Body: { email, password }

    GET /api/v1/auth/logout
    - Logout user

    POST /api/v1/auth/forgot-password
    - Request password reset
    - Body: { email }

    PATCH /api/v1/auth/reset-password/:token
    - Reset password using token
    - Body: { password }

    GET /api/v1/auth/verify/:token
    - Verify email address

    POST /api/v1/auth/resend-verification
    - Resend verification email
    - Body: { email }
```

### Protected Routes (Require Authentication)

```plaintext
    GET /api/v1/auth/current-user
    - Get current user profile

    PATCH /api/v1/auth/update-user
    - Update user profile
    - Body: { name, email }

    PATCH /api/v1/auth/change-password
    - Change password
    - Body: { currentPassword, newPassword }
```

## Authentication Flow

### Registration

- User registers with email and password
- Verification email is sent
- Account is created but marked as unverified

### Email Verification

- User clicks verification link in email
- Account is marked as verified
- User can now login

### Password Reset

- User requests password reset
- Reset link is sent to email
- User sets new password using the link

## Error Handling

The API uses consistent error handling and returns responses in the following format:

```javascript
    // Success Response
    {
        "status": "success",
        "data": {
            // response data
        }
    }

    // Error Response
    {
        "status": "fail",
        "message": "Error message here"
    }
```

## Security Features

- Passwords are hashed using bcrypt
- JWT tokens for authentication
- HTTP-only cookies
- Email verification required
- Password strength validation

## Security Packages

### Rate Limiting

- General API: 100 requests per 15 minutes
- Auth endpoints: 5 attempts per hour for login and password reset

### Security Headers (Helmet)

- Protection against common web vulnerabilities
- Secure HTTP headers

### CORS

- Configured for cross-origin requests
- Secure cookie handling

### XSS Protection

- Sanitizes user input
- Prevents cross-site scripting attacks

## Project Structure

```plaintext
auth-workflow/
├── .env
├── .gitignore
├── package.json
├── README.md
├── server.js
├── controllers/
│   └── authController.js
├── models/
│   └── User.js
├── middleware/
│   ├── auth.js
│   └── errorHandler.js
├── routes/
│   └── authRoutes.js
└── utils/
    ├── AppError.js
    ├── emailService.js
    └── tokenService.js

```

## Contact

Mohammed Darras - tarifi79@gmail.com,
Project Link: https://github.com/tarifi79/Auth-Workflow
