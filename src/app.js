/**
 * app.js
 * 
 * Main Server File for INADS with MFA and improved password reset.
 * 
 * Features:
 * - User authentication with MFA (via email or TOTP).
 * - Password validation: must be at least 8 characters, start with an uppercase letter,
 *   and contain at least one digit and one special character.
 * - Secure forgot password flow using a reset token stored in the database.
 * - Secure reset password flow using the reset token.
 * 
 * Note: This code uses email as the unique identifier.
 */

const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const speakeasy = require('speakeasy');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit'); // For rate limiting

// Load environment variables from .env
require('dotenv').config({
  path: "/Users/akashthanneeru/Desktop/INADS_Repo/INADS/.env"
});

const app = express();
const PORT = process.env.PORT || 3000;

// Create MySQL connection pool
const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'INADS'
});

(async () => {
  try {
    await db.getConnection();
    console.log("Successfully connected to the database.");
  } catch (error) {
    console.error("Database connection failed:", error.message);
    process.exit(1);
  }
})();

// Configure Nodemailer transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT || 587,
  secure: false, // true for port 465, false for others
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// Password Validation Function
function validatePassword(password) {
  // Must be at least 8 characters, start with an uppercase letter,
  // contain at least one digit and one special character.
  const regex = /^(?=[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{8,}$/;
  return regex.test(password);
}

// Global Middleware
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  next();
});
app.use(express.static(path.join(__dirname, '../public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // set to true if using HTTPS
    httpOnly: true,
    maxAge: 1000 * 60 * 60 //1 hour
  }
}));

// Rate Limiter for Forgot Password endpoint
const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per window
  message: "Too many password reset requests from this IP, please try again after 15 minutes."
});

// Routes

// Render Login Page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

/**
 * User Login with MFA Support
 */
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      return res.status(401).json({ success: false, message: "Invalid email or password" });
    }
    const user = rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: "Invalid email or password" });
    }
    // Validate password requirements (if desired)
    if (!validatePassword(password)) {
      return res.status(400).json({ success: false, message: "Password does not meet security requirements." });
    }
    // If MFA is enabled, generate MFA code
    if (user.mfa_enabled) {
      req.session.tempUser = { email: user.email, role: user.role };
      if (user.mfa_type === 'email') {
        const mfaCode = Math.floor(100000 + Math.random() * 900000).toString();
        req.session.mfa = { code: mfaCode, expires: Date.now() + 5 * 60 * 1000 };
        await transporter.sendMail({
          from: process.env.SMTP_FROM || 'no-reply@example.com',
          to: user.email,
          subject: 'Your INADS MFA Code',
          text: `Your one-time MFA code is: ${mfaCode}`
        });
        return res.json({ success: true, mfa: true, redirect: "/mfa.html" });
      }
    }
   
    // If MFA is not enabled, complete login
    req.session.user = user.email;
    req.session.role = user.role;
    return res.json({ success: true, redirect: user.role === 'admin' ? '/admin-dashboard' : '/dashboard' });
  } catch (error) {
    console.error("Error during login:", error);
    return res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

/**
 * MFA Verification Endpoint
 * Verifies the MFA code and returns role for routing.
 */

    if (verified) {
      req.session.user = req.session.tempUser.email;
      req.session.role = req.session.tempUser.role;
      req.session.tempUser = null;
      req.session.mfa = null;
      return res.json({ success: true, role: req.session.role, message: "OTP verified successfully!" });
    } else {
      return res.status(400).json({ success: false, message: "Invalid authenticator code." });
    }
  } else {
    return res.status(400).json({ success: false, message: "No MFA process found." });
  }
});

/**
 * Resend MFA Code Endpoint
 */
app.post('/api/auth/resend-mfa', async (req, res) => {
  const { email } = req.body;
  try {
    if (!req.session.tempUser || req.session.tempUser.email !== email) {
      return res.json({ success: false, message: "No pending MFA for this email." });
    }
    const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      return res.json({ success: false, message: "User not found." });
    }
    const mfaCode = Math.floor(100000 + Math.random() * 900000).toString();
    req.session.mfa = { code: mfaCode, expires: Date.now() + 5 * 60 * 1000 };
    await transporter.sendMail({
      from: process.env.SMTP_FROM || 'no-reply@example.com',
      to: email,
      subject: 'Your INADS MFA Code (Resent)',
      text: `Your new one-time MFA code is: ${mfaCode}`
    });
    return res.json({ success: true, message: "A new MFA code has been sent to your email." });
  } catch (err) {
    console.error('Error resending MFA:', err);
    return res.json({ success: false, message: "Failed to resend code." });
  }
});

/**
 * GET /forgot-password
 * Serves the Forgot Password page.
 */
app.get('/forgot-password', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/forgot-password.html'));
});

/**
 * POST /forgot-password
 * Generates a reset token, stores it in the user's record, and sends a reset link via email.
 * Rate limiting is applied.
 */
app.post('/forgot-password', forgotPasswordLimiter, async (req, res) => {
  const { email } = req.body;
  const message = `<h2>If the email exists, a reset link has been sent.</h2>`;
  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      return res.send(message);
    }
    const token = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + 3600000; // 1 hour expiry
    await db.execute('UPDATE users SET reset_token = ?, reset_expires = ? WHERE email = ?', [token, expires, email]);
    const resetUrl = `${req.protocol}://${req.get('host')}/reset-password/${token}`;
    await transporter.sendMail({
      from: process.env.SMTP_FROM || 'no-reply@example.com',
      to: email,
      subject: 'INADS Password Reset',
      text: `You have requested a password reset. Click the following link to reset your password: ${resetUrl}\n\nIf you did not request this, please ignore this email.`
    });
    return res.send(message);
  } catch (error) {
    console.error('Error in /forgot-password:', error);
    return res.status(500).send('Internal server error');
  }
});

/**
 * GET /reset-password/:token
 * Renders a reset password form if the token is valid.
 */
app.get('/reset-password/:token', async (req, res) => {
  const token = req.params.token;
  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE reset_token = ? AND reset_expires > ?', [token, Date.now()]);
    if (rows.length === 0) {
      return res.send('<h2>Reset link is invalid or expired.</h2>');
    }
    return res.sendFile(path.join(__dirname, '../public/reset_password.html'));
  } catch (error) {
    console.error('Error fetching reset token:', error);
    return res.status(500).send('Internal server error');
  }
});

/**
 * POST /reset-password/:token
 * Updates the user's password if the reset token is valid.
 */
app.post('/reset-password/:token', async (req, res) => {
  const token = req.params.token;
  const { password } = req.body;
  if (!validatePassword(password)) {
    return res.status(400).send("Password must be at least 8 characters long, start with an uppercase letter, and contain at least one digit and one special character.");
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await db.execute(
      'UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE reset_token = ? AND reset_expires > ?',
      [hashedPassword, token, Date.now()]
    );
    if (result.affectedRows === 0) {
      //invalid reset link
      return res.send('<h2>Reset link is invalid or has expired.</h2>');
    }
    return res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <title>Password Reset Success</title>
      </head>
      <body style="background-color: #0f0f0f; color: #e0e0e0; text-align: center; padding-top: 100px; font-family: Arial, sans-serif;">
        <h2>Password has been reset successfully!</h2>
        <p>You can now <a href="/" style="color: #00c853;">log in</a> with your new password.</p>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('Error resetting password:', error);
    return res.status(500).send('Internal server error');
  }
});

/**
 * Dashboard Route for Regular Users
 */
app.get('/dashboard', (req, res) => {
  if (req.session.user && req.session.role === 'user') {
    return res.sendFile(path.join(__dirname, '../public/dashboard.html'));
  }
  return res.redirect('/');
});

/**
 * Admin Dashboard Route
 */
app.get('/admin-dashboard', (req, res) => {
  if (req.session.user && req.session.role === 'admin') {
    return res.sendFile(path.join(__dirname, '../public/admin_dashboard.html'));
  }
  return res.redirect('/');
});

/**
 * User Management Page (Admin Only)
 */
app.get('/user-management', (req, res) => {
  if (req.session.user && req.session.role === 'admin') {
    return res.sendFile(path.join(__dirname, '../public/user_management.html'));
  }
  return res.redirect('/');
});

/**
 * Get All Users (Admin Only)
 */
app.get('/api/admin/get-users', async (req, res) => {
  if (!req.session.user || req.session.role !== "admin") {
    return res.status(403).json({ success: false, message: "Unauthorized" });
  }
  try {
    const [rows] = await db.execute("SELECT id, email, role FROM users");
    return res.json(rows);
  } catch (error) {
    console.error("Error fetching users:", error);
    return res.status(500).json({ success: false, message: "Error fetching users" });
  }
});

/**
 * Delete a User (Admin Only)
 */
app.delete('/api/admin/delete-user/:email', async (req, res) => {
  const { email } = req.params;
  if (!req.session.user || req.session.role !== 'admin') {
    return res.status(403).json({ success: false, message: "Unauthorized" });
  }
  try {
    const [result] = await db.execute('DELETE FROM users WHERE email = ?', [email]);
    if (result.affectedRows > 0) {
      return res.status(200).send('User deleted successfully!');
    } else {
      return res.status(404).send('User not found');
    }
  } catch (error) {
    console.error('Error deleting user:', error);
    return res.status(500).send('Error deleting user');
  }
});

/**
 * Add a New User (Admin Only)
 */
app.post('/api/admin/add-user', async (req, res) => {
  if (!req.session.user || req.session.role !== "admin") {
    return res.status(403).json({ success: false, message: "Unauthorized" });
  }
  const { email, password, role } = req.body;
  if (!validatePassword(password)) {
    return res.status(400).json({ success: false, message: "Password must be at least 8 characters long, start with an uppercase letter, and contain at least one digit and one special character." });
  }
  try {
    const [existingUser] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);
    if (existingUser.length > 0) {
      return res.status(400).json({ success: false, message: "User with this email already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.execute("INSERT INTO users (email, password, role) VALUES (?, ?, ?)", [email, hashedPassword, role]);
    return res.status(201).json({ success: true, message: "User registered successfully!" });
  } catch (error) {
    console.error("Error adding user:", error);
    return res.status(500).json({ success: false, message: "Error adding user" });
  }
});

/**
 * Edit an Existing User (Admin Only)
 */
app.put('/api/admin/edit-user', async (req, res) => {
  const { email, password, role } = req.body;
  if (!req.session.user || req.session.role !== 'admin') {
    return res.status(403).json({ success: false, message: "Unauthorized" });
  }
  try {
    if (password) {
      if (!validatePassword(password)) {
        return res.status(400).json({ success: false, message: "Password must be at least 8 characters long, start with an uppercase letter, and contain at least one digit and one special character." });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      await db.execute('UPDATE users SET password = ?, role = ? WHERE email = ?', [hashedPassword, role, email]);
    } else {
      await db.execute('UPDATE users SET role = ? WHERE email = ?', [role, email]);
    }
    return res.status(200).send('User updated successfully!');
  } catch (error) {
    console.error('Error updating user:', error);
    return res.status(500).send('Error updating user');
  }
});

/**
 * Test Database Connection
 */
app.get('/test-db', async (req, res) => {
  try {
    await db.execute('SELECT 1');
    return res.send('Database connection is working!');
  } catch (error) {
    console.error('Database connection error:', error);
    return res.status(500).send('Database connection failed');
  }
});
// Load environment variables from .env


// Start the server
app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});

console.log({
  DB_HOST: process.env.DB_HOST,
  DB_USER: process.env.DB_USER,
  DB_PASS: process.env.DB_PASS,
  DB_NAME: process.env.DB_NAME
});
