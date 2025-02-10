/**
 * Main Server File
 * 
 * This Express server handles user authentication (login, logout), 
 * user management (admin-only CRUD operations), and password resets.
 * 
 * Note: This code uses email as the unique identifier for users.
 */

const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const mysql = require('mysql2/promise'); // Using the promise API for MySQL
const bcrypt = require('bcryptjs');

// Use an absolute path for the .env file
require('dotenv').config({ path: "C:/Users/S569652/Documents/INADS/Website/INADS/.env" });

const app = express();
const PORT = process.env.PORT || 3000;

// Create a MySQL connection pool using environment variables (or defaults)
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'INADS'
});

// Immediately check if the database connection works
(async () => {
    try {
        await db.getConnection();
        console.log("Successfully connected to the database.");
    } catch (error) {
        console.error("Database connection failed:", error.message);
        process.exit(1); // Exit the process if unable to connect
    }
})();

// ---------------------
// Global Middleware
// ---------------------

// Cache Control Middleware: Prevent caching on all dynamic responses
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    next();
});

// Serve static files from the "public" folder (e.g., HTML, CSS, client JS)
app.use(express.static(path.join(__dirname, '../public')));

// Parse URL-encoded form data and JSON bodies
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Session Middleware configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'secret-key', // Use an env variable in production
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,  // Set to true when using HTTPS
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 1 // Session expires after 1 hour
    }
}));

// ---------------------
// Routes
// ---------------------

// Root Route: Render the login page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

/**
 * User Login
 * POST /api/auth/login
 * Expects: { email, password } in the request body.
 * On success, sets session variables and redirects to the appropriate dashboard.
 */
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Fetch user by email from the database
        const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) {
            // Respond with a generic message to avoid user enumeration
            return res.status(401).json({ success: false, message: "Invalid email or password" });
        }

        const user = rows[0];

        // Compare the provided password with the stored hashed password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, message: "Invalid email or password" });
        }

        // Set session data for the authenticated user
        req.session.user = user.email;
        req.session.role = user.role;
        await new Promise((resolve) => req.session.save(resolve));

        // Instead of redirecting, send JSON with success and a redirect URL
        const redirectUrl = user.role === 'admin' ? '/admin-dashboard' : '/dashboard';
        return res.json({ success: true, redirect: redirectUrl });
    } catch (error) {
        console.error("Error during login:", error);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});

/**
 * Dashboard Route for Regular Users
 * GET /dashboard
 */
app.get('/dashboard', (req, res) => {
    if (req.session.user && req.session.role === 'user') {
        return res.sendFile(path.join(__dirname, '../public/dashboard.html'));
    }
    return res.redirect('/');
});

/**
 * Admin Dashboard Route
 * GET /admin-dashboard
 */
app.get('/admin-dashboard', (req, res) => {
    if (req.session.user && req.session.role === 'admin') {
        return res.sendFile(path.join(__dirname, '../public/admin_dashboard.html'));
    }
    return res.redirect('/');
});

/**
 * User Management Page (Admin Only)
 * GET /user-management
 */
app.get('/user-management', (req, res) => {
    if (req.session.user && req.session.role === 'admin') {
        return res.sendFile(path.join(__dirname, '../public/user_management.html'));
    }
    return res.redirect('/');
});

/**
 * Get All Users (Admin Only)
 * GET /api/admin/get-users
 * Returns a JSON array of user objects.
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
 * DELETE /api/admin/delete-user/:email
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
 * POST /api/admin/add-user
 * Expects: { email, password, role } in the request body.
 */
app.post('/api/admin/add-user', async (req, res) => {
    if (!req.session.user || req.session.role !== "admin") {
        return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    const { email, password, role } = req.body;

    try {
        // Check if a user with the provided email already exists
        const [existingUser] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);
        if (existingUser.length > 0) {
            return res.status(400).json({ success: false, message: "User with this email already exists" });
        }

        // Hash the provided password before storing
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
 * PUT /api/admin/edit-user
 * Expects: { email, password (optional), role } in the request body.
 */
app.put('/api/admin/edit-user', async (req, res) => {
    const { email, password, role } = req.body;

    if (!req.session.user || req.session.role !== 'admin') {
        return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    try {
        if (password) {
            // If a new password is provided, hash it before updating
            const hashedPassword = await bcrypt.hash(password, 10);
            await db.execute('UPDATE users SET password = ?, role = ? WHERE email = ?', [hashedPassword, role, email]);
        } else {
            // Only update the user's role if no new password is provided
            await db.execute('UPDATE users SET role = ? WHERE email = ?', [role, email]);
        }
        return res.status(200).send('User updated successfully!');
    } catch (error) {
        console.error('Error updating user:', error);
        return res.status(500).send('Error updating user');
    }
});

/**
 * User Logout
 * GET /logout
 * Destroys the user session and redirects to the login page.
 */
app.get('/logout', (req, res) => {
    if (req.session) {
        req.session.destroy((err) => {
            if (err) {
                console.error("Error destroying session:", err);
                return res.status(500).send("Logout failed.");
            }
            res.clearCookie('connect.sid'); // Remove session cookie
            return res.redirect('/');
        });
    } else {
        return res.redirect('/');
    }
});

/**
 * Forgot Password
 * POST /forgot-password
 * Expects: { email } in the request body.
 * For security, always respond with the same message regardless of whether the email exists.
 */
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        // Query the user by email (this is used only to mimic the process)
        await db.execute('SELECT * FROM users WHERE email = ?', [email]);

        // Always return the same message to prevent email enumeration
        return res.send(`
            <h2>If the email exists, a reset link has been sent.</h2>
        `);
    } catch (error) {
        console.error('Error handling forgot password:', error);
        return res.status(500).send('Internal server error');
    }
});

/**
 * Render the Reset Password Form
 * GET /reset-password/:email
 * This route displays a form for the user to input a new password.
 */
app.get('/reset-password/:email', (req, res) => {
    const email = req.params.email;

    // Render a simple HTML form for password reset
    return res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
            <title>Reset Password</title>
            <style>
                body {
                    background-color: #0f0f0f;
                    color: #e0e0e0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    font-family: Arial, sans-serif;
                }
                .card {
                    background-color: #1e1e1e;
                    border-radius: 10px;
                    padding: 30px;
                    width: 100%;
                    max-width: 400px;
                }
                .btn-primary {
                    background-color: #00c853;
                    border: none;
                }
                .btn-primary:hover {
                    background-color: #009624;
                }
            </style>
        </head>
        <body>
            <div class="card">
                <h3 class="text-center"><i class="fas fa-key"></i> Reset Password</h3>
                <form action="/reset-password/${encodeURIComponent(email)}" method="POST">
                    <div class="form-group">
                        <label for="password">Enter your New Password:</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary btn-block">Reset Password</button>
                </form>
            </div>
        </body>
        </html>
    `);
});

/**
 * Handle Reset Password Submission
 * POST /reset-password/:email
 * Expects: { password } in the request body.
 */
app.post('/reset-password/:email', async (req, res) => {
    const email = req.params.email;
    const { password } = req.body;

    try {
        // Hash the new password before storing it in the database
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update the user's password based on their email
        const [result] = await db.execute('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);

        if (result.affectedRows === 0) {
            console.error(`No user found with email: ${email}`);
            return res.status(404).send("User not found.");
        }

        console.log(`Password reset successfully for ${email}`);

        // Respond with a success page
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
 * Test Database Connection
 * GET /test-db
 * Returns a simple confirmation message if the connection works.
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

// ---------------------
// Start the Server
// ---------------------

app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});

console.log({
    DB_HOST: process.env.DB_HOST,
    DB_USER: process.env.DB_USER,
    DB_PASS: process.env.DB_PASS,
    DB_NAME: process.env.DB_NAME
  });
  
