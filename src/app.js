const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const mysql = require('mysql2/promise'); // Import mysql2 library

const app = express();
const PORT = process.env.PORT || 3000;

// MySQL Database Connection to localhost
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'Catsanddogs#666', // Replace with your MySQL root password
    database: 'INADS' // Replace with your database name
});

// Middleware
app.use(bodyParser.urlencoded({ extended: false })); // Parse form data
app.use(express.static(path.join(__dirname, '../public'))); // Serve static files

// Middleware to handle both URL-encoded and JSON data
app.use(bodyParser.urlencoded({ extended: true })); // Parse URL-encoded form data
app.use(bodyParser.json()); // Parse JSON data


// Session Middleware
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// Root route - Login page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Handle login form submission
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Fetch user data from the Database
        const [rows] = await db.execute('SELECT * FROM users WHERE username = ? AND password = ?', [username, password]);
        if (rows.length > 0) {
            const user = rows[0];
            // Store user details in the session
            req.session.user = username; 
            req.session.role = user.role; 

            // Route based on user role
            if (user.role === 'admin') {
                res.redirect('/admin-dashboard'); // Redirect to admin dashboard for admin users
            } else {
                res.redirect('/dashboard'); // Redirect to dashboard for regular users
            }
        } else {
            res.redirect('/?error=Invalid credentials'); // Redirect with error message
        }
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).send('Internal server error');
    }
});

// Handle user registration (Admin use only)
app.post('/api/admin/add-user', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Insert new user into the database
        await db.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, password, 'user']);
        res.status(201).send('User registered successfully!');
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).send('Error registering user');
    }
});

// Dashboard route (for regular users)
app.get('/dashboard', (req, res) => {
    if (req.session.user && req.session.role === 'user') {
        res.sendFile(path.join(__dirname, '../public/dashboard.html'));
    } else {
        res.redirect('/');
    }
});

// Admin Dashboard route (for admins only)
app.get('/admin-dashboard', (req, res) => {
    if (req.session.user && req.session.role === 'admin') {
        res.sendFile(path.join(__dirname, '../public/admin_dashboard.html'));
    } else {
        res.redirect('/');
    }
});

// User Management route (for admins only)
app.get('/user-management', (req, res) => {
    if (req.session.user && req.session.role === 'admin') {
        res.sendFile(path.join(__dirname, '../public/user_management.html'));
    } else {
        res.redirect('/');
    }
});

// Get all users (Admin use only)
app.get('/api/admin/get-users', async (req, res) => {
    if (req.session.user && req.session.role === 'admin') {
        try {
            const [rows] = await db.execute('SELECT username, role FROM users');
            res.json(rows);
        } catch (error) {
            console.error('Error fetching users:', error);
            res.status(500).send('Error fetching users');
        }
    } else {
        res.redirect('/');
    }
});

// Delete user (Admin use only)
app.delete('/api/admin/delete-user/:username', async (req, res) => {
    const { username } = req.params;

    if (req.session.user && req.session.role === 'admin') {
        try {
            const [result] = await db.execute('DELETE FROM users WHERE username = ?', [username]);
            
            if (result.affectedRows > 0) {
                res.status(200).send('User deleted successfully!');
            } else {
                res.status(404).send('User not found');
            }
        } catch (error) {
            console.error('Error deleting user:', error);
            res.status(500).send('Error deleting user');
        }
    } else {
        res.status(403).send('Forbidden: Unauthorized user');
    }
});


// Handle user registration (Admin use only)
app.post('/api/admin/add-user', async (req, res) => {
    const { username, password, role } = req.body;

    try {
        // Insert new user into the database
        await db.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, password, role]);
        res.status(201).send('User registered successfully!');
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).send('Error registering user');
    }
});

// Edit user (Admin use only)
app.put('/api/admin/edit-user', async (req, res) => {
    const { username, password, role } = req.body;

    if (req.session.user && req.session.role === 'admin') {
        try {
            if (password) {
                // Update both role and password if provided
                await db.execute('UPDATE users SET password = ?, role = ? WHERE username = ?', [password, role, username]);
            } else {
                // Update role only if password is not provided
                await db.execute('UPDATE users SET role = ? WHERE username = ?', [role, username]);
            }
            res.status(200).send('User updated successfully!');
        } catch (error) {
            console.error('Error updating user:', error);
            res.status(500).send('Error updating user');
        }
    } else {
        res.redirect('/');
    }
});

// Logout route
app.get('/logout', (req, res) => {
    if (req.session) {
        req.session.destroy((err) => {
            if (err) {
                return res.status(500).send('Unable to log out');
            }
            res.redirect('/');
        });
    } else {
        res.redirect('/');
    }
});

// Handle forgot password form submission
app.post('/forgot-password', async (req, res) => {
    const { username } = req.body;

    try {
        // Check if the user exists in the database
        const [rows] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);

        if (rows.length > 0) {
            // If the user exists, redirect to the reset password page
            res.redirect(`/reset-password/${username}`);
        } else {
            // If user does not exist, re-render the forgot password page with an error message
            res.send(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
                    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
                    <link rel="stylesheet" href="style.css">
                    <title>Forgot Password</title>
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
                        <h3 class="text-center"><i class="fas fa-unlock-alt"></i> Forgot Password</h3>
                        
                        <!-- Error message alert -->
                        <div class="alert alert-danger" role="alert">
                            User not found. Please try again.
                        </div>

                        <form action="/forgot-password" method="POST">
                            <div class="form-group">
                                <label for="username">Enter your Username:</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <button type="submit" class="btn btn-primary btn-block">Submit</button>
                        </form>
                    </div>
                </body>
                </html>
            `);
        }
    } catch (error) {
        console.error('Error handling forgot password:', error);
        res.status(500).send('Internal server error');
    }
});

// Serve the reset password form and handle reset submission in one consistent route
app.get('/reset-password/:username', (req, res) => {
    const username = req.params.username;

    res.send(`
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
                <form action="/reset-password/${username}" method="POST">
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

// Handle reset password form submission
app.post('/reset-password/:username', async (req, res) => {
    const { username } = req.params;
    const { password } = req.body;

    try {
        // Update the user's password in the database
        await db.execute('UPDATE users SET password = ? WHERE username = ?', [password, username]);
        res.send(`
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
        res.status(500).send('Error resetting password');
    }
});



// Serve the forgot password form
app.get('/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/forgot_password.html')); // Corrected path
});

// Serve the reset password form
app.get('/reset-password/:username', (req, res) => {
    const username = req.params.username;

    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Reset Password</title>
        </head>
        <body>
            <h2>Reset Password</h2>
            <form action="/reset-password" method="POST">
                <input type="hidden" name="username" value="${username}" />
                <label for="password">Enter new password:</label>
                <input type="password" id="password" name="password" required>
                <button type="submit">Reset Password</button>
            </form>
        </body>
        </html>
    `);
});

// Handle reset password form submission
app.post('/reset-password', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Update the user's password in the database
        await db.execute('UPDATE users SET password = ? WHERE username = ?', [password, username]);
        res.send('Password has been reset successfully. You can now log in with your new password.');
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).send('Error resetting password');
    }
});

// Test Database Connection
app.get('/test-db', async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT 1');
        res.send('Database connection is working!');
    } catch (error) {
        console.error('Database connection error:', error);
        res.status(500).send('Database connection failed');
    }
});


// Cache Control
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    next();
});


// Start the server
app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});
