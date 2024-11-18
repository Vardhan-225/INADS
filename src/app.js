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
        // Fetch user data from the database
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
app.delete('/api/admin/delete-user', async (req, res) => {
    const { username } = req.query;

    if (req.session.user && req.session.role === 'admin') {
        try {
            await db.execute('DELETE FROM users WHERE username = ?', [username]);
            res.status(200).send('User deleted successfully!');
        } catch (error) {
            console.error('Error deleting user:', error);
            res.status(500).send('Error deleting user');
        }
    } else {
        res.redirect('/');
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
