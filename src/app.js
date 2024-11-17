const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session'); // Import session middleware

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: false })); // Parse form data
app.use(express.static(path.join(__dirname, '../public'))); // Serve static files

// Session Middleware
app.use(session({
    secret: 'secret-key', // A secret key used to sign the session ID cookie
    resave: false, // Prevents the session from being saved back to the session store if it wasn't modified
    saveUninitialized: true, // Saves new sessions that haven't been modified
    cookie: { secure: false } // Set to true if using HTTPS
}));

// Root route - Login page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Handle login form submission
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;

    // Hardcoded credentials for now
    const mockUsername = 'admin';
    const mockPassword = 'password123';

    if (username === mockUsername && password === mockPassword) {
        req.session.user = username; // Store user session
        res.redirect('/dashboard'); // Redirect to the dashboard after successful login
    } else {
        res.status(401).send('<h1>Invalid credentials</h1>'); // Unauthorized response
    }
});

// Dashboard route
app.get('/dashboard', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, '../public/dashboard.html'));
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
            res.redirect('/'); // Redirect to the login page after logging out
        });
    } else {
        res.redirect('/');
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});
