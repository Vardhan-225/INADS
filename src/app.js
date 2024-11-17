const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: false })); // Parse form data
app.use(express.static(path.join(__dirname, '../public'))); // Serve static files

// Root route
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
        res.send('<h1>Login successful!</h1>'); // Temporary success message
    } else {
        res.status(401).send('<h1>Invalid credentials</h1>'); // Unauthorized
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});
