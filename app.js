const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
require('dotenv').config();
const expressLayouts = require('express-ejs-layouts'); // Import layouts middleware
const authRoutes = require('./routes/auth'); // Import the routes from auth.js
const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL Database Connection
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: 5432,
    ssl: { rejectUnauthorized: false },
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(
    session({
        secret: 'yourSecretKey',
        resave: false,
        saveUninitialized: false,
    })
);

// Enable EJS layouts
app.use(expressLayouts);
app.set('layout', 'layout'); // Set default layout file to 'layout.ejs'

// Set EJS as the templating engine
app.set('view engine', 'ejs');

// ------ Middleware ------//

//Pass `email` to all views
app.use((req, res, next) => {
    res.locals.email = req.session.email || null;
    next();
});

//pass registration success/error message to all views
app.use((req, res, next) => {
    res.locals.successMessage = req.session.successMessage;
    res.locals.errorMessage = req.session.errorMessage;
    delete req.session.successMessage;
    delete req.session.errorMessage;
    next();
});

// ------ Import the QBO auth routes ------ //
app.use('/', authRoutes);


// ------ User Routes ------ //

//Root Route
app.get('/', (req, res) => {
    // Pass req.query.message to the template
    res.render('index', { message: req.query.message });
});

//Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.render('index', { message: 'Invalid email or password.' });
        }

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.render('index', { message: 'Invalid email or password.' });
        }

        req.session.userId = user.id;
        req.session.email = user.email;
        res.redirect('/account');
    } catch (err) {
        console.error(err);
        res.render('index', { message: 'An error occurred. Please try again.' });
    }
});

// Logout Route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error during logout:', err.message);
            return res.status(500).send('Error logging out.');
        }
        res.redirect('/?message=logout'); // Redirect to the homepage
    });
});

// Register Route
app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        req.session.errorMessage = 'Email and password are required.';
        return res.redirect('/');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10); // Hash the password
        const client = await pool.connect();
        await client.query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2)',
            [email, hashedPassword]
        );
        client.release();

        // Store the success message in the session
        req.session.successMessage = 'User registered successfully. Please login.';
    } catch (err) {
        if (err.code === '23505') { // Unique constraint violation
            req.session.errorMessage = 'Email is already registered.';
        } else {
            console.error('Error registering user:', err.message);
            req.session.errorMessage = 'Internal server error. Please try again later.';
        }
    }

    // Redirect to the root route
    res.redirect('/');
});



// Account Route
// Authentication middleware
const isAuthenticated = (req, res, next) => {
    if (!req.session.userId) {
        // If not logged in, redirect to the login page
        return res.redirect('/');
    }
    next(); // If logged in, proceed to the account page
};

// Account Route - Apply the isAuthenticated middleware
app.get('/account', isAuthenticated, async (req, res) => {
    const userId = req.session.userId; 

    try {
        const client = await pool.connect();
        const result = await client.query('SELECT * FROM user_tokens WHERE user_id = $1', [userId]);

        if (result.rows.length > 0) {
            const lastRefresh = result.rows[0].last_refresh; 
            // User is connected to QuickBooks
            res.render('account', { 
                isConnected: true, 
                email: req.session.email, 
                lastRefresh: lastRefresh,
                message: req.query.message,
                status: req.query.status
            });
        } else {
            // User is not connected to QuickBooks
            res.render('account', { 
                isConnected: false, 
                email: req.session.email,
                message: req.query.message,
                status: req.query.status
            });
        }

        client.release();
    } catch (err) {
        console.error('Error fetching user token:', err);
        res.render('account', {
            isConnected: false,
            email: req.session.email,
            message: 'Error checking connection status.',
            status: 'error'
        });
    }
});


app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
