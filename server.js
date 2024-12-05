const express = require('express');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const session = require('express-session');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'secretKey',
  resave: false,
  saveUninitialized: false
}));

// In-memory user storage (for simplicity)
const users = [];

// View Engine
app.set('view engine', 'ejs');

// Routes
app.get('/', (req, res) => res.redirect('/login'));

app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });
  res.send('Registration successful. <a href="/login">Login</a>');
});

app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(user => user.username === username);
  if (user && await bcrypt.compare(password, user.password)) {
    req.session.username = username;
    res.redirect('/dashboard');
  } else {
    res.send('Invalid credentials. <a href="/login">Try again</a>');
  }
});

app.get('/dashboard', (req, res) => {
  if (!req.session.username) {
    return res.redirect('/login');
  }
  res.render('dashboard', { username: req.session.username });
});

app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.redirect('/dashboard');
    }
    res.send('You have been logged out. <a href="/login">Login again</a>');
  });
});

// Start Server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
