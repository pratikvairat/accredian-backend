const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// MySQL Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port:process.env.DB_PORT
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL: ' + err.stack);
    return;
  }
  console.log('Connected to MySQL as id ' + db.threadId);
});

// Middleware to check if the request has a valid token
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ message: 'Access denied. Token not provided.' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: err });
    req.user = user;
    next();
  });
};

// Register endpoint
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;

  // Check if username or email already exists
  db.query(
    'SELECT * FROM users WHERE username = ? OR email = ?',
    [username, email],
    async (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: 'Error checking duplicate users.' });
      }

      if (result.length > 0) {
        // Username or email is already taken
        const existingUser = result[0];
        if (existingUser.username === username) {
          return res.status(400).json({ message: 'Username is already taken.' });
        } else if (existingUser.email === email) {
          return res.status(400).json({ message: 'Email is already registered.' });
        }
      } else {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into the database
        db.query(
          'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
          [username, hashedPassword, email],
          (insertErr, insertResult) => {
            if (insertErr) {
              console.error(insertErr);
              return res.status(500).json({ message: 'Error registering user.' });
            }
            res.status(201).json({ message: 'User registered successfully.' });
          }
        );
      }
    }
  );
});


// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // Retrieve user from the database
  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Error logging in.' });
    }
    if (result.length === 0) {
      return res.status(401).json({ message: 'Invalid username or password.' });
    }
    const user = result[0];
    // Compare the provided password with the hashed password in the database
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid username or password.' });
    }
    // Generate a token
    const token = jwt.sign({ username: user.username, email: user.email }, process.env.JWT_SECRET);
   
    res.json({ token });
  });
});

// Profile information endpoint
app.get('/profile', authenticateToken, (req, res) => {
  const { username, email } = req.user;
  res.json({ username, email, token: req.header('Authorization') });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
