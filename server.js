const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const WebSocket = require('ws');
require('dotenv').config();


// Initialize express app
const app = express();
app.use(cors());
app.use(express.json());

const { Pool } = require('pg');

// Set up PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DB_URL,  // Connection URL stored in .env file
  port: 5432,                             // PostgreSQL port
  ssl: {
    rejectUnauthorized: false,  // This disables the strict SSL certificate validation
  }
});

// Test the connection
pool.connect((err) => {
  if (err) {
    return console.error('Error acquiring client', err.stack);
  }
  console.log('Connected to PostgreSQL database');
});

// Create the `users` table if it doesn't exist
const createUsersTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      registration_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      last_login_time TIMESTAMP,
      status VARCHAR(10) DEFAULT 'active'
    );
  `;

  try {
    await pool.query(createTableQuery);
    console.log('Users table created or already exists.');
  } catch (err) {
    console.error('Error creating users table:', err);
  }
};

// Call the function to create the table
createUsersTable();
// JWT secret key
const secretKey = 'secret';

// Middleware to verify token and block unauthorized users
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(403).json({ message: 'No token provided' });

  jwt.verify(token, secretKey, async (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Unauthorized' });

    try {
      const result = await pool.query('SELECT status FROM users WHERE id = $1', [decoded.id]);
      if (!result.rows.length || result.rows[0].status === 'blocked') {
        return res.status(403).json({ message: 'Access denied' });
      }
      req.userId = decoded.id;
      next();
    } catch (error) {
      return res.status(500).json(error);
    }
  });
};

// Registration route
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const query = 'INSERT INTO users (name, email, password, registration_time) VALUES ($1, $2, $3, NOW())';
    await pool.query(query, [name, email, hashedPassword]);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Please fill all fields' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    if (user.status === 'blocked') {
      return res.status(403).json({ message: 'Your account is blocked' });
    }

    // Update last_login_time
    await pool.query('UPDATE users SET last_login_time = NOW() WHERE id = $1', [user.id]);

    const token = jwt.sign({ id: user.id }, secretKey, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get users route
app.get('/api/users', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, registration_time, last_login_time, status FROM users');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json(err);
  }
});

// WebSocket server setup
const wss = new WebSocket.Server({ port: 8080 });

wss.on('connection', (ws) => {
  console.log('User connected to WebSocket');

  ws.on('message', (message) => {
    console.log(`Received message => ${message}`);
  });

  ws.on('close', () => {
    console.log('User disconnected from WebSocket');
  });
});

// Function to notify clients when a user is blocked
function notifyUserBlocked(userId) {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: 'block', userId }));
    }
  });
}

// Block users route
app.post('/api/users/block', verifyToken, async (req, res) => {
  const { userIds } = req.body;
  try {
    const query = 'UPDATE users SET status = $1 WHERE id = ANY($2)';
    await pool.query(query, ['blocked', userIds]);
    notifyUserBlocked(userIds);
    res.json({ message: 'Users blocked successfully' });
  } catch (err) {
    res.status(500).json(err);
  }
});

// Unblock users route
app.post('/api/users/unblock', verifyToken, async (req, res) => {
  const { userIds } = req.body;
  try {
    const query = 'UPDATE users SET status = $1 WHERE id = ANY($2)';
    await pool.query(query, ['active', userIds]);
    res.json({ message: 'Users unblocked successfully' });
  } catch (err) {
    res.status(500).json(err);
  }
});

// Delete users route
app.post('/api/users/delete', verifyToken, async (req, res) => {
  const { userIds } = req.body;
  if (!userIds || !userIds.length) {
    return res.status(400).json({ message: 'No users selected for deletion' });
  }
  try {
    const query = 'DELETE FROM users WHERE id = ANY($1)';
    await pool.query(query, [userIds]);
    res.status(200).json({ message: 'Users deleted successfully' });
  } catch (err) {
    res.status(500).json(err);
  }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
