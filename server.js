const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mysql = require('mysql2');
const WebSocket = require('ws');
require('dotenv').config();


// Initialize express app
const app = express();
app.use(cors());
app.use(express.json());

// Connect to MySQL
const db = mysql.createConnection({
  host: process.env.DB_HOST, // set this to Railway's MySQL host
  user: process.env.DB_USER, // set this to Railway's MySQL user
  password: process.env.DB_PASS, // set this to Railway's MySQL password
  database: process.env.DB_NAME // set this to Railway's MySQL database name
  
});

db.connect((err) => {
  if (err) throw err;
  console.log('Connected to MySQL');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// JWT secret key
const secretKey = 'secret';

// Middleware to verify token and block unauthorized users
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(403).json({ message: 'No token provided' });

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Unauthorized' });

    db.query('SELECT status FROM users WHERE id = ?', [decoded.id], (err, results) => {
      if (err) return res.status(500).json(err);
      if (!results.length || results[0].status === 'blocked') {
        return res.status(403).json({ message: 'Access denied' });
      }
      req.userId = decoded.id;
      next();
    });
  });
};

//registration route
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.query(
    'INSERT INTO users (name, email, password, registration_time) VALUES (?, ?, ?, NOW())',
    [name, email, hashedPassword],
    (err, result) => {
      if (err) return res.status(500).json(err);
      res.status(201).json({ message: 'User registered successfully' });
    }
  );
});


// Login route
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Please fill all fields' });
  }

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ message: 'Internal server error' });

    if (!results.length) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = results[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    if (user.status === 'blocked') {
      return res.status(403).json({ message: 'Your account is blocked' });
    }

    // Update last_login_time
    db.query('UPDATE users SET last_login_time = NOW() WHERE id = ?', [user.id], (err) => {
      if (err) console.error('Failed to update last login time:', err);
    });

    const token = jwt.sign({ id: user.id }, secretKey, { expiresIn: '1h' });
    res.json({ token });
  });
});


// Get users route
app.get('/api/users', verifyToken, (req, res) => {
  db.query('SELECT id, name, email, registration_time, last_login_time, status FROM users', (err, results) => {
    if (err) return res.status(500).json(err);
    res.json(results);
  });
});

const wss = new WebSocket.Server({ port: 8081 });

wss.on('connection', (ws) => {
  console.log('User connected to WebSocket');

  ws.on('message', (message) => {
    console.log(`Received message => ${message}`);
  });

  ws.on('close', () => {
    console.log('User disconnected from WebSocket');
  });
});

function notifyUserBlocked(userId) {
  // Broadcast to all connected users
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: 'block', userId }));
    }
  });
}


// When you block a user
app.post('/api/users/block', verifyToken, (req, res) => {
  const { userIds } = req.body;
  db.query('UPDATE users SET status = "blocked" WHERE id IN (?)', [userIds], (err, result) => {
    if (err) return res.status(500).json(err);
    notifyUserBlocked(userIds);
    res.json({ message: 'Users blocked successfully' });
  });
});

// Unblock users route
app.post('/api/users/unblock', verifyToken, (req, res) => {
  const { userIds } = req.body;
  db.query('UPDATE users SET status = "active" WHERE id IN (?)', [userIds], (err, result) => {
    if (err) return res.status(500).json(err);
    res.json({ message: 'Users unblocked successfully' });
  });
});

// Delete users route
app.post('/api/users/delete', verifyToken, (req, res) => {
  const { userIds } = req.body;
  if (!userIds || !userIds.length) {
    return res.status(400).json({ message: 'No users selected for deletion' });
  }
  db.query('DELETE FROM users WHERE id IN (?)', [userIds], (err, result) => {
    if (err) return res.status(500).json(err);
    res.status(200).json({ message: 'Users deleted successfully' });
  });
});

// Start the server
app.listen(5000, () => {
  console.log('Server running on http://localhost:5000');
});
