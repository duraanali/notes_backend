require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const sqlite3 = require('sqlite3').verbose();

// Add body-parser middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(cors());
const port = process.env.PORT || 9000;

// Create SQLite database connection
const db = new sqlite3.Database('./notes.db'); // Replace with your desired database file name or path

const JWT_SECRET = 'secret';

// Create 'users' table
db.serialize(() => {
  db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT, password TEXT)');
  db.run('CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, content TEXT, user_id INTEGER)');
});

// List all notes
app.get('/notes', (req, res) => {
  const query = 'SELECT * FROM notes ORDER BY id DESC';
  db.all(query, (error, rows) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'An error occurred' });
    }
    res.json(rows);
  });
});

// Create a new note
app.post('/create_note', authenticateToken, (req, res) => {
  const { title, content } = req.body;
  const userId = req.user.id;
  const query = 'INSERT INTO notes (title, content, user_id) VALUES (?, ?, ?)';
  db.run(query, [title, content, userId], function (error) {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'An error occurred' });
    }
    const id = this.lastID;
    res.json({ id, title, content });
  });
});

// Update a note
app.put('/update_note/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { title, content } = req.body;
  const userId = req.user.id;
  const query = 'UPDATE notes SET title = ?, content = ? WHERE id = ? AND user_id = ?';
  db.run(query, [title, content, id, userId], function (error) {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'An error occurred' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Note not found or unauthorized' });
    }
    res.json({ id, title, content });
  });
});

// Delete a note
app.delete('/delete_note/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;
  const query = 'DELETE FROM notes WHERE id = ? AND user_id = ?';
  db.run(query, [id, userId], function (error) {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'An error occurred' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Note not found or unauthorized' });
    }
    res.json({ message: 'Note deleted successfully' });
  });
});

// Get current user data
app.get('/user', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const query = 'SELECT id, name, email FROM users WHERE id = ?';
  db.get(query, [userId], (error, row) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'An error occurred' });
    }
    if (!row) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(row);
  });
});


// Register a new user
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  // Check if user with the same email already exists
  const checkQuery = 'SELECT * FROM users WHERE email = ?';
  db.get(checkQuery, [email], async (error, row) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'An error occurred' });
    }
    if (row) {
      return res.status(409).json({ error: 'User with this email already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    const insertQuery = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
    db.run(insertQuery, [name, email, hashedPassword], function (error) {
      if (error) {
        console.error(error);
        return res.status(500).json({ error: 'An error occurred' });
      }
      const userId = this.lastID;

      // Create and return JWT token
      const token = jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '1d' });
      res.json({ token });
    });
  });
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Check if user with the provided email exists
  const checkQuery = 'SELECT * FROM users WHERE email = ?';
  db.get(checkQuery, [email], async (error, row) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'An error occurred' });
    }
    if (!row) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check if the password is correct
    const passwordMatch = await bcrypt.compare(password, row.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Create and return JWT token
    const token = jwt.sign({ id: row.id }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
  });
});

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, JWT_SECRET, (error, user) => {
    if (error) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    req.user = user;
    next();
  });
}

// Start the server
app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
