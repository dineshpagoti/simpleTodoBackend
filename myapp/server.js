const express = require("express");
const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const dbPath = path.join(__dirname, "database.db");

// Secret key for JWT
const SECRET_KEY = "your_jwt_secret";

// Initialize the database
let db = null;
const initializeDbServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      )
    `);

    await db.exec(`
      CREATE TABLE IF NOT EXISTS todos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        description TEXT,
        status TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);
    app.listen(3005, () => {
      console.log("Server starts at http://localhost:3005");
    });
  } catch (e) {
    console.log(e.message);
  }
};
initializeDbServer();

// User Registration
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.run(
      `INSERT INTO users (username, password) VALUES (?, ?)`,
      [username, hashedPassword]
    );
    res.status(201).send({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// Login Route
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await db.get(`SELECT * FROM users WHERE username = ?`, [username]);
    if (!user) {
      return res.status(404).send('User not found');
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send('Invalid credentials');
    }
    const token = jwt.sign({ userId: user.id }, SECRET_KEY);
    res.send({ token });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// Middleware to check JWT
const authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Extract token from 'Bearer <token>'

  if (!token) {
    return res.status(403).send('No token provided.');
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(500).send('Failed to authenticate token.');
    }
    req.userId = decoded.userId;
    next();
  });
};

// CRUD for To-Dos
app.post('/todos', authenticate, async (req, res) => {
  const { description, status } = req.body;
  try {
    const result = await db.run(
      `INSERT INTO todos (user_id, description, status) VALUES (?, ?, ?)`,
      [req.userId, description, status]
    );
    res.status(201).send({ id: result.lastID, description, status });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

app.get('/todos', authenticate, async (req, res) => {
  try {
    const todos = await db.all(`SELECT * FROM todos WHERE user_id = ?`, [req.userId]);
    res.send(todos);
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

app.put('/todos/:id', authenticate, async (req, res) => {
  const { description, status } = req.body;
  const { id } = req.params;
  try {
    const result = await db.run(
      `UPDATE todos SET description = ?, status = ? WHERE id = ? AND user_id = ?`,
      [description, status, id, req.userId]
    );
    if (result.changes === 0) {
      return res.status(404).send('To-do not found or not authorized');
    }
    res.send({ message: 'To-do updated' });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

app.delete('/todos/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await db.run(
      `DELETE FROM todos WHERE id = ? AND user_id = ?`,
      [id, req.userId]
    );
    if (result.changes === 0) {
      return res.status(404).send('To-do not found or not authorized');
    }
    res.send({ message: 'To-do deleted' });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});
