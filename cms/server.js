const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const marked = require('marked');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
require('dotenv').config();

// Validate required environment variables
const requiredEnvVars = ['SESSION_SECRET', 'ADMIN_PASSWORD'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Error: ${envVar} environment variable is required`);
    process.exit(1);
  }
}

const app = express();
const db = new sqlite3.Database('cms/db.sqlite');

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'https://wrong.athrvakhrbde.com',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/cms/', limiter);

// Login rate limiting
const loginLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5 // limit each IP to 5 login requests per hour
});
app.use('/cms/login', loginLimiter);

// Initialize database
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY,
    title TEXT,
    content TEXT,
    date TEXT,
    slug TEXT UNIQUE
  )`);

  // Create default admin user if it doesn't exist
  bcrypt.hash(process.env.ADMIN_PASSWORD, 10, (err, hash) => {
    if (err) return console.error('Error creating admin user:', err);
    db.run('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)', 
      ['admin', hash]);
  });
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));
app.use(express.static('cms/public'));

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.redirect('/cms/login');
  }
  next();
};

// Routes
app.get('/cms/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/cms/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.redirect('/cms/login?error=1');
    }
    
    req.session.userId = user.id;
    res.redirect('/cms/dashboard');
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).redirect('/cms/login?error=1');
  }
});

app.get('/cms/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/cms/login');
});

app.get('/cms/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/cms/posts', requireAuth, (req, res) => {
  db.all('SELECT id, title, date, slug FROM posts ORDER BY date DESC', (err, posts) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(posts);
  });
});

app.post('/cms/posts', requireAuth, (req, res) => {
  const { title, content } = req.body;
  
  if (!title || !content) {
    return res.status(400).json({ error: 'Title and content are required' });
  }

  const date = new Date().toISOString();
  const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  
  // Save to database
  db.run('INSERT INTO posts (title, content, date, slug) VALUES (?, ?, ?, ?)',
    [title, content, date, slug], function(err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      try {
        // Create Hugo content file
        const hugoContent = `---
title: "${title}"
date: ${date}
draft: false
---

${content}`;
        
        const filePath = path.join(process.cwd(), 'content/posts', `${slug}.md`);
        fs.mkdirSync(path.dirname(filePath), { recursive: true });
        fs.writeFileSync(filePath, hugoContent);
        
        res.json({ id: this.lastID, slug });
      } catch (err) {
        console.error('File system error:', err);
        return res.status(500).json({ error: 'Error creating post file' });
      }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`CMS server running at http://localhost:${PORT}/cms/login`);
}); 