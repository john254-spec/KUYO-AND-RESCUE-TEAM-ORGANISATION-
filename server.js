require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Pool } = require('pg');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();

// ✅ IMPORTANT: Render uses PORT automatically
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;

// -------------------- DATABASE --------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false
});

// -------------------- SUPABASE --------------------
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// -------------------- MIDDLEWARE --------------------
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ FIX 1: static path must exist or fallback breaks routes
app.use(express.static(path.join(__dirname, 'public')));

// -------------------- FILE UPLOAD --------------------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 200 * 1024 * 1024
  }
});

// -------------------- AUTH --------------------
function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ message: 'No token provided' });
  }

  const token = header.split(' ')[1];

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Invalid token' });
  }
}

// -------------------- ADMIN --------------------
function admin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admins only' });
  }
  next();
}

// -------------------- SIGNUP --------------------
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields required' });
    }

    const exists = await pool.query(
      'SELECT id FROM users WHERE email=$1',
      [email]
    );

    if (exists.rows.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashed = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO users(name,email,password,role) VALUES($1,$2,$3,$4)',
      [name, email, hashed, 'user']
    );

    res.json({ message: 'Account created' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// -------------------- LOGIN --------------------
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      'SELECT * FROM users WHERE email=$1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'User not found' });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(400).json({ message: 'Wrong password' });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      role: user.role
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// -------------------- UPLOAD --------------------
app.post('/api/upload', auth, admin, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const fileName = `${Date.now()}-${req.file.originalname}`;

    const { error } = await supabase.storage
      .from('kuyo-files')
      .upload(fileName, req.file.buffer, {
        contentType: req.file.mimetype
      });

    if (error) {
      return res.status(500).json(error);
    }

    const publicUrl = supabase.storage
      .from('kuyo-files')
      .getPublicUrl(fileName)
      .data.publicUrl;

    res.json({
      message: 'Upload successful',
      url: publicUrl
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Upload failed' });
  }
});

// -------------------- FILE LIST --------------------
app.get('/api/files', async (req, res) => {
  const { data, error } = await supabase.storage
    .from('kuyo-files')
    .list();

  if (error) {
    return res.status(500).json(error);
  }

  const files = data.map(file => ({
    name: file.name,
    url: supabase.storage
      .from('kuyo-files')
      .getPublicUrl(file.name)
      .data.publicUrl
  }));

  res.json(files);
});

// -------------------- FRONTEND ROUTES --------------------

// ✅ FIX 2: avoid confusion — explicit root first

// -------------------- FRONTEND ROUTES --------------------

// Home
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Authentication Pages
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/forgot-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

// Organization Pages
app.get('/about', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'about.html'));
});

app.get('/mission', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'mission.html'));
});

app.get('/vision', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'vision.html'));
});

app.get('/objectives', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'objectives.html'));
});

app.get('/core-values', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'core-values.html'));
});

app.get('/contact', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'contact.html'));
});

// Admin Dashboard
app.get('/admin', auth, admin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Logo
app.get('/logo', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'logo.png'));
});

// Health Check
app.get('/api/status', (req, res) => {
  res.json({
    status: 'online',
    service: 'KUYO Rescue Team'
  });
});

// KEEP THIS LAST
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
// -------------------- START SERVER --------------------
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  

});
