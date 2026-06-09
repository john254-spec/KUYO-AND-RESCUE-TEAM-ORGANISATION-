require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');

const { createClient } = require('@supabase/supabase-js');
const { Pool } = require('pg');

const app = express();

// ===================== SUPABASE =====================
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// ===================== POSTGRES (pg) =====================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ===================== MULTER =====================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage });

// ===================== MIDDLEWARE =====================
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));
app.use('/uploads', express.static('uploads'));

// ===================== JWT =====================
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// ===================== AUTH =====================
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function admin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
}

// ===================== ROUTE DEBUGGER =====================
app.get('/api/routes', (req, res) => {
  const routes = [];

  app._router.stack.forEach(middleware => {
    if (middleware.route) {
      routes.push({
        path: middleware.route.path,
        method: Object.keys(middleware.route.methods)[0]
      });
    }
  });

  res.json(routes);
});

// ===================== PAGES (YOUR FULL REPO ROUTES) =====================

// Home
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// About pages
app.get('/about', (req, res) => {
  res.sendFile(path.join(__dirname, 'About Us.html'));
});

app.get('/mission', (req, res) => {
  res.sendFile(path.join(__dirname, 'Mission.html'));
});

app.get('/vision', (req, res) => {
  res.sendFile(path.join(__dirname, 'Vision.html'));
});

app.get('/objectives', (req, res) => {
  res.sendFile(path.join(__dirname, 'Objectives.html'));
});

app.get('/core-values', (req, res) => {
  res.sendFile(path.join(__dirname, 'Core-values.html'));
});

app.get('/contact', (req, res) => {
  res.sendFile(path.join(__dirname, 'Contact.html'));
});

app.get('/support', (req, res) => {
  res.sendFile(path.join(__dirname, 'Support.html'));
});

// Auth pages
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'Sign-up.html'));
});

app.get('/forgot-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'Forgot-password.html'));
});

app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'Reset-password.html'));
});

// Dashboard
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// Admin (protected)
app.get('/admin', auth, admin, (req, res) => {
  res.sendFile(path.join(__dirname, 'Admin.html'));
});

// ===================== API =====================

// Status
app.get('/api/status', (req, res) => {
  res.json({
    status: 'online',
    service: 'KUYO Rescue Team'
  });
});

// ===================== PG TEST =====================
app.get('/api/db-test', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({
      status: 'ok',
      time: result.rows[0].now
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===================== SUPABASE TEST =====================
app.get('/api/supabase-test', async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .limit(1);

  if (error) return res.status(500).json({ error: error.message });

  res.json({ status: 'ok', data });
});

// ===================== AUTH =====================
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;

  const hashed = await bcrypt.hash(password, 10);

  const { data, error } = await supabase
    .from('users')
    .insert([{ email, password: hashed, role: 'user' }])
    .select();

  if (error) return res.status(400).json({ error: error.message });

  res.json({ message: 'User registered', data });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .single();

  if (error || !data) {
    return res.status(400).json({ error: 'User not found' });
  }

  const valid = await bcrypt.compare(password, data.password);

  if (!valid) {
    return res.status(401).json({ error: 'Invalid password' });
  }

  const token = generateToken(data);

  res.json({
    message: 'Login success',
    token,
    user: data
  });
});

// ===================== PROFILE =====================
app.get('/api/profile', auth, (req, res) => {
  res.json(req.user);
});

// ===================== FILE UPLOAD =====================
app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  res.json({
    message: 'Upload successful',
    file: req.file.filename,
    url: `/uploads/${req.file.filename}`
  });
});

// ===================== USERS (ADMIN ONLY) =====================
app.get('/api/users', auth, admin, async (req, res) => {
  const { data, error } = await supabase.from('users').select('*');

  if (error) return res.status(400).json({ error: error.message });

  res.json(data);
});

// ===================== CATCH ALL =====================
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ===================== START SERVER =====================
const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
  console.log(`🚀 KUYO server running on port ${PORT}`);
});
