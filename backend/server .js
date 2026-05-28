require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const { Pool } = require('pg');

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;

// DB CONNECTION
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')));

if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
app.use('/uploads', express.static('uploads'));

/* ---------------- UPLOAD ---------------- */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) =>
    cb(null, Date.now() + '-' + file.originalname)
});

const upload = multer({
  storage,
  limits: { fileSize: 200 * 1024 * 1024 }
});

/* ---------------- AUTH ---------------- */
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

function admin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admins only' });
  }
  next();
}

/* ---------------- SIGNUP ---------------- */
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;

  const exists = await pool.query(
    'SELECT * FROM users WHERE email=$1',
    [email]
  );

  if (exists.rows.length > 0) {
    return res.status(400).json({ message: 'User exists' });
  }

  const hashed = await bcrypt.hash(password, 10);

  const role = 'user';

  await pool.query(
    'INSERT INTO users (name,email,password,role) VALUES ($1,$2,$3,$4)',
    [name, email, hashed, role]
  );

  res.json({ message: 'Account created' });
});

/* ---------------- LOGIN ---------------- */
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  const result = await pool.query(
    'SELECT * FROM users WHERE email=$1',
    [email]
  );

  if (result.rows.length === 0)
    return res.status(400).json({ message: 'User not found' });

  const user = result.rows[0];

  const ok = await bcrypt.compare(password, user.password);

  if (!ok) return res.status(400).json({ message: 'Wrong password' });

  const token = jwt.sign(
    { id: user.id, role: user.role, email: user.email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({
    message: 'Login success',
    token,
    role: user.role
  });
});

/* ---------------- FORGOT/RESET (DB READY) ---------------- */
app.post('/api/forgot-password', (req, res) => {
  res.json({ message: 'Reset email system not yet connected' });
});

app.post('/api/reset-password', (req, res) => {
  res.json({ message: 'Password reset endpoint ready' });
});

/* ---------------- UPLOAD (ADMIN ONLY) ---------------- */
app.post('/api/upload', auth, admin, upload.single('file'), (req, res) => {
  res.json({
    message: 'Uploaded successfully',
    file: req.file.filename
  });
});

/* ---------------- FILE LIST ---------------- */
app.get('/api/downloads', (req, res) => {
  fs.readdir('./uploads', (err, files) => {
    if (err) return res.status(500).json({ message: 'Error' });
    res.json(files);
  });
});

/* ---------------- START ---------------- */
app.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});
