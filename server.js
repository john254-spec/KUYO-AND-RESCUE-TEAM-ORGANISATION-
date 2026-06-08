require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Pool } = require('pg');
const { createClient } = require('@supabase/supabase-js');

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 200 * 1024 * 1024
  }
});

function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({
      message: 'No token provided'
    });
  }

  const token = header.split(' ')[1];

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(403).json({
      message: 'Invalid token'
    });
  }
}

function admin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({
      message: 'Admins only'
    });
  }

  next();
}

app.post('/api/signup', async (req, res) => {
  try {

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message: 'All fields required'
      });
    }

    const exists = await pool.query(
      'SELECT id FROM users WHERE email=$1',
      [email]
    );

    if (exists.rows.length) {
      return res.status(400).json({
        message: 'User already exists'
      });
    }

    const hashed = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO users(name,email,password,role) VALUES($1,$2,$3,$4)',
      [name, email, hashed, 'user']
    );

    res.json({
      message: 'Account created'
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: 'Server error'
    });
  }
});

app.post('/api/login', async (req, res) => {
  try {

    const { email, password } = req.body;

    const result = await pool.query(
      'SELECT * FROM users WHERE email=$1',
      [email]
    );

    if (!result.rows.length) {
      return res.status(400).json({
        message: 'User not found'
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password
    );

    if (!valid) {
      return res.status(400).json({
        message: 'Wrong password'
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      JWT_SECRET,
      {
        expiresIn: '7d'
      }
    );

    res.json({
      message: 'Login successful',
      token,
      role: user.role
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: 'Server error'
    });
  }
});

app.post(
  '/api/upload',
  auth,
  admin,
  upload.single('file'),
  async (req, res) => {

    try {

      if (!req.file) {
        return res.status(400).json({
          message: 'No file uploaded'
        });
      }

      const fileName =
        Date.now() + '-' + req.file.originalname;

      const { error } =
        await supabase.storage
          .from('kuyo-files')
          .upload(
            fileName,
            req.file.buffer,
            {
              contentType: req.file.mimetype
            }
          );

      if (error) {
        return res.status(500).json(error);
      }

      const publicUrl =
        supabase.storage
          .from('kuyo-files')
          .getPublicUrl(fileName)
          .data.publicUrl;

      res.json({
        message: 'Upload successful',
        url: publicUrl
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        message: 'Upload failed'
      });
    }
  }
);

app.get('/api/files', async (req, res) => {

  const { data, error } =
    await supabase.storage
      .from('kuyo-files')
      .list();

  if (error) {
    return res.status(500).json(error);
  }

  const files = data.map(file => ({
    name: file.name,
    url:
      supabase.storage
        .from('kuyo-files')
        .getPublicUrl(file.name)
        .data.publicUrl
  }));

  res.json(files);
});

app.get('/', (req, res) => {
  res.send('KUYO & RESCUE TEAM API RUNNING');
});app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});

