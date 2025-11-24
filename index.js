const express = require('express');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2');

const app = express();
const port = 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Koneksi database
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Bil1o8775',
  database: 'api_p7',
  port: 3307
});

db.connect(err => {
  if (err) throw err;
  console.log('✅ Terhubung ke database!');
});

// Route utama
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 🔑 Route untuk generate API key
app.post('/generate-key', (req, res) => {
  const { username, email } = req.body;

  if (!username || !email) {
    return res.status(400).json({ error: 'Username dan email wajib diisi.' });
  }

  // Generate API key unik
  const randomBytes = crypto.randomBytes(16).toString('hex').toUpperCase();
  const hash = crypto.createHash('sha256')
    .update(username + email + Date.now())
    .digest('hex')
    .substring(0, 12)
    .toUpperCase();

  const apiKey = `${username.substring(0, 3).toUpperCase()}-${randomBytes}-${hash}`;

  // Simpan ke database
  const sql = 'INSERT INTO api_keys (username, email, api_key) VALUES (?, ?, ?)';
  db.query(sql, [username, email, apiKey], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Gagal menyimpan API key ke database.' });
    }

    res.json({ message: 'API key berhasil dibuat!', apiKey });
  });
});

// ✅ Route untuk validasi API key
app.post('/validate-key', (req, res) => {
  const { apiKey } = req.body;

  if (!apiKey) {
    return res.status(400).json({ error: 'API key wajib diisi.' });
  }

  const sql = 'SELECT * FROM api_keys WHERE api_key = ? LIMIT 1';
  db.query(sql, [apiKey], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
    }

    if (results.length === 0) {
      return res.status(404).json({ valid: false, message: 'API key tidak ditemukan.' });
    }

    res.json({ valid: true, message: 'API key valid.', data: results[0] });
  });
});

app.listen(port, () => {
  console.log(`🚀 Server berjalan di http://localhost:${port}`);
});
