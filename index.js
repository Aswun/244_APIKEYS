const express = require('express');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2/promise'); // Menggunakan promise agar async/await lebih mudah
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
const port = 3000;

// Konfigurasi Database (Sesuaikan dengan kredensial Anda)
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: 'Bil1o8775',
  database: 'api_p7',
  port: 3307
};

// Secret Key untuk JWT
const ACCESS_TOKEN_SECRET = 'KUNCI_RAHASIA_ADMIN_ANDA_YANG_KUAT'; // Ganti dengan key yang kuat

// Middleware
app.use(express.json());
// Semua file statis (HTML, CSS, JS frontend) ada di folder public
app.use(express.static(path.join(__dirname, 'public')));

// Buat koneksi pool database
let db;
(async () => {
  try {
    db = await mysql.createPool(dbConfig);
    console.log('✅ Terhubung ke database!');
  } catch (err) {
    console.error('❌ Gagal terhubung ke database:', err.message);
    process.exit(1);
  }
})();

// =========================================================================================
// MIDDLEWARE
// =========================================================================================

/**
 * Middleware untuk memverifikasi JWT Admin.
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  // Format: Bearer <TOKEN>
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    return res.status(401).json({ error: 'Akses ditolak. Token tidak tersedia.' }); // Unauthorized
  }

  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, admin) => {
    if (err) {
      return res.status(403).json({ error: 'Token tidak valid atau kadaluarsa.' }); // Forbidden
    }
    req.admin = admin; // Menyimpan payload admin (id, email)
    next(); // Lanjutkan ke route handler
  });
}

// =========================================================================================
// ROUTES UTAMA
// =========================================================================================

// Route utama: Mengarahkan ke form generate API key untuk User
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'user_generate.html'));
});

// =========================================================================================
// ROUTES USER: GENERATE & VALIDASI API KEY
// =========================================================================================

/**
 * Endpoint POST untuk Generate API Key.
 * Disederhanakan untuk hanya menerima first_name, last_name, email, dan expiry_duration.
 */
app.post('/generate-key', async (req, res) => {
  const { 
    first_name, 
    last_name, 
    email, 
    expiry_duration // e.g., '30', '90', '180', '365'
  } = req.body; // Input form disederhanakan

  if (!email || !first_name || !last_name || !expiry_duration) {
    return res.status(400).json({ error: 'Semua field wajib diisi.' });
  }

  try {
    // 1. Cek atau buat User (LOGIKA INI TETAP SAMA)
    let [userResults] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
    let userId;

    if (userResults.length === 0) {
      const insertSql = 'INSERT INTO users (first_name, last_name, email) VALUES (?, ?, ?)';
      const [insertResult] = await db.query(insertSql, [first_name, last_name, email]);
      userId = insertResult.insertId;
    } else {
      userId = userResults[0].id;
    }

    // 2. Hitung Tanggal Kedaluwarsa (LOGIKA INI TETAP SAMA)
    const days = parseInt(expiry_duration);
    if (isNaN(days) || days <= 0) {
        return res.status(400).json({ error: 'Masa berlaku tidak valid.' });
    }
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + days);
    const expiryDateString = expiryDate.toISOString().split('T')[0]; // Format YYYY-MM-DD

    // 3. Generate API Key unik (Format disederhanakan)
    const randomHex = crypto.randomBytes(16).toString('hex').toUpperCase();
    const hashPart = crypto.createHash('sha256')
        .update(email + Date.now())
        .digest('hex')
        .substring(0, 12)
        .toUpperCase();
    
    // Format: RANDOMHEX-HASH (Prefix dihilangkan)
    const apiKey = `${randomHex}-${hashPart}`;

    // 4. Simpan ke database (Disesuaikan dengan kolom baru)
    const sql = `
      INSERT INTO api_keys (user_id, api_key, expiry_date) 
      VALUES (?, ?, ?)
    `;
    // Status 'active'/ 'inactive' dihilangkan dari INSERT karena dihitung real-time
    const values = [userId, apiKey, expiryDateString];
    
    await db.query(sql, values);

    res.json({ 
      message: 'API key berhasil dibuat!', 
      apiKey: apiKey,
      expiryDate: expiryDateString,
      userId: userId
    });

  } catch (err) {
    console.error(err);
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Email sudah terdaftar. Silakan cek riwayat key Anda.' });
    }
    res.status(500).json({ error: 'Gagal membuat API key karena kesalahan server.' });
  }
});

/**
 * Endpoint POST untuk Validasi API Key.
 * Logika: Cek keberadaan Key dan status aktif/kedaluwarsa.
 */
app.post('/validate-key', async (req, res) => {
  const { apiKey } = req.body;

  if (!apiKey) {
    return res.status(400).json({ valid: false, error: 'API key wajib diisi.' });
  }

  try {
    // Query untuk mengambil data key DAN menentukan status real-time
    const sql = `
      SELECT 
        ak.*, u.first_name, u.last_name, u.email AS user_email,
        CASE 
          WHEN ak.expiry_date >= CURDATE() THEN 'active' 
          ELSE 'inactive' 
        END AS status_realtime
      FROM api_keys ak
      JOIN users u ON ak.user_id = u.id
      WHERE ak.api_key = ? LIMIT 1
    `;
    
    const [results] = await db.query(sql, [apiKey]);

    if (results.length === 0) {
      return res.status(404).json({ valid: false, message: 'API key tidak ditemukan.' });
    }

    const keyData = results[0];

    if (keyData.status_realtime === 'inactive') {
      return res.status(403).json({ valid: false, message: 'API key sudah kedaluwarsa.' });
    }

    // Key valid dan aktif
    res.json({ valid: true, message: 'API key valid.', data: {
      keyId: keyData.id,
      apiKey: keyData.api_key,
      expiryDate: keyData.expiry_date,
      status: keyData.status_realtime,
      owner: `${keyData.first_name} ${keyData.last_name} (${keyData.user_email})`
    }});

  } catch (err) {
    console.error(err);
    res.status(500).json({ valid: false, error: 'Terjadi kesalahan pada server.' });
  }
});

// =========================================================================================
// ROUTES ADMIN: REGISTRASI & LOGIN
// =========================================================================================

/**
 * Endpoint POST untuk Registrasi Admin Baru.
 * Logika: Hash password sebelum disimpan.
 */
app.post('/admin/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email dan password wajib diisi.' });
  }

  try {
    // 1. Hash Password
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // 2. Simpan ke Database
    const sql = 'INSERT INTO admins (email, password_hash) VALUES (?, ?)';
    await db.query(sql, [email, passwordHash]);

    res.status(201).json({ message: 'Registrasi admin berhasil!' });
  } catch (err) {
    console.error(err);
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Email admin sudah terdaftar.' });
    }
    res.status(500).json({ error: 'Gagal registrasi admin.' });
  }
});

/**
 * Endpoint POST untuk Login Admin.
 * Logika: Bandingkan password, buat JWT jika sukses.
 */
app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email dan password wajib diisi.' });
  }

  try {
    // 1. Cari Admin
    const [adminResults] = await db.query('SELECT * FROM admins WHERE email = ? LIMIT 1', [email]);

    if (adminResults.length === 0) {
      return res.status(401).json({ error: 'Email atau password salah.' });
    }

    const admin = adminResults[0];

    // 2. Bandingkan Password
    const isMatch = await bcrypt.compare(password, admin.password_hash);

    if (!isMatch) {
      return res.status(401).json({ error: 'Email atau password salah.' });
    }

    // 3. Buat dan Kirim JWT (Token)
    const token = jwt.sign(
      { id: admin.id, email: admin.email }, 
      ACCESS_TOKEN_SECRET, 
      { expiresIn: '1h' } // Token berlaku 1 jam
    );

    res.json({ message: 'Login berhasil!', token });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Terjadi kesalahan server saat login.' });
  }
});

// =========================================================================================
// ROUTES ADMIN: DASHBOARD (DILINDUNGI MIDDLEWARE)
// =========================================================================================

/**
 * Endpoint GET untuk menampilkan semua List User.
 * Dilindungi oleh authenticateToken.
 */
app.get('/admin/users', authenticateToken, async (req, res) => {
  try {
    const [users] = await db.query('SELECT id, first_name, last_name, email, status, created_at FROM users');
    res.json({ message: 'List semua user berhasil dimuat.', data: users });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Gagal mengambil data user.' });
  }
});

/**
 * Endpoint GET untuk menampilkan semua List API Keys.
 * Dilindungi oleh authenticateToken.
 */
app.get('/admin/apikeys', authenticateToken, async (req, res) => {
  try {
    const sql = `
      SELECT 
        ak.id AS key_id, ak.api_key, ak.expiry_date, ak.created_at,
        u.email AS user_email, u.first_name, u.last_name,
        CASE 
          WHEN ak.expiry_date >= CURDATE() THEN 'active' 
          ELSE 'inactive' 
        END AS status_realtime
      FROM api_keys ak
      JOIN users u ON ak.user_id = u.id
      ORDER BY ak.created_at DESC
    `;
    const [apiKeys] = await db.query(sql);
    
    // Catatan: Karena kolom 'status' di api_keys dihilangkan, kita tidak perlu 
    // lagi melakukan UPDATE status pasif di sini. Status murni didapatkan dari JOIN dan CASE.

    res.json({ message: 'List semua API Keys berhasil dimuat.', data: apiKeys });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Gagal mengambil data API keys.' });
  }
});

// =========================================================================================
// SERVER START
// =========================================================================================

app.listen(port, () => {
  console.log(`🚀 Server berjalan di http://localhost:${port}`);
  console.log(`🔐 Admin Register: http://localhost:${port}/admin_register.html`);
  console.log(`🔑 User Key Generator: http://localhost:${port}/user_generate.html`);
});