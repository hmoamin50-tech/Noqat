require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const JWT_EXPIRES_IN = '7d';

// ---------- اتصال قاعدة البيانات ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('sslmode=require')
    ? { rejectUnauthorized: false }
    : (process.env.DATABASE_URL && process.env.DATABASE_URL.includes('supabase')
        ? { rejectUnauthorized: false }
        : false),
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

app.use(cors());
app.use(express.json({ limit: '100kb' }));

// ---------- إنشاء الجداول عند البدء ----------
async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id              BIGSERIAL PRIMARY KEY,
        member_number   VARCHAR(20) UNIQUE NOT NULL,
        full_name       VARCHAR(120) NOT NULL,
        username        VARCHAR(40) UNIQUE NOT NULL,
        phone           VARCHAR(20),
        password_hash   VARCHAR(200) NOT NULL,
        status          VARCHAR(20) NOT NULL DEFAULT 'active',
        balance_points  BIGINT NOT NULL DEFAULT 0 CHECK (balance_points >= 0),
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_users_member_number ON users(member_number);
    `);

    console.log('✅ Tables ready');
  } finally {
    client.release();
  }
}

// ---------- أدوات مساعدة ----------

function generateMemberNumber() {
  const n = Math.floor(10000000 + Math.random() * 90000000);
  return `NQ-${n}`;
}

function issueToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function publicUser(row) {
  return {
    id: Number(row.id),
    memberNumber: row.member_number,
    fullName: row.full_name,
    username: row.username,
    phone: row.phone,
    status: row.status,
    balancePoints: Number(row.balance_points),
    joinedAt: row.created_at
  };
}

// ---------- Middleware ----------

function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({
      success: false,
      code: 'NO_TOKEN',
      message: 'لم يتم توفير رمز الدخول'
    });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    next();
  } catch (e) {
    return res.status(401).json({
      success: false,
      code: 'INVALID_TOKEN',
      message: 'رمز الدخول غير صالح أو منتهي'
    });
  }
}

// ---------- المسارات ----------

app.get('/', async (req, res) => {
  let userCount = 0;
  let dbStatus = 'unknown';
  try {
    const result = await pool.query('SELECT COUNT(*) AS c FROM users');
    userCount = Number(result.rows[0].c);
    dbStatus = 'connected';
  } catch (e) {
    dbStatus = 'error: ' + e.message;
  }

  res.send(`
    <!DOCTYPE html>
    <html dir="rtl" lang="ar">
    <head>
      <meta charset="utf-8">
      <title>NOQAT API</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { font-family: -apple-system, sans-serif; background:#102C27; color:#E0F3EB;
               padding:40px; max-width:600px; margin:0 auto; line-height:1.8; }
        h1 { color:#fff; }
        code { background:#146752; padding:3px 8px; border-radius:6px; color:#E0F3EB; }
        .card { background:#146752; padding:20px; border-radius:12px; margin-top:20px; }
        .ok { color:#A8E6CF; }
        .err { color:#FFB4B4; }
      </style>
    </head>
    <body>
      <h1>NOQAT API ✓</h1>
      <p>الخادم يعمل بنجاح مع قاعدة البيانات.</p>
      <div class="card">
        <p><strong>المستخدمون الحاليون:</strong> ${userCount}</p>
        <p><strong>حالة قاعدة البيانات:</strong>
          <span class="${dbStatus === 'connected' ? 'ok' : 'err'}">${dbStatus}</span>
        </p>
      </div>
      <h3>المسارات المتاحة:</h3>
      <ul>
        <li><code>GET /health</code></li>
        <li><code>POST /api/auth/register</code></li>
        <li><code>POST /api/auth/login</code></li>
        <li><code>GET /api/account/me</code> (يتطلب توثيق)</li>
        <li><code>GET /api/account/balance</code> (يتطلب توثيق)</li>
      </ul>
    </body>
    </html>
  `);
});

app.get('/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) AS c FROM users');
    res.json({
      status: 'ok',
      time: new Date().toISOString(),
      usersCount: Number(result.rows[0].c),
      db: 'connected'
    });
  } catch (e) {
    res.status(500).json({
      status: 'error',
      time: new Date().toISOString(),
      db: 'error: ' + e.message
    });
  }
});

// تسجيل
app.post('/api/auth/register', async (req, res, next) => {
  try {
    const { fullName, username, phone, password } = req.body || {};

    if (!fullName || !username || !password) {
      return res.status(400).json({
        success: false,
        code: 'MISSING_FIELDS',
        message: 'الاسم واسم المستخدم وكلمة المرور مطلوبة'
      });
    }

    if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_USERNAME',
        message: 'اسم المستخدم يجب أن يكون 3-20 حرفًا إنجليزيًا/رقمًا'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        code: 'WEAK_PASSWORD',
        message: 'كلمة المرور قصيرة جدًا (6 أحرف على الأقل)'
      });
    }

    // تحقق من التفرد
    const exists = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );
    if (exists.rowCount > 0) {
      return res.status(409).json({
        success: false,
        code: 'USERNAME_TAKEN',
        message: 'اسم المستخدم مستخدم مسبقًا'
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    let memberNumber;
    let inserted = null;
    let attempts = 0;

    // محاولة حتى 5 مرات لتوليد رقم عضوية فريد
    while (attempts < 5) {
      memberNumber = generateMemberNumber();
      try {
        const result = await pool.query(
          `INSERT INTO users (member_number, full_name, username, phone, password_hash)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING *`,
          [memberNumber, fullName.trim(), username.trim(),
           phone ? phone.trim() : null, passwordHash]
        );
        inserted = result.rows[0];
        break;
      } catch (e) {
        if (e.code === '23505' && e.constraint && e.constraint.includes('member_number')) {
          // تعارض في رقم العضوية — جرب مجددًا
          attempts++;
          continue;
        }
        throw e;
      }
    }

    if (!inserted) {
      return res.status(500).json({
        success: false,
        code: 'MEMBER_NUMBER_COLLISION',
        message: 'تعذر إنشاء رقم عضوية فريد. حاول مجددًا'
      });
    }

    const token = issueToken(inserted);

    res.status(201).json({
      success: true,
      data: { token, user: publicUser(inserted) }
    });
  } catch (e) { next(e); }
});

// تسجيل الدخول
app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        code: 'MISSING_FIELDS',
        message: 'اسم المستخدم وكلمة المرور مطلوبان'
      });
    }

    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({
        success: false,
        code: 'INVALID_CREDENTIALS',
        message: 'بيانات الدخول غير صحيحة'
      });
    }

    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({
        success: false,
        code: 'INVALID_CREDENTIALS',
        message: 'بيانات الدخول غير صحيحة'
      });
    }

    if (user.status !== 'active') {
      return res.status(403).json({
        success: false,
        code: 'ACCOUNT_NOT_ACTIVE',
        message: 'الحساب غير نشط'
      });
    }

    const token = issueToken(user);
    res.json({
      success: true,
      data: { token, user: publicUser(user) }
    });
  } catch (e) { next(e); }
});

// حسابي
app.get('/api/account/me', authRequired, async (req, res, next) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.userId]);
    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        code: 'USER_NOT_FOUND',
        message: 'المستخدم غير موجود'
      });
    }
    res.json({ success: true, data: publicUser(result.rows[0]) });
  } catch (e) { next(e); }
});

// الرصيد
app.get('/api/account/balance', authRequired, async (req, res, next) => {
  try {
    const result = await pool.query(
      'SELECT balance_points FROM users WHERE id = $1',
      [req.userId]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        code: 'USER_NOT_FOUND',
        message: 'المستخدم غير موجود'
      });
    }
    res.json({
      success: true,
      data: { balancePoints: Number(result.rows[0].balance_points) }
    });
  } catch (e) { next(e); }
});

// قائمة المستخدمين (اختبار)
app.get('/api/users', async (req, res, next) => {
  try {
    const result = await pool.query('SELECT * FROM users ORDER BY id');
    res.json({
      success: true,
      data: result.rows.map(publicUser)
    });
  } catch (e) { next(e); }
});

// ---------- معالجات الأخطاء ----------

app.use((req, res) => {
  res.status(404).json({
    success: false,
    code: 'NOT_FOUND',
    message: 'المسار غير موجود'
  });
});

app.use((err, req, res, next) => {
  console.error('❌ Server error:', err.message);
  res.status(500).json({
    success: false,
    code: 'SERVER_ERROR',
    message: 'حدث خطأ في الخادم'
  });
});

// ---------- بدء ----------

(async () => {
  try {
    await initDb();
    console.log('✅ Database connected');
    app.listen(PORT, () => {
      console.log('🚀 NOQAT Server running on port ' + PORT);
    });
  } catch (e) {
    console.error('❌ Startup failed:', e.message);
    process.exit(1);
  }
})();
