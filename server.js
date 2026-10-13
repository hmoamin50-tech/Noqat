require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const JWT_EXPIRES_IN = '7d';

app.use(cors());
app.use(express.json({ limit: '100kb' }));

// ---------- المخزن في الذاكرة ----------
// ⚠️ يُفقد عند إعادة تشغيل الخادم — سنستبدله بـ PostgreSQL لاحقًا
const users = [];
let nextUserId = 1;

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

function publicUser(user) {
  return {
    id: user.id,
    memberNumber: user.memberNumber,
    fullName: user.fullName,
    username: user.username,
    phone: user.phone,
    status: user.status,
    balancePoints: user.balancePoints,
    joinedAt: user.joinedAt
  };
}

function findUserByUsername(username) {
  return users.find(u => u.username === username);
}

function findUserById(id) {
  return users.find(u => u.id === id);
}

// ---------- Middleware: التحقق من JWT ----------

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
    const user = findUserById(payload.sub);
    if (!user) {
      return res.status(401).json({
        success: false,
        code: 'USER_NOT_FOUND',
        message: 'المستخدم غير موجود'
      });
    }
    req.user = user;
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

// الصفحة الرئيسية — اختبار سريع من المتصفح
app.get('/', (req, res) => {
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
      </style>
    </head>
    <body>
      <h1>NOQAT API ✓</h1>
      <p>الخادم يعمل بنجاح.</p>
      <div class="card">
        <p><strong>المستخدمون الحاليون:</strong> ${users.length}</p>
        <p><strong>الحالة:</strong> متصل</p>
      </div>
      <h3>المسارات المتاحة:</h3>
      <ul>
        <li><code>GET /health</code></li>
        <li><code>POST /api/auth/register</code></li>
        <li><code>POST /api/auth/login</code></li>
        <li><code>GET /api/account/me</code> (يتطلب توثيق)</li>
        <li><code>GET /api/account/balance</code> (يتطلب توثيق)</li>
        <li><code>GET /api/users</code> (اختبار)</li>
      </ul>
    </body>
    </html>
  `);
});

// فحص الحالة
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    time: new Date().toISOString(),
    usersCount: users.length
  });
});

// تسجيل حساب جديد
app.post('/api/auth/register', async (req, res, next) => {
  try {
    const { fullName, username, phone, password } = req.body || {};

    // تحقق أساسي
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
    if (findUserByUsername(username)) {
      return res.status(409).json({
        success: false,
        code: 'USERNAME_TAKEN',
        message: 'اسم المستخدم مستخدم مسبقًا'
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = {
      id: nextUserId++,
      memberNumber: generateMemberNumber(),
      fullName: fullName.trim(),
      username: username.trim(),
      phone: phone ? phone.trim() : null,
      passwordHash,
      status: 'active',
      balancePoints: 0,
      joinedAt: new Date().toISOString()
    };

    users.push(user);

    const token = issueToken(user);

    res.status(201).json({
      success: true,
      data: { token, user: publicUser(user) }
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

    const user = findUserByUsername(username);
    if (!user) {
      return res.status(401).json({
        success: false,
        code: 'INVALID_CREDENTIALS',
        message: 'بيانات الدخول غير صحيحة'
      });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
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
app.get('/api/account/me', authRequired, (req, res) => {
  res.json({ success: true, data: publicUser(req.user) });
});

// الرصيد
app.get('/api/account/balance', authRequired, (req, res) => {
  res.json({
    success: true,
    data: { balancePoints: req.user.balancePoints }
  });
});

// قائمة المستخدمين (للاختبار فقط — بدون كلمات مرور)
app.get('/api/users', (req, res) => {
  res.json({
    success: true,
    data: users.map(publicUser)
  });
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

app.listen(PORT, () => {
  console.log('🚀 NOQAT Server running on port ' + PORT);
});
