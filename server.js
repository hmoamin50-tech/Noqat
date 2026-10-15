// ---------- البحث عن مستلم التحويل ----------

app.get('/api/users/lookup', authRequired, async (req, res, next) => {
  try {
    let memberNumber = String(req.query.memberNumber || '').trim();

    // السماح بإدخال الأرقام فقط أو الرقم الكامل NQ-12345678
    memberNumber = memberNumber.replace(/^NQ-/i, '');

    // يجب أن يتكون رقم العضوية من 8 أرقام
    if (!/^\d{8}$/.test(memberNumber)) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_MEMBER_NUMBER',
        message: 'أدخل رقم العضوية المكوّن من 8 أرقام'
      });
    }

    // قاعدة البيانات تخزن الرقم بالصيغة NQ-12345678
    const formattedNumber = `NQ-${memberNumber}`;

    const result = await pool.query(
      `SELECT id, member_number, full_name, status, is_verified
       FROM users
       WHERE member_number = $1
       LIMIT 1`,
      [formattedNumber]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        code: 'RECEIVER_NOT_FOUND',
        message: 'لم يتم العثور على حساب بهذا الرقم'
      });
    }

    const user = result.rows[0];

    if (Number(user.id) === Number(req.userId)) {
      return res.status(400).json({
        success: false,
        code: 'SELF_TRANSFER',
        message: 'لا يمكنك التحويل إلى حسابك الشخصي'
      });
    }

    if (user.status !== 'active') {
      return res.status(400).json({
        success: false,
        code: 'RECEIVER_NOT_ACTIVE',
        message: 'حساب المستلم غير نشط'
      });
    }

    if (!user.is_verified) {
      return res.status(400).json({
        success: false,
        code: 'RECEIVER_NOT_VERIFIED',
        message: 'حساب المستلم غير موثّق'
      });
    }

    return res.json({
      success: true,
      data: {
        memberNumber: user.member_number,
        fullName: user.full_name,
        isVerified: user.is_verified
      }
    });
  } catch (error) {
    next(error);
  }
});
