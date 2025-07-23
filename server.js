
// server.js — منصة إدارة إجازات "عبدالإله سليمان عبدالله الهديلج"
const express        = require('express');
const helmet         = require('helmet');
const cors           = require('cors');
const rateLimit      = require('express-rate-limit');
const hpp            = require('hpp');
const geoip          = require('geoip-lite');
const useragent      = require('express-useragent');
const winston        = require('winston');
const axios          = require('axios');
const xssClean       = require('xss-clean');
const mongoSanitize  = require('express-mongo-sanitize');
const path           = require('path');
require('dotenv').config();

const app                  = express();
const PORT                 = process.env.PORT || 3000;
const ALLOWED_ORIGINS      = ['https://sicklv.shop'];
const ALLOWED_COUNTRIES    = ['SA', 'AE', 'KW', 'QA', 'OM', 'BH', 'EG', 'JO', 'SD'];
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY || "";

// نظام التسجيل الدقيق بالنظام
const logger = winston.createLogger({
  transports: [
    new winston.transports.File({ filename: 'activity.log' }),
    new winston.transports.Console()
  ]
});

// رؤوس وحماية أمان متقدمة
app.use(helmet());
app.use(helmet.hsts({
  maxAge: 63072000,
  includeSubDomains: true,
  preload: true
}));
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc:  ["'self'", "https://www.google.com", "https://www.gstatic.com"],
    styleSrc:   ["'self'", "'unsafe-inline'"],
    imgSrc:     ["'self'", "data:", "https://www.google.com", "https://www.gstatic.com"],
    objectSrc:  ["'none'"],
    frameAncestors: ["'none'"],
    upgradeInsecureRequests: [],
    baseUri:    ["'self'"],
    formAction: ["'self'"]
  }
}));

// تفعيل CORS للمجالات المصرح بها فقط
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('غير مسموح'));
    }
  },
  optionsSuccessStatus: 200,
  credentials: true
}));

// أنواع حماية إضافية
app.use(hpp());
app.use(xssClean());
app.use(mongoSanitize());
app.use(express.json({ limit: '12kb' }));

// تحديد الحد الأعلى للطلبات (30 طلب لكل 15 دقيقة)
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "تم تقييد طلبك مؤقتاً."
  }
}));
app.use(useragent.express());

// الحجب الجغرافي بناءً على الدولة
app.use((req, res, next) => {
  const ip  = req.headers['cf-connecting-ip'] || req.ip;
  const geo = geoip.lookup(ip);
  if (geo && geo.country && !ALLOWED_COUNTRIES.includes(geo.country)) {
    logger.warn(`[GeoBlock]: البلد = ${geo.country} - IP: ${ip}`);
    return res.status(403).json({ success: false, message: "الوصول مرفوض من منطقتك." });
  }
  next();
});

// تسجيل حركة كل طلب
app.use((req, res, next) => {
  logger.info(`[${new Date().toISOString()}] [${req.ip}] [UA:${req.useragent.source}] ${req.method} ${req.originalUrl}`);
  next();
});

// تقديم ملفات ثابته (اختياري)
app.use(express.static(path.join(__dirname, 'public')));

// دالة لحساب عدد الأيام بين تاريخين
function calcDays(start, end) {
  try {
    const s = new Date(start);
    const e = new Date(end);
    if (isNaN(s) || isNaN(e) || e < s) return 0;
    return Math.floor((e - s) / (1000 * 60 * 60 * 24)) + 1;
  } catch { return 0; }
}

// بيانات الإجازات الافتراضية
const leavesRaw = [
  {serviceCode: "GSL25021372778", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-02-09", startDate: "2025-02-09", endDate: "2025-02-24", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري"},
  {serviceCode: "GSL25021898579", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-02-25", startDate: "2025-02-25", endDate: "2025-03-26", doctorName: "جمال راشد السر محمد احمد", jobTitle: "استشاري"},
  {serviceCode: "GSL25022385036", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-03-27", startDate: "2025-03-27", endDate: "2025-04-17", doctorName: "جمال راشد السر محمد احمد", jobTitle: "استشاري"},
  {serviceCode: "GSL25022884602", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-04-18", startDate: "2025-04-18", endDate: "2025-05-15", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري"},
  {serviceCode: "GSL25023345012", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-05-16", startDate: "2025-05-16", endDate: "2025-06-12", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري"},
  {serviceCode: "GSL25062955824", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-06-13", startDate: "2025-06-13", endDate: "2025-07-11", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري"},
  {serviceCode: "GSL25071678945", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-07-12", startDate: "2025-07-12", endDate: "2025-07-17", doctorName: "عبدالعزيز فهد هميجان الروقي", jobTitle: "استشاري"}
];

// إضافة days لكل سجل
const leaves = leavesRaw.map(rec => ({
  ...rec,
  days: calcDays(rec.startDate, rec.endDate)
}));

// استعلام عن الإجازة
app.post('/api/leave', async (req, res) => {
  const { serviceCode, idNumber, captchaToken } = req.body;
  if (
    typeof serviceCode !== 'string' || !/^[A-Za-z0-9]{8,20}$/.test(serviceCode) ||
    typeof idNumber !== 'string' || !/^[0-9]{10}$/.test(idNumber)
  ) {
    return res.status(400).json({ success: false, message: "البيانات غير صحيحة." });
  }

  // تحقق reCAPTCHA
  if (RECAPTCHA_SECRET_KEY && captchaToken) {
    try {
      const resp = await axios.post(
        'https://www.google.com/recaptcha/api/siteverify',
        new URLSearchParams({
          secret: RECAPTCHA_SECRET_KEY,
          response: captchaToken
        }).toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      if (!resp.data.success || (resp.data.score !== undefined && resp.data.score < 0.5)) {
        logger.warn(`[reCAPTCHA]: فشل التحقق من ${req.ip}`);
        return res.status(403).json({ success: false, message: "فشل التحقق الأمني." });
      }
    } catch (err) {
      logger.error(`[reCAPTCHA] خطأ جوجل: ${err.message}`);
      return res.status(500).json({ success: false, message: "خطأ في التحقق الأمني." });
    }
  }

  const record = leaves.find(
    item => item.serviceCode === serviceCode && item.idNumber === idNumber
  );

  if (record) {
    return res.json({ success: true, record });
  }
  res.status(404).json({ success: false, message: "لا يوجد سجل مطابق." });
});

// إضافة إجازة جديدة
app.post('/api/add-leave', (req, res) => {
  const { serviceCode, idNumber, name, reportDate, startDate, endDate, doctorName, jobTitle } = req.body;
  if (
    typeof serviceCode !== 'string' || !/^[A-Za-z0-9]{8,20}$/.test(serviceCode) ||
    typeof idNumber   !== 'string' || !/^[0-9]{10}$/.test(idNumber) ||
    typeof name       !== 'string' ||
    typeof reportDate !== 'string' ||
    typeof startDate  !== 'string' ||
    typeof endDate    !== 'string' ||
    typeof doctorName !== 'string' ||
    typeof jobTitle   !== 'string'
  ) {
    return res.status(400).json({ success: false, message: "مدخلات غير صحيحة." });
  }

  leaves.push({
    serviceCode,
    idNumber,
    name,
    reportDate,
    startDate,
    endDate,
    doctorName,
    jobTitle,
    days: calcDays(startDate, endDate)
  });

  return res.json({ success: true, message: "تمت إضافة الإجازة بنجاح." });
});

// أي مسار غير موجود
app.use((req, res) => {
  res.status(404).json({ success: false, message: "الصفحة غير موجودة." });
});

// إيقاف آمن للخدمة
process.on('SIGTERM', () => {
  logger.info("تم إيقاف الخدمة بطاقة عالية الأمان.");
  process.exit(0);
});

app.listen(PORT, () => {
  logger.info(`✅ SickLV Ultra Secure API is running on port ${PORT}`);
});