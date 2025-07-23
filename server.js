// server.js — منصة إدارة إجازات "عبدالإله سليمان عبدالله الهديلج"

const express       = require('express');
const helmet        = require('helmet');
const cors          = require('cors');
const rateLimit     = require('express-rate-limit');
const hpp           = require('hpp');
const useragent     = require('express-useragent');
const winston       = require('winston');
const axios         = require('axios');
const xssClean      = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');
const path          = require('path');

const app              = express();
const PORT             = process.env.PORT || 3000;
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || '';

// إذا كان الخادم خلف CDN أو Load Balancer
app.set('trust proxy', 1);

// إعداد Winston للتسجيل
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(info =>
      `[${info.timestamp}] ${info.level.toUpperCase()}: ${info.message}`
    )
  ),
  transports: [
    new winston.transports.File({ filename: 'activity.log', maxsize: 5_000_000, maxFiles: 3 }),
    new winston.transports.Console()
  ]
});

// ===== رؤوس الأمان =====
app.use(helmet());
app.use(helmet.hsts({
  maxAge: 2 * 365 * 24 * 60 * 60,
  includeSubDomains: true,
  preload: true
}));
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc:  ["'self'", "https://www.google.com", "https://www.gstatic.com"],
    styleSrc:   ["'self'", "'unsafe-inline'"],
    imgSrc:     ["'self'", "data:"],
    objectSrc:  ["'none'"],
    frameAncestors: ["'none'"],
    baseUri:    ["'self'"],
    formAction: ["'self'"],
    upgradeInsecureRequests: []
  }
}));

// ===== إلغاء قيود CORS تمامًا =====
app.use(cors());

// ===== حماية إضافية وميدل‌ويرات =====
app.use(hpp());
app.use(xssClean());
app.use(mongoSanitize());
app.use(express.json({ limit: '16kb' }));
app.use(useragent.express());

// ===== تحديد الحد الأعلى للطلبات =====
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 30,                  // 30 طلب لكل IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "تم تقييد طلبك مؤقتاً." }
}));

// ===== تسجيل حركة كل طلب =====
app.use((req, res, next) => {
  logger.info(`[IP: ${req.ip}] [UA: ${req.useragent.source}] ${req.method} ${req.originalUrl}`);
  next();
});

// ===== تقديم ملفات الواجهة الثابتة =====
app.use(express.static(path.join(__dirname, 'public')));

// ===== دالة لحساب عدد الأيام =====
function calcDays(start, end) {
  const s = new Date(start), e = new Date(end);
  if (isNaN(s) || isNaN(e) || e < s) return 0;
  return Math.floor((e - s) / (1000 * 60 * 60 * 24)) + 1;
}

// ===== بيانات الإجازات الافتراضية =====
const leavesRaw = [
  {
    serviceCode: "GSL25021372778", idNumber: "1088576044",
    name: "عبدالإله سليمان عبدالله الهديلج",
    reportDate: "2025-02-09", startDate: "2025-02-09",
    endDate: "2025-02-24", doctorName: "هدى مصطفى خضر دحبور",
    jobTitle: "استشاري"
  },
  {
    serviceCode: "GSL25021898579", idNumber: "1088576044",
    name: "عبدالإله سليمان عبدالله الهديلج",
    reportDate: "2025-02-25", startDate: "2025-02-25",
    endDate: "2025-03-26", doctorName: "جمال راشد السر محمد احمد",
    jobTitle: "استشاري"
  },
  {
    serviceCode: "GSL25022385036", idNumber: "1088576044",
    name: "عبدالإله سليمان عبدالله الهديلج",
    reportDate: "2025-03-27", startDate: "2025-03-27",
    endDate: "2025-04-17", doctorName: "جمال راشد السر محمد احمد",
    jobTitle: "استشاري"
  },
  {
    serviceCode: "GSL25022884602", idNumber: "1088576044",
    name: "عبدالإله سليمان عبدالله الهديلج",
    reportDate: "2025-04-18", startDate: "2025-04-18",
    endDate: "2025-05-15", doctorName: "هدى مصطفى خضر دحبور",
    jobTitle: "استشاري"
  },
  {
    serviceCode: "GSL25023345012", idNumber: "1088576044",
    name: "عبدالإله سليمان عبدالله الهديلج",
    reportDate: "2025-05-16", startDate: "2025-05-16",
    endDate: "2025-06-12", doctorName: "هدى مصطفى خضر دحبور",
    jobTitle: "استشاري"
  },
  {
    serviceCode: "GSL25062955824", idNumber: "1088576044",
    name: "عبدالإله سليمان عبدالله الهديلج",
    reportDate: "2025-06-13", startDate: "2025-06-13",
    endDate: "2025-07-11", doctorName: "هدى مصطفى خضر دحبور",
    jobTitle: "استشاري"
  },
  {
    serviceCode: "GSL25071678945", idNumber: "1088576044",
    name: "عبدالإله سليمان عبدالله الهديلج",
    reportDate: "2025-07-12", startDate: "2025-07-12",
    endDate: "2025-07-17", doctorName: "عبدالعزيز فهد هميجان الروقي",
    jobTitle: "استشاري"
  }
];
const leaves = leavesRaw.map(rec => ({ ...rec, days: calcDays(rec.startDate, rec.endDate) }));

// ===== مسار استعلام الإجازة =====
app.post('/api/leave', async (req, res) => {
  const { serviceCode, idNumber, captchaToken } = req.body;

  // التحقق من صحة المدخلات
  if (
    typeof serviceCode !== 'string' || !/^[A-Za-z0-9]{8,20}$/.test(serviceCode) ||
    typeof idNumber   !== 'string' || !/^[0-9]{10}$/.test(idNumber)
  ) {
    return res.status(400).json({ success: false, message: "البيانات غير صحيحة." });
  }

  // reCAPTCHA اختياري
  if (RECAPTCHA_SECRET && captchaToken) {
    try {
      const resp = await axios.post(
        'https://www.google.com/recaptcha/api/siteverify',
        new URLSearchParams({ secret: RECAPTCHA_SECRET, response: captchaToken }).toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      if (!resp.data.success || (resp.data.score !== undefined && resp.data.score < 0.5)) {
        logger.warn(`[reCAPTCHA Failed] IP: ${req.ip}`);
        return res.status(403).json({ success: false, message: "فشل التحقق الأمني." });
      }
    } catch (err) {
      logger.error(`[reCAPTCHA Error] ${err.message}`);
      return res.status(500).json({ success: false, message: "خطأ أثناء التحقق الأمني." });
    }
  }

  // البحث عن السجل
  const record = leaves.find(item =>
    item.serviceCode === serviceCode && item.idNumber === idNumber
  );
  if (record) {
    return res.json({ success: true, record });
  }
  return res.status(404).json({ success: false, message: "لا يوجد سجل مطابق." });
});

// ===== مسار إضافة إجازة جديدة =====
app.post('/api/add-leave', (req, res) => {
  const {
    serviceCode, idNumber, name,
    reportDate, startDate, endDate,
    doctorName, jobTitle
  } = req.body;

  // التحقق من صحة البيانات
  if (
    typeof serviceCode !== 'string' || !/^[A-Za-z0-9]{8,20}$/.test(serviceCode) ||
    typeof idNumber   !== 'string' || !/^[0-9]{10}$/.test(idNumber) ||
    typeof name       !== 'string' || !name.trim() ||
    typeof reportDate !== 'string' || !Date.parse(reportDate) ||
    typeof startDate  !== 'string' || !Date.parse(startDate) ||
    typeof endDate    !== 'string' || !Date.parse(endDate) ||
    typeof doctorName !== 'string' || !doctorName.trim() ||
    typeof jobTitle   !== 'string' || !jobTitle.trim()
  ) {
    return res.status(400).json({ success: false, message: "مدخلات غير صحيحة." });
  }

  leaves.push({
    serviceCode, idNumber, name,
    reportDate, startDate, endDate,
    doctorName, jobTitle,
    days: calcDays(startDate, endDate)
  });
  return res.json({ success: true, message: "تمت إضافة الإجازة بنجاح." });
});

// ===== مسار عرض جميع الإجازات =====
app.get('/api/leaves', (req, res) => {
  res.json({ success: true, leaves });
});

// ===== مسار 404 لجميع المسارات الأخرى =====
app.use((req, res) => {
  res.status(404).json({ success: false, message: "الصفحة غير موجودة." });
});

// ===== إيقاف آمن =====
process.on('SIGTERM', () => {
  logger.info("تم إيقاف الخدمة بأمان.");
  process.exit(0);
});

// ===== بدء الاستماع =====
app.listen(PORT, () => {
  logger.info(`✅ SickLV API تعمل على المنفذ ${PORT}`);
});
