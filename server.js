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
  message: {
    success: false,
    message: "تم تقييد طلبك مؤقتاً."
  }
}));

// ===== تسجيل حركة كل طلب =====
app.use((req, res, next) => {
  logger.info(
    `[IP: ${req.ip}] [UA: ${req.useragent.source}] ${req.method} ${req.originalUrl}`
  );
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
const
