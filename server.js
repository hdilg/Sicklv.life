// server.js — منصة إدارة إجازات Sicklv (النسخة النهائية للرفع على Render)

const express       = require('express');
const helmet        = require('helmet');
const compression   = require('compression');
const cors          = require('cors');
const rateLimit     = require('express-rate-limit');
const slowDown      = require('express-slow-down');
const hpp           = require('hpp');
const mongoSanitize = require('express-mongo-sanitize');
const xssClean      = require('xss-clean');
const useragent     = require('express-useragent');
const winston       = require('winston');
const path          = require('path');
const Joi           = require('joi');
const jwt           = require('jsonwebtoken');

const PORT       = process.env.PORT || process.env.npm_package_config_port || 3000;
const JWT_SECRET = process.env.JWT_SECRET || process.env.npm_package_config_jwt_secret;

if (!JWT_SECRET) {
  console.error('❌ JWT_SECRET غير موجود، أوقف التشغيل.');
  process.exit(1);
}

const app = express();

// ===== إعدادات تسجيل اللوغ =====
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(info =>
      `[${info.timestamp}] ${info.level.toUpperCase()}: ${info.message}`)
  ),
  transports: [
    new winston.transports.Console()
  ]
});

app.disable('x-powered-by');
app.set('trust proxy', true);

// ===== الحماية =====
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(helmet.hsts({ maxAge: 31536000, preload: true }));
app.use(helmet.referrerPolicy({ policy: 'strict-origin' }));
app.use(helmet.noSniff());
app.use(helmet.permittedCrossDomainPolicies());
app.use(compression());
app.use(hpp());
app.use(xssClean());
app.use(mongoSanitize());

// ===== مدخلات ومراقبة =====
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(cors({
  origin: ['https://sicklv.shop', 'https://sicklv.life'],
  credentials: true
}));
app.use(useragent.express());
app.use((req, res, next) => {
  logger.info(`${req.ip} | ${req.useragent.platform} | ${req.method} ${req.originalUrl}`);
  next();
});

app.use(express.static(path.join(__dirname, 'public'), {
  dotfiles: 'deny',
  index: false
}));

// ===== المساعدة =====
const calcDays = (start, end) => {
  const s = new Date(start), e = new Date(end);
  if (isNaN(s) || isNaN(e) || e < s) return 0;
  return Math.floor((e - s) / (86400000)) + 1;
};

const leavesRaw = [ /* سجلات تجريبية */ ];
const leaves = leavesRaw.map(r => ({ ...r, days: calcDays(r.startDate, r.endDate) }));

// ===== الحماية الخاصة =====
const leaveLimiter = rateLimit({ windowMs: 60000, max: 10 });
const addLeaveLimiter = rateLimit({ windowMs: 60000, max: 3 });
const leaveSlowDown = slowDown({ windowMs: 60000, delayAfter: 5, delayMs: 500 });

const authenticate = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer '))
    return res.status(401).json({ success: false, message: 'Missing token.' });

  try {
    req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ success: false, message: 'Invalid token.' });
  }
};

// ===== التحقق من المدخلات =====
const leaveSchema = Joi.object({
  serviceCode: Joi.string().alphanum().min(8).max(20).required(),
  idNumber: Joi.string().pattern(/^[0-9]{10}$/).required()
});
const addLeaveSchema = Joi.object({
  serviceCode: Joi.string().alphanum().min(8).max(20).required(),
  idNumber: Joi.string().pattern(/^[0-9]{10}$/).required(),
  name: Joi.string().min(3).max(100).required(),
  reportDate: Joi.date().iso().required(),
  startDate: Joi.date().iso().required(),
  endDate: Joi.date().iso().required(),
  doctorName: Joi.string().min(3).max(100).required(),
  jobTitle: Joi.string().min(3).max(100).required()
});

// ===== المسارات =====
app.post('/api/leave', leaveLimiter, leaveSlowDown, (req, res, next) => {
  const { error, value } = leaveSchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: 'Invalid input.' });
  req.validated = value; next();
}, (req, res) => {
  const { serviceCode, idNumber } = req.validated;
  const record = leaves.find(l => l.serviceCode === serviceCode && l.idNumber === idNumber);
  if (!record) return res.status(404).json({ success: false, message: 'Not found.' });
  res.json({ success: true, record });
});

app.post('/api/add-leave', authenticate, addLeaveLimiter, leaveSlowDown, (req, res, next) => {
  const { error, value } = addLeaveSchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: 'Invalid input.' });
  req.validated = value; next();
}, (req, res) => {
  const r = req.validated;
  leaves.push({ ...r, days: calcDays(r.startDate, r.endDate) });
  res.json({ success: true, message: 'Leave added.' });
});

app.get('/api/leaves', authenticate, (req, res) => {
  res.json({ success: true, leaves });
});

// ===== المعالجات النهائية =====
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found.' });
});
app.use((err, req, res, next) => {
  logger.error(err.stack);
  res.status(500).json({ success: false, message: 'Internal server error.' });
});
process.on('SIGTERM', () => {
  logger.info('SIGTERM received — shutting down.');
  process.exit(0);
});

app.listen(PORT, () => {
  logger.info(`✅ Sicklv API جاهز ويستمع على المنفذ ${PORT}`);
});
