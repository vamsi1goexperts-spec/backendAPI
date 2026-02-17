const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { getAllowedOrigins } = require('./config');

const buildCors = () => {
    const allowedOrigins = getAllowedOrigins();
    if (allowedOrigins.includes('*')) {
        return cors({ origin: '*' });
    }

    return cors({
        origin: (origin, callback) => {
            // Allow server-to-server and non-browser clients.
            if (!origin) return callback(null, true);
            if (allowedOrigins.includes(origin)) return callback(null, true);
            return callback(new Error('Not allowed by CORS'));
        },
        credentials: true
    });
};

const buildLimiter = () => rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
    max: parseInt(process.env.RATE_LIMIT_MAX || '300', 10),
    standardHeaders: true,
    legacyHeaders: false
});

const applyCommonSecurity = (app) => {
    app.set('trust proxy', 1);
    app.use(helmet());
    app.use(buildCors());
    app.use(buildLimiter());
};

module.exports = {
    applyCommonSecurity
};

