const path = require('path');
const dotenv = require('dotenv');

const resolvedEnvPath = path.resolve(__dirname, '../../.env');
dotenv.config({ path: resolvedEnvPath });

const isProduction = process.env.NODE_ENV === 'production';
const strictProductionMode = (process.env.STRICT_PRODUCTION_MODE || 'true').toLowerCase() === 'true';

const parseAllowedOrigins = () => {
    const raw = process.env.ALLOWED_ORIGINS || '';
    return raw
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean);
};

const getAllowedOrigins = () => {
    const origins = parseAllowedOrigins();
    if (!isProduction && origins.length === 0) {
        return ['*'];
    }
    return origins;
};

const requiredInProduction = (keys) => {
    if (!isProduction) return;
    const missing = keys.filter((key) => !process.env[key] || !process.env[key].trim());
    if (missing.length > 0) {
        throw new Error(`Missing required env vars in production: ${missing.join(', ')}`);
    }
};

module.exports = {
    isProduction,
    strictProductionMode,
    getAllowedOrigins,
    requiredInProduction
};

