const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const twilio = require('twilio');
const { createClient } = require('redis');
const { requiredInProduction, isProduction, strictProductionMode } = require('../_shared/config');
const { applyCommonSecurity } = require('../_shared/security');
const { applyRequestContext } = require('../_shared/observability');
const { logEvent } = require('../_shared/logger');
const { sendError, ErrorCodes } = require('../_shared/http');

const app = express();
const PORT = process.env.AUTH_SERVICE_URL?.split(':')[2] || 3001;

requiredInProduction(['MONGO_URI', 'JWT_SECRET', 'JWT_EXPIRES_IN', 'REDIS_URL']);

// Middleware
applyRequestContext(app);
applyCommonSecurity(app);
app.use(express.json());

// In-memory OTP storage (for testing - replace with Redis in production)
const otpStore = new Map();
const otpRequestTracker = new Map();
const OTP_TTL_SECONDS = parseInt(process.env.OTP_TTL_SECONDS || '300', 10);
const OTP_WINDOW_MS = parseInt(process.env.OTP_WINDOW_MS || '600000', 10);
const OTP_WINDOW_SECONDS = Math.max(1, Math.ceil(OTP_WINDOW_MS / 1000));
const OTP_MAX_PER_WINDOW = parseInt(process.env.OTP_MAX_PER_WINDOW || '5', 10);
const redisUrl = process.env.REDIS_URL || '';
let redisClient = null;
let redisReady = false;

const otpKey = (phone) => `auth:otp:${phone}`;
const otpRateKey = (phone) => `auth:otp:rl:${phone}`;

const initRedis = async () => {
    if (!redisUrl) {
        if (isProduction && strictProductionMode) {
            throw new Error('REDIS_URL is required in strict production mode');
        }
        return;
    }
    try {
        redisClient = createClient({ url: redisUrl });
        redisClient.on('error', (error) => {
            redisReady = false;
            logEvent('auth-service', 'warn', 'redis.error', { error: error.message });
        });
        redisClient.on('ready', () => {
            redisReady = true;
            logEvent('auth-service', 'info', 'redis.connected');
        });
        await redisClient.connect();
    } catch (error) {
        redisReady = false;
        redisClient = null;
        if (isProduction && strictProductionMode) {
            throw new Error(`Redis unavailable in strict production mode: ${error.message}`);
        }
        logEvent('auth-service', 'warn', 'redis.fallback_inmemory', { error: error.message });
    }
};

const setOtp = async (phone, otp) => {
    if (redisReady && redisClient) {
        await redisClient.setEx(otpKey(phone), OTP_TTL_SECONDS, otp);
        return;
    }
    otpStore.set(phone, { otp, expires: Date.now() + OTP_TTL_SECONDS * 1000 });
    setTimeout(() => otpStore.delete(phone), OTP_TTL_SECONDS * 1000);
};

const getOtp = async (phone) => {
    if (redisReady && redisClient) {
        const otp = await redisClient.get(otpKey(phone));
        return otp ? { otp, expires: null } : null;
    }
    return otpStore.get(phone);
};

const deleteOtp = async (phone) => {
    if (redisReady && redisClient) {
        await redisClient.del(otpKey(phone));
        return;
    }
    otpStore.delete(phone);
};

setInterval(() => {
    if (redisReady) return;
    const now = Date.now();
    for (const [phone, timestamps] of otpRequestTracker.entries()) {
        const recent = timestamps.filter((ts) => now - ts <= OTP_WINDOW_MS);
        if (recent.length === 0) otpRequestTracker.delete(phone);
        else otpRequestTracker.set(phone, recent);
    }
}, Math.max(30000, OTP_WINDOW_MS)).unref();

// Twilio client (optional for testing)
let twilioClient = null;
const twilioEnabled = Boolean(
    process.env.TWILIO_ACCOUNT_SID &&
    process.env.TWILIO_AUTH_TOKEN &&
    process.env.TWILIO_PHONE_NUMBER
);
try {
    if (twilioEnabled) {
        twilioClient = twilio(
            process.env.TWILIO_ACCOUNT_SID,
            process.env.TWILIO_AUTH_TOKEN
        );
    }
} catch (error) {
    logEvent('auth-service', 'warn', 'twilio.not_configured');
}

// MongoDB User Schema
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true, sparse: true },
    phone: { type: String, unique: true, required: true },
    password: String,
    age: Number,
    isVerified: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

const serializeUser = (user) => ({
    _id: user._id,
    id: user._id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    age: user.age,
    isVerified: Boolean(user.isVerified)
});

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => logEvent('auth-service', 'info', 'mongodb.connected'))
    .catch(err => logEvent('auth-service', 'error', 'mongodb.connection_failed', { error: err.message }));
initRedis().catch((error) => {
    logEvent('auth-service', 'error', 'startup.dependency_failed', { error: error.message });
    process.exit(1);
});

// Generate OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

async function canSendOtp(phone) {
    if (redisReady && redisClient) {
        const count = await redisClient.incr(otpRateKey(phone));
        if (count === 1) {
            await redisClient.expire(otpRateKey(phone), OTP_WINDOW_SECONDS);
        }
        return count <= OTP_MAX_PER_WINDOW;
    }
    const now = Date.now();
    const recent = (otpRequestTracker.get(phone) || []).filter((ts) => now - ts <= OTP_WINDOW_MS);
    if (recent.length >= OTP_MAX_PER_WINDOW) return false;
    recent.push(now);
    otpRequestTracker.set(phone, recent);
    return true;
}

// Routes

// Send OTP
app.post('/api/auth/send-otp', async (req, res) => {
    try {
        const { phone } = req.body;

        if (!phone) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'Phone number required');
        }
        if (!(await canSendOtp(phone))) {
            return sendError(res, 429, ErrorCodes.RATE_LIMITED, 'Too many OTP requests. Please try again later.');
        }

        const otp = generateOTP();

        await setOtp(phone, otp);

        // Non-blocking SMS dispatch keeps auth API responsive even if SMS provider is degraded.
        if (twilioClient) {
            twilioClient.messages.create({
                    body: `Your INFLIQ verification code is: ${otp}`,
                    from: process.env.TWILIO_PHONE_NUMBER,
                    to: phone
                })
                .then(() => {
                logEvent('auth-service', 'info', 'otp.sent_twilio', { phone });
                })
                .catch((twilioError) => {
                    logEvent('auth-service', 'warn', 'otp.twilio_failed', { error: twilioError.message });
                });
        }
        res.json({ success: true, message: 'OTP sent successfully' });
    } catch (error) {
        logEvent('auth-service', 'error', 'otp.send_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to send OTP', error.message);
    }
});

// Verify OTP & Register/Login
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { phone, otp, name, age } = req.body;

        if (!phone || !otp) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'Phone and OTP required');
        }

        // Verify OTP from memory
        const stored = await getOtp(phone);

        if (!stored || stored.otp !== otp) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'Invalid or expired OTP');
        }

        // Check if OTP expired
        if (Date.now() > stored.expires) {
            await deleteOtp(phone);
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'OTP expired');
        }

        // Delete OTP after verification
        await deleteOtp(phone);

        // Find or create user
        let user = await User.findOne({ phone });

        if (!user) {
            // Register new user
            user = new User({
                phone,
                name: name || 'User',
                age: age || null,
                isVerified: true
            });
            await user.save();
        } else {
            // Update verification status
            user.isVerified = true;
            await user.save();
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, phone: user.phone },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        const refreshToken = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN }
        );

        res.json({
            success: true,
            token,
            refreshToken,
            user: serializeUser(user)
        });
    } catch (error) {
        logEvent('auth-service', 'error', 'otp.verify_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Verification failed', error.message);
    }
});

// Email/Password Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'Email and password required');
        }

        const user = await User.findOne({ email });

        if (!user || !user.password) {
            return sendError(res, 401, ErrorCodes.UNAUTHORIZED, 'Invalid credentials');
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return sendError(res, 401, ErrorCodes.UNAUTHORIZED, 'Invalid credentials');
        }

        const token = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.json({
            success: true,
            token,
            user: serializeUser(user)
        });
    } catch (error) {
        logEvent('auth-service', 'error', 'auth.login_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Login failed', error.message);
    }
});

// Register with Email/Password
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phone, age } = req.body;

        if (!name || !email || !password || !phone) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'All fields required');
        }

        const existingUser = await User.findOne({ $or: [{ email }, { phone }] });

        if (existingUser) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'User already exists');
        }

        const hashedPassword = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS));

        const user = new User({
            name,
            email,
            phone,
            password: hashedPassword,
            age
        });

        await user.save();

        const token = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.json({
            success: true,
            token,
            user: serializeUser(user)
        });
    } catch (error) {
        logEvent('auth-service', 'error', 'auth.register_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Registration failed', error.message);
    }
});

// Refresh Token
app.post('/api/auth/refresh', async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'Refresh token required');
        }

        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);

        const newToken = jwt.sign(
            { userId: decoded.userId },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.json({ success: true, token: newToken });
    } catch (error) {
        return sendError(res, 401, ErrorCodes.INVALID_TOKEN, 'Invalid refresh token');
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', service: 'auth-service' });
});

app.listen(PORT, () => {
    logEvent('auth-service', 'info', 'service.started', { port: PORT });
});
