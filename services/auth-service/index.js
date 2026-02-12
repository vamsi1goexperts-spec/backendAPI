const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const twilio = require('twilio');
require('dotenv').config({ path: '../../.env' });

const app = express();
const PORT = process.env.AUTH_SERVICE_URL?.split(':')[2] || 3001;

// Middleware
app.use(cors({ origin: '*' })); // Allow all origins for testing
app.use(express.json());

// In-memory OTP storage (for testing - replace with Redis in production)
const otpStore = new Map();

// Twilio client (optional for testing)
let twilioClient = null;
try {
    twilioClient = twilio(
        process.env.TWILIO_ACCOUNT_SID,
        process.env.TWILIO_AUTH_TOKEN
    );
} catch (error) {
    console.log('⚠️  Twilio not configured - using test mode');
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

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Auth Service: MongoDB connected'))
    .catch(err => console.error('❌ MongoDB connection error:', err));

// Generate OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Routes

// Send OTP
app.post('/api/auth/send-otp', async (req, res) => {
    try {
        const { phone } = req.body;

        if (!phone) {
            return res.status(400).json({ error: 'Phone number required' });
        }

        const otp = generateOTP();

        // Store OTP in memory (5 minutes expiry)
        otpStore.set(phone, { otp, expires: Date.now() + 300000 });

        // Clean up expired OTPs
        setTimeout(() => otpStore.delete(phone), 300000);

        // Send OTP via Twilio
        if (twilioClient) {
            try {
                await twilioClient.messages.create({
                    body: `Your INFLIQ verification code is: ${otp}`,
                    from: process.env.TWILIO_PHONE_NUMBER,
                    to: phone
                });
                console.log(`✅ OTP sent via Twilio to ${phone}`);
            } catch (twilioError) {
                console.log('⚠️  Twilio error:', twilioError.message);
                console.log(`📱 TEST MODE - OTP for ${phone}: ${otp}`);
            }
        } else {
            console.log(`📱 TEST MODE - OTP for ${phone}: ${otp}`);
        }
        res.json({ success: true, message: 'OTP sent successfully', testOTP: otp }); // Include OTP in response for testing
    } catch (error) {
        console.error('Send OTP error:', error);
        res.status(500).json({ error: 'Failed to send OTP', details: error.message });
    }
});

// Verify OTP & Register/Login
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { phone, otp, name, age } = req.body;

        if (!phone || !otp) {
            return res.status(400).json({ error: 'Phone and OTP required' });
        }

        // Verify OTP from memory
        const stored = otpStore.get(phone);

        if (!stored || stored.otp !== otp) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        // Check if OTP expired
        if (Date.now() > stored.expires) {
            otpStore.delete(phone);
            return res.status(400).json({ error: 'OTP expired' });
        }

        // Delete OTP after verification
        otpStore.delete(phone);

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
            user: {
                id: user._id,
                name: user.name,
                phone: user.phone,
                age: user.age,
                isVerified: user.isVerified
            }
        });
    } catch (error) {
        console.error('Verify OTP error:', error);
        res.status(500).json({ error: 'Verification failed', details: error.message });
    }
});

// Email/Password Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        const user = await User.findOne({ email });

        if (!user || !user.password) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                phone: user.phone
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed', details: error.message });
    }
});

// Register with Email/Password
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phone, age } = req.body;

        if (!name || !email || !password || !phone) {
            return res.status(400).json({ error: 'All fields required' });
        }

        const existingUser = await User.findOne({ $or: [{ email }, { phone }] });

        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
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
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                phone: user.phone
            }
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'Registration failed', details: error.message });
    }
});

// Refresh Token
app.post('/api/auth/refresh', async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(400).json({ error: 'Refresh token required' });
        }

        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);

        const newToken = jwt.sign(
            { userId: decoded.userId },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.json({ success: true, token: newToken });
    } catch (error) {
        res.status(401).json({ error: 'Invalid refresh token' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', service: 'auth-service' });
});

app.listen(PORT, () => {
    console.log(`🚀 Auth Service running on port ${PORT}`);
});
