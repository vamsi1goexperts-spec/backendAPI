const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const twilio = require('twilio');
const AccessToken = twilio.jwt.AccessToken;
const VideoGrant = AccessToken.VideoGrant;
const AWS = require('aws-sdk');
const multer = require('multer');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({ origin: '*' }));
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ MongoDB connected'))
    .catch(err => console.error('❌ MongoDB error:', err));

// Twilio Setup (optional)
let twilioClient = null;
try {
    twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
} catch (error) {
    console.log('⚠️  Twilio not configured - using test mode');
}

// AWS S3 Setup
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION
});

// Multer for file uploads
const upload = multer({ storage: multer.memoryStorage() });

// In-memory OTP storage
const otpStore = new Map();

// ==================== SCHEMAS ====================

// User Schema
const userSchema = new mongoose.Schema({
    phone: { type: String, unique: true, sparse: true },
    email: { type: String, unique: true, sparse: true },
    password: String,
    name: String,
    age: Number,
    bio: String,
    profilePicture: String,
    location: {
        type: String,  // Simplified - just store as string or null
        coordinates: [Number]
    },
    category: { type: String, default: 'global' },
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Post Schema
const postSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['post', 'reel'], default: 'post' },
    content: String,
    mediaUrl: String,
    mediaType: { type: String, enum: ['image', 'video'] },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    comments: [{
        userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        text: String,
        createdAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', postSchema);

// Chat Schema
const chatSchema = new mongoose.Schema({
    type: { type: String, enum: ['chat', 'community', 'debate'], default: 'chat' },
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    messages: [{
        senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        text: String,
        createdAt: { type: Date, default: Date.now },
        read: { type: Boolean, default: false }
    }],
    lastMessage: String,
    lastMessageAt: Date,
    createdAt: { type: Date, default: Date.now }
});
const Chat = mongoose.model('Chat', chatSchema);

// Call Schema
const callSchema = new mongoose.Schema({
    callerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['audio', 'video'], default: 'video' },
    status: { type: String, enum: ['ringing', 'active', 'ended', 'rejected', 'missed'], default: 'ringing' },
    roomName: String,
    startedAt: Date,
    endedAt: Date,
    duration: Number,
    createdAt: { type: Date, default: Date.now }
});
const Call = mongoose.model('Call', callSchema);

// ==================== AUTH MIDDLEWARE ====================

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access denied' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// ==================== AUTH ROUTES ====================

// Send OTP
app.post('/api/auth/send-otp', async (req, res) => {
    try {
        const { phone } = req.body;
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        otpStore.set(phone, otp);
        setTimeout(() => otpStore.delete(phone), 300000); // 5 min expiry

        if (twilioClient) {
            try {
                await twilioClient.messages.create({
                    body: `Your INFLIQ verification code is: ${otp}`,
                    from: process.env.TWILIO_PHONE_NUMBER,
                    to: phone
                });
                console.log(`✅ OTP sent via Twilio to ${phone}`);
            } catch (twilioError) {
                console.log(`📱 TEST MODE - OTP for ${phone}: ${otp}`);
            }
        } else {
            console.log(`📱 TEST MODE - OTP for ${phone}: ${otp}`);
        }

        res.json({ success: true, message: 'OTP sent successfully', testOTP: otp });
    } catch (error) {
        console.error('Send OTP error:', error);
        res.status(500).json({ error: 'Failed to send OTP' });
    }
});

// Verify OTP
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { phone, otp } = req.body;
        console.log(`🔍 Verifying OTP for ${phone}, received: ${otp}`);
        const storedOTP = otpStore.get(phone);
        console.log(`🔍 Stored OTP: ${storedOTP}`);

        if (!storedOTP || storedOTP !== otp) {
            console.log(`❌ OTP mismatch or not found`);
            return res.status(400).json({ error: 'Invalid OTP' });
        }

        otpStore.delete(phone);

        let user = await User.findOne({ phone });
        if (!user) {
            user = await User.create({ phone });
            console.log(`✅ Created new user: ${user._id}`);
        } else {
            console.log(`✅ Found existing user: ${user._id}`);
        }

        const token = jwt.sign(
            { userId: user._id, phone: user.phone },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ success: true, token, user });
    } catch (error) {
        console.error('Verify OTP error:', error);
        res.status(500).json({ error: 'Failed to verify OTP' });
    }
});

// Email/Password Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user || user.password !== password) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ success: true, token, user });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ==================== USER ROUTES ====================

// Get user profile
app.get('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.params.id)
            .populate('followers', 'name profilePicture')
            .populate('following', 'name profilePicture');
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch user' });
    }
});

// Update user profile
app.put('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update user' });
    }
});

// Follow user
app.post('/api/users/:id/follow', authenticateToken, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.params.id, { $addToSet: { followers: req.user.userId } });
        await User.findByIdAndUpdate(req.user.userId, { $addToSet: { following: req.params.id } });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to follow user' });
    }
});

// Get nearby users
app.get('/api/users/nearby', authenticateToken, async (req, res) => {
    try {
        const { lat, lng, category } = req.query;
        const query = category && category !== 'global' ? { category } : {};

        const users = await User.find(query).limit(50);
        res.json({ users });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// ==================== POST ROUTES ====================

// Create post
app.post('/api/posts', authenticateToken, async (req, res) => {
    try {
        const post = await Post.create({ ...req.body, userId: req.user.userId });
        res.json(post);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create post' });
    }
});

// Get feed
app.get('/api/posts/feed', authenticateToken, async (req, res) => {
    try {
        const posts = await Post.find()
            .populate('userId', 'name profilePicture')
            .sort({ createdAt: -1 })
            .limit(20);
        res.json({ posts });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch feed' });
    }
});

// Like post
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
    try {
        const post = await Post.findByIdAndUpdate(
            req.params.id,
            { $addToSet: { likes: req.user.userId } },
            { new: true }
        );
        res.json(post);
    } catch (error) {
        res.status(500).json({ error: 'Failed to like post' });
    }
});

// Add comment
app.post('/api/posts/:id/comment', authenticateToken, async (req, res) => {
    try {
        const post = await Post.findByIdAndUpdate(
            req.params.id,
            { $push: { comments: { userId: req.user.userId, text: req.body.text } } },
            { new: true }
        );
        res.json(post);
    } catch (error) {
        res.status(500).json({ error: 'Failed to add comment' });
    }
});

// ==================== MEDIA ROUTES ====================

// Upload to S3
app.post('/api/media/upload', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        const file = req.file;
        const fileName = `${Date.now()}-${file.originalname}`;

        const params = {
            Bucket: process.env.S3_BUCKET,
            Key: fileName,
            Body: file.buffer,
            ContentType: file.mimetype,
            ACL: 'public-read'
        };

        const result = await s3.upload(params).promise();
        res.json({ url: result.Location });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Failed to upload file' });
    }
});

// ==================== CALL ROUTES ====================

// Generate Twilio Video Access Token
app.post('/api/calls/token', authenticateToken, async (req, res) => {
    try {
        const { roomName } = req.body;
        const identity = req.user.userId;

        // For trial accounts, use Account SID as API Key
        const apiKeySid = process.env.TWILIO_API_KEY_SID || process.env.TWILIO_ACCOUNT_SID;
        const apiKeySecret = process.env.TWILIO_API_KEY_SECRET || process.env.TWILIO_AUTH_TOKEN;

        console.log(`🎥 Generating video token for room: ${roomName}, identity: ${identity}`);

        // Create access token with identity in options
        const token = new AccessToken(
            process.env.TWILIO_ACCOUNT_SID,
            apiKeySid,
            apiKeySecret,
            {
                identity: identity,
                ttl: 3600 // 1 hour expiry
            }
        );

        // Grant access to Video
        const videoGrant = new VideoGrant({
            room: roomName
        });
        token.addGrant(videoGrant);

        const jwt = token.toJwt();
        console.log(`✅ Token generated successfully`);

        res.json({
            token: jwt,
            roomName: roomName,
            identity: identity
        });
    } catch (error) {
        console.error('❌ Token generation error:', error);
        res.status(500).json({ error: 'Failed to generate token', details: error.message });
    }
});

// Initiate Call
app.post('/api/calls/initiate', authenticateToken, async (req, res) => {
    try {
        const { receiverId, type } = req.body;
        const callerId = req.user.userId;

        // Create unique room name
        const roomName = `room-${callerId}-${receiverId}-${Date.now()}`;

        // Create call record
        const call = await Call.create({
            callerId,
            receiverId,
            type: type || 'video',
            roomName,
            status: 'ringing'
        });

        // Emit socket event to receiver
        io.emit(`incoming-call-${receiverId}`, {
            callId: call._id,
            callerId,
            type: call.type,
            roomName
        });

        res.json({
            success: true,
            callId: call._id,
            roomName
        });
    } catch (error) {
        console.error('Initiate call error:', error);
        res.status(500).json({ error: 'Failed to initiate call' });
    }
});

// Accept Call
app.post('/api/calls/:id/accept', authenticateToken, async (req, res) => {
    try {
        const call = await Call.findByIdAndUpdate(
            req.params.id,
            {
                status: 'active',
                startedAt: new Date()
            },
            { new: true }
        );

        if (!call) {
            return res.status(404).json({ error: 'Call not found' });
        }

        // Emit socket event to caller
        io.emit(`call-accepted-${call.callerId}`, {
            callId: call._id,
            roomName: call.roomName
        });

        res.json({
            success: true,
            roomName: call.roomName,
            callId: call._id
        });
    } catch (error) {
        console.error('Accept call error:', error);
        res.status(500).json({ error: 'Failed to accept call' });
    }
});

// Reject Call
app.post('/api/calls/:id/reject', authenticateToken, async (req, res) => {
    try {
        const call = await Call.findByIdAndUpdate(
            req.params.id,
            {
                status: 'rejected',
                endedAt: new Date()
            },
            { new: true }
        );

        if (!call) {
            return res.status(404).json({ error: 'Call not found' });
        }

        // Emit socket event to caller
        io.emit(`call-rejected-${call.callerId}`, {
            callId: call._id
        });

        res.json({ success: true });
    } catch (error) {
        console.error('Reject call error:', error);
        res.status(500).json({ error: 'Failed to reject call' });
    }
});

// End Call
app.post('/api/calls/:id/end', authenticateToken, async (req, res) => {
    try {
        const call = await Call.findById(req.params.id);

        if (!call) {
            return res.status(404).json({ error: 'Call not found' });
        }

        const endedAt = new Date();
        const duration = call.startedAt
            ? Math.floor((endedAt - call.startedAt) / 1000)
            : 0;

        await Call.findByIdAndUpdate(req.params.id, {
            status: 'ended',
            endedAt,
            duration
        });

        // Emit socket event to other participant
        const otherUserId = call.callerId.toString() === req.user.userId
            ? call.receiverId
            : call.callerId;

        io.emit(`call-ended-${otherUserId}`, {
            callId: call._id,
            duration
        });

        res.json({ success: true, duration });
    } catch (error) {
        console.error('End call error:', error);
        res.status(500).json({ error: 'Failed to end call' });
    }
});

// Get Call History
app.get('/api/calls/history', authenticateToken, async (req, res) => {
    try {
        const calls = await Call.find({
            $or: [
                { callerId: req.user.userId },
                { receiverId: req.user.userId }
            ]
        })
            .populate('callerId', 'name profilePicture')
            .populate('receiverId', 'name profilePicture')
            .sort({ createdAt: -1 })
            .limit(50);

        res.json({ calls });
    } catch (error) {
        console.error('Get call history error:', error);
        res.status(500).json({ error: 'Failed to fetch call history' });
    }
});

// ==================== CHAT ROUTES ====================

// Get chats
app.get('/api/chats', authenticateToken, async (req, res) => {
    try {
        const chats = await Chat.find({ participants: req.user.userId })
            .populate('participants', 'name profilePicture')
            .sort({ lastMessageAt: -1 });
        res.json({ chats });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch chats' });
    }
});

// Create chat
app.post('/api/chats', authenticateToken, async (req, res) => {
    try {
        const chat = await Chat.create({
            ...req.body,
            participants: [req.user.userId, ...req.body.participants]
        });
        res.json(chat);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create chat' });
    }
});

// ==================== SOCKET.IO (Real-time Chat) ====================

io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    socket.on('join-chat', (chatId) => {
        socket.join(chatId);
    });

    socket.on('send-message', async (data) => {
        const { chatId, text, senderId } = data;

        const chat = await Chat.findByIdAndUpdate(
            chatId,
            {
                $push: { messages: { senderId, text } },
                lastMessage: text,
                lastMessageAt: new Date()
            },
            { new: true }
        );

        io.to(chatId).emit('new-message', chat.messages[chat.messages.length - 1]);
    });

    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
    });
});

// ==================== HEALTH CHECK ====================

app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date() });
});

// ==================== START SERVER ====================

server.listen(PORT, () => {
    console.log(`🚀 INFLIQ MVP Server running on port ${PORT}`);
    console.log(`📱 Frontend should connect to: http://localhost:${PORT}`);
});
