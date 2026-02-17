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
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 3000;
const AWS_REGION_PATTERN = /^(?:us|eu|ap|sa|ca|me|af|cn|us-gov|il)-[a-z0-9-]+-\d$/;

const getValidatedAwsRegion = () => {
    const region = process.env.AWS_REGION?.trim();
    if (!region || !AWS_REGION_PATTERN.test(region)) {
        throw new Error(`Invalid AWS_REGION value: ${region || '(empty)'}`);
    }
    return region;
};

const awsRegion = getValidatedAwsRegion();

// Middleware
app.use(cors({ origin: '*' }));
app.use(express.json());

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Serve static files from uploads directory
app.use('/uploads', express.static(uploadsDir));

// Request Logger
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    next();
});

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
    region: awsRegion
});

// Multer for file uploads (disk-backed to avoid unbounded memory spikes on larger videos)
const MAX_UPLOAD_FILE_SIZE = 50 * 1024 * 1024; // 50MB
const ALLOWED_UPLOAD_MIME_TYPES = [
    'image/jpeg',
    'image/png',
    'image/jpg',
    'image/webp',
    'video/mp4',
    'video/quicktime',
    'video/x-msvideo',
    'video/webm'
];

const upload = multer({
    storage: multer.diskStorage({
        destination: uploadsDir,
        filename: (req, file, cb) => {
            const ext = path.extname(file.originalname || '') || '';
            cb(null, `${Date.now()}-${Math.random().toString(36).slice(2, 10)}${ext}`);
        }
    }),
    limits: { fileSize: MAX_UPLOAD_FILE_SIZE },
    fileFilter: (req, file, cb) => {
        if (!ALLOWED_UPLOAD_MIME_TYPES.includes(file.mimetype)) {
            return cb(new Error(`Unsupported file type: ${file.mimetype}`));
        }
        cb(null, true);
    }
});

// S3 Signing Utility
// S3 Signing Utility
const signS3Url = (url) => {
    if (!url) return url;

    try {
        let key = url;

        // If it's a full URL
        if (url.startsWith('http')) {
            // Case 1: Local fallback or non-S3 URL
            if (!url.includes('amazonaws.com')) return url;

            // Case 2: Full S3 URL (extract key)
            const baseUrl = url.split('?')[0];
            key = baseUrl.split('.com/')[1];
        }

        // Now we have the key (either extracted or it was already a key)
        if (!key) return url;

        return s3.getSignedUrl('getObject', {
            Bucket: process.env.S3_BUCKET,
            Key: key,
            Expires: 60 * 60 * 24 * 7 // 7 days
        });
    } catch (err) {
        console.error('Error signing S3 URL:', err);
        return url;
    }
};

const emitRealtimeNotification = (targetUserId, payload = {}) => {
    if (!targetUserId) return;
    const safeTargetUserId = targetUserId.toString();
    const notificationPayload = {
        id: payload.id || `notif-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
        type: payload.type || 'general',
        title: payload.title || 'Notification',
        message: payload.message || '',
        createdAt: payload.createdAt || new Date().toISOString(),
        meta: payload.meta || {}
    };
    io.emit(`notification-${safeTargetUserId}`, notificationPayload);
};

// S3 Sanitizer - Extracts the key from a full S3 URL or signed URL for storage
const sanitizeS3Url = (url) => {
    if (!url) return url;
    // If it's not an S3 URL, return as is (e.g. local fallback)
    if (!url.includes('amazonaws.com')) return url;

    try {
        const baseUrl = url.split('?')[0];
        // Extracts whatever is after .com/
        const key = baseUrl.split('.com/')[1];
        return key || url;
    } catch (err) {
        console.error('Error sanitizing S3 URL:', err);
        return url;
    }
};

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
        type: { type: String, enum: ['Point'], default: 'Point' },
        coordinates: { type: [Number], default: [0, 0] }
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
        type: { type: String, enum: ['text', 'call-started', 'call-ended', 'call-missed'], default: 'text' },
        callId: { type: mongoose.Schema.Types.ObjectId, ref: 'Call' },
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

// Helper to add call events to chat history
const addCallMessageToChat = async (callerId, receiverId, messageType, callId, callType) => {
    try {
        console.log(`📝 Adding call message: ${messageType} for call ${callId}`);
        let chat = await Chat.findOne({
            participants: { $all: [callerId, receiverId] },
            type: 'chat'
        });

        if (!chat) {
            console.log(`🆕 Creating new chat for call history between ${callerId} and ${receiverId}`);
            chat = await Chat.create({
                participants: [callerId, receiverId],
                type: 'chat',
                messages: [],
                lastMessageAt: new Date()
            });
        }

        const callText = {
            'call-started': `${callType === 'video' ? 'Video' : 'Audio'} call started`,
            'call-ended': `${callType === 'video' ? 'Video' : 'Audio'} call ended`,
            'call-missed': `Missed ${callType === 'video' ? 'video' : 'audio'} call`
        }[messageType];

        const newMessage = {
            senderId: callerId,
            text: callText,
            type: messageType,
            callId: callId,
            createdAt: new Date()
        };

        chat.messages.push(newMessage);
        chat.lastMessage = callText;
        chat.lastMessageAt = new Date();
        await chat.save();
        console.log(`✅ Call message saved to chat ${chat._id}`);

        // Emit to both participants
        io.to(chat._id.toString()).emit('new-message', {
            chatId: chat._id,
            message: newMessage
        });
        console.log(`📡 Broadcasted new-message to room ${chat._id}`);

        return chat;
    } catch (error) {
        console.error('❌ Error adding call message to chat:', error);
    }
};

// ==================== AUTH MIDDLEWARE ====================

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        console.log(`❌ Auth failed: No token provided for ${req.method} ${req.url}`);
        return res.status(401).json({ error: 'Access denied' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.log(`❌ Auth failed: Invalid token for ${req.method} ${req.url} - ${err.message}`);
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// ==================== AUTH ROUTES ====================

// Send OTP
app.post('/api/auth/send-otp', async (req, res) => {
    try {
        let { phone } = req.body;
        if (phone) phone = phone.trim().replace(/\s/g, '');

        // Auto-format phone number: if 10 digits, add +91
        if (phone && phone.length === 10 && !phone.startsWith('+')) {
            phone = `+91${phone}`;
            console.log(`📱 Auto-formatted phone: ${phone}`);
        }

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
                console.log(`⚠️ Twilio error for ${phone}: ${twilioError.message}`);
                console.error('Twilio error:', twilioError.message);
            }
        }

        res.json({ success: true, message: 'OTP sent successfully' });
    } catch (error) {
        console.error('Send OTP error:', error);
        res.status(500).json({ error: 'Failed to send OTP' });
    }
});

// Verify OTP
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        let { phone, otp } = req.body;
        if (phone) phone = phone.trim().replace(/\s/g, '');
        if (otp) otp = otp.trim();

        // Auto-format phone number: if 10 digits, add +91
        if (phone && phone.length === 10 && !phone.startsWith('+')) {
            phone = `+91${phone}`;
            console.log(`📱 Auto-formatted phone: ${phone}`);
        }

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

        const userObj = user.toObject();
        userObj.profilePicture = signS3Url(userObj.profilePicture);

        res.json({ success: true, token, user: userObj });
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

        const userObj = user.toObject();
        userObj.profilePicture = signS3Url(userObj.profilePicture);

        res.json({ success: true, token, user: userObj });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Registration
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phone, age } = req.body;

        // Validation
        if (!name || !email || !password || !phone) {
            return res.status(400).json({ error: 'Name, email, password, and phone are required' });
        }

        // Check if user already exists
        const existingUser = await User.findOne({
            $or: [{ email }, { phone }]
        });

        if (existingUser) {
            return res.status(400).json({ error: 'User with this email or phone already exists' });
        }

        // Create user
        const user = await User.create({
            name,
            email,
            password,
            phone,
            age: age || null,
            profilePicture: req.body.profilePicture ? sanitizeS3Url(req.body.profilePicture) : null
        });

        console.log(`✅ Registered new user: ${user._id}`);

        // Generate token
        const token = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        const userObj = user.toObject();
        userObj.profilePicture = signS3Url(userObj.profilePicture);

        res.json({ success: true, token, user: userObj });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed', details: error.message });
    }
});

// ==================== USER ROUTES ====================

// Get nearby users (flexible for both /nearby and /by-category)
const getNearbyUsersHandler = async (req, res) => {
    try {
        const { lat, lng, category } = req.query;
        const requestedCategory = req.params.category || category;

        const query = requestedCategory && requestedCategory !== 'global' ? { category: requestedCategory } : {};

        console.log(`🔍 Nearby: ${requestedCategory || 'all'}. Query:`, query);

        // Fetch users with a specific catch for DB errors (like index issues)
        let users = [];
        try {
            users = await User.find(query).limit(50).exec();
        } catch (dbError) {
            console.error('❌ Database Find Error:', dbError);
            throw new Error(`Database error: ${dbError.message}`);
        }

        console.log(`📊 Found ${users.length} users.`);

        const defaultLat = parseFloat(lat) || 28.6139;
        const defaultLng = parseFloat(lng) || 77.2090;

        const processedUsers = users.map(user => {
            try {
                const userObj = user.toObject();
                const hasCoords = userObj.location &&
                    userObj.location.coordinates &&
                    Array.isArray(userObj.location.coordinates) &&
                    userObj.location.coordinates.length >= 2;

                if (!hasCoords) {
                    userObj.location = {
                        type: 'Point',
                        coordinates: [
                            defaultLng + (Math.random() - 0.5) * 0.05,
                            defaultLat + (Math.random() - 0.5) * 0.05
                        ]
                    };
                }

                // Sign profile picture
                userObj.profilePicture = signS3Url(userObj.profilePicture);

                return userObj;
            } catch (err) {
                return null;
            }
        }).filter(u => u !== null);

        res.json({ users: processedUsers });
    } catch (error) {
        console.error('❌ Nearby Handler Exception:', error);
        try {
            require('fs').appendFileSync('debug_error.log', `[${new Date().toISOString()}] Nearby Error: ${error.message}\n${error.stack}\n\n`);
        } catch (e) { }
        res.status(500).json({
            error: 'Failed to fetch users',
            details: error.message,
            stack: error.stack
        });
    }
};

app.get('/api/users/nearby', authenticateToken, getNearbyUsersHandler);
app.get('/api/users/by-category/:category', authenticateToken, getNearbyUsersHandler);

// Search users
app.get('/api/users/search', authenticateToken, async (req, res) => {
    try {
        const { q } = req.query;
        if (!q) return res.json({ users: [] });

        const users = await User.find({
            $or: [
                { name: { $regex: q, $options: 'i' } },
                { phone: { $regex: q, $options: 'i' } }
            ]
        }).limit(20);

        const processedUsers = users.map(user => {
            const userObj = user.toObject();
            userObj.profilePicture = signS3Url(userObj.profilePicture);
            return userObj;
        });

        res.json({ users: processedUsers });
    } catch (error) {
        res.status(500).json({ error: 'Search failed' });
    }
});

// Get user profile
app.get('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.params.id)
            .populate('followers', 'name profilePicture')
            .populate('following', 'name profilePicture');

        if (!user) return res.status(404).json({ error: 'User not found' });

        const userObj = user.toObject();
        userObj.profilePicture = signS3Url(userObj.profilePicture);

        res.json(userObj);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch user' });
    }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        if (req.body.profilePicture) {
            req.body.profilePicture = sanitizeS3Url(req.body.profilePicture);
        }

        const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!user) return res.status(404).json({ error: 'User not found' });

        const userObj = user.toObject();
        userObj.profilePicture = signS3Url(userObj.profilePicture);

        res.json(userObj);
    } catch (error) {
        console.error('❌ Profile Update Error:', error);
        res.status(500).json({
            error: 'Failed to update user',
            details: error.message,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

// Follow user
app.post('/api/users/:id/follow', authenticateToken, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.params.id, { $addToSet: { followers: req.user.userId } });
        await User.findByIdAndUpdate(req.user.userId, { $addToSet: { following: req.params.id } });

        if (req.params.id.toString() !== req.user.userId.toString()) {
            const actor = await User.findById(req.user.userId).select('name profilePicture');
            emitRealtimeNotification(req.params.id, {
                id: `follow-${req.user.userId}-${req.params.id}`,
                type: 'follow',
                title: 'New follower',
                message: `${actor?.name || 'Someone'} started following you`,
                meta: {
                    actorId: req.user.userId,
                    actorName: actor?.name || 'User',
                    actorProfilePicture: signS3Url(actor?.profilePicture),
                    targetUserId: req.params.id
                }
            });
        }
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to follow user' });
    }
});

// End of user routes



// ==================== POST ROUTES ====================

// Create post
app.post('/api/posts', authenticateToken, async (req, res) => {
    try {
        if (req.body.mediaUrl) {
            req.body.mediaUrl = sanitizeS3Url(req.body.mediaUrl);
        }
        const post = await Post.create({ ...req.body, userId: req.user.userId });

        const postObj = post.toObject();
        postObj.mediaUrl = signS3Url(postObj.mediaUrl);

        res.json(postObj);
    } catch (error) {
        console.error('❌ Create Post Error:', error);
        res.status(500).json({
            error: 'Failed to create post',
            details: error.message,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

// Get feed
app.get('/api/posts/feed', authenticateToken, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const posts = await Post.find({ type: 'post' })
            .populate('userId', 'name profilePicture')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);

        const processedPosts = posts.map(post => {
            const postObj = post.toObject();
            postObj.mediaUrl = signS3Url(postObj.mediaUrl);
            if (postObj.userId) {
                postObj.userId.profilePicture = signS3Url(postObj.userId.profilePicture);
            }
            postObj.likesCount = postObj.likes?.length || 0;
            postObj.commentsCount = postObj.comments?.length || 0;
            postObj.isLiked = (postObj.likes || []).some(
                (id) => id.toString() === req.user.userId
            );
            return postObj;
        });

        res.json({
            posts: processedPosts,
            page,
            hasMore: posts.length === limit
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch feed' });
    }
});

// Get reels feed
app.get('/api/reels/feed', authenticateToken, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const reels = await Post.find({ type: 'reel' })
            .populate('userId', 'name profilePicture')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);

        const processedReels = reels.map(reel => {
            const reelObj = reel.toObject();
            reelObj.mediaUrl = signS3Url(reelObj.mediaUrl);
            if (reelObj.userId) {
                reelObj.userId.profilePicture = signS3Url(reelObj.userId.profilePicture);
            }
            return reelObj;
        });

        res.json({
            reels: processedReels,
            page,
            hasMore: reels.length === limit
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch reels' });
    }
});

// Get user posts
app.get('/api/posts/user/:id', authenticateToken, async (req, res) => {
    try {
        const posts = await Post.find({ userId: req.params.id })
            .populate('userId', 'name profilePicture')
            .sort({ createdAt: -1 });

        const processedPosts = posts.map(post => {
            const postObj = post.toObject();
            postObj.mediaUrl = signS3Url(postObj.mediaUrl);
            if (postObj.userId) {
                postObj.userId.profilePicture = signS3Url(postObj.userId.profilePicture);
            }
            return postObj;
        });

        res.json({ posts: processedPosts });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch user posts' });
    }
});

// Like post
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).json({ error: 'Post not found' });

        const userId = req.user.userId;
        const existingIndex = post.likes.findIndex((id) => id.toString() === userId);
        const didLike = existingIndex < 0;
        if (existingIndex >= 0) {
            post.likes.splice(existingIndex, 1); // unlike
        } else {
            post.likes.push(userId); // like
        }
        await post.save();

        if (didLike && post.userId?.toString() !== userId.toString()) {
            const actor = await User.findById(userId).select('name profilePicture');
            emitRealtimeNotification(post.userId, {
                id: `like-${post._id}-${userId}`,
                type: 'like',
                title: 'New like',
                message: `${actor?.name || 'Someone'} liked your post`,
                meta: {
                    actorId: userId,
                    actorName: actor?.name || 'User',
                    actorProfilePicture: signS3Url(actor?.profilePicture),
                    postId: post._id
                }
            });
        }

        const postObj = post.toObject();
        postObj.mediaUrl = signS3Url(postObj.mediaUrl);

        res.json(postObj);
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
        if (!post) return res.status(404).json({ error: 'Post not found' });

        if (post.userId?.toString() !== req.user.userId.toString()) {
            const actor = await User.findById(req.user.userId).select('name profilePicture');
            const commentText = typeof req.body?.text === 'string' ? req.body.text.trim() : '';
            emitRealtimeNotification(post.userId, {
                id: `comment-${post._id}-${Date.now()}`,
                type: 'comment',
                title: 'New comment',
                message: `${actor?.name || 'Someone'} commented on your post${commentText ? ': ' + commentText.slice(0, 60) : ''}`,
                meta: {
                    actorId: req.user.userId,
                    actorName: actor?.name || 'User',
                    actorProfilePicture: signS3Url(actor?.profilePicture),
                    postId: post._id
                }
            });
        }

        const postObj = post.toObject();
        postObj.mediaUrl = signS3Url(postObj.mediaUrl);

        res.json(postObj);
    } catch (error) {
        res.status(500).json({ error: 'Failed to add comment' });
    }
});

// Delete post
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
    try {
        const post = await Post.findOne({ _id: req.params.id });

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        // Check ownership
        if (post.userId.toString() !== req.user.userId) {
            return res.status(403).json({ error: 'Not authorized to delete this post' });
        }

        await Post.deleteOne({ _id: req.params.id });
        res.json({ success: true, message: 'Post deleted successfully' });
    } catch (error) {
        console.error('Delete post error:', error);
        res.status(500).json({ error: 'Failed to delete post' });
    }
});

// ==================== MEDIA ROUTES ====================

// Upload to S3
app.post('/api/media/upload', authenticateToken, (req, res, next) => {
    console.log(`🖼️  [/api/media/upload] Request headers:`, req.headers['content-type']);
    next();
}, upload.single('file'), async (req, res) => {
    let tempFilePath = null;
    try {
        const file = req.file;
        if (!file) {
            console.log('❌ No file received in /api/media/upload');
            return res.status(400).json({ error: 'No file uploaded' });
        }
        tempFilePath = file.path;

        console.log(`🚀 Uploading file: ${file.originalname} (${file.mimetype}, ${file.size} bytes)`);
        const safeOriginalName = (file.originalname || 'upload').replace(/[^\w.\-]/g, '_');
        const fileName = `${Date.now()}-${safeOriginalName}`;

        const params = {
            Bucket: process.env.S3_BUCKET,
            Key: fileName,
            Body: fs.createReadStream(file.path),
            ContentType: file.mimetype
            // ACL: 'public-read' // Removed as it often fails on buckets with "Block Public Access" enabled
        };

        try {
            const result = await s3.upload(params).promise();
            console.log(`✅ File uploaded successfully to S3: ${result.Location}`);

            // Generate signed URL for secure access (7 days expiration)
            const signedUrl = s3.getSignedUrl('getObject', {
                Bucket: process.env.S3_BUCKET,
                Key: fileName,
                Expires: 60 * 60 * 24 * 7 // 7 days
            });

            console.log(`🔐 Generated signed URL for: ${fileName}`);
            fs.unlink(file.path, () => { });
            res.json({ url: signedUrl });
        } catch (s3Error) {
            console.error('⚠️ S3 Upload failed, falling back to local storage:', s3Error.message);

            // Local storage fallback: keep file in uploads directory with stable name.
            const localPath = path.join(uploadsDir, fileName);
            try {
                fs.renameSync(file.path, localPath);
            } catch (renameError) {
                fs.copyFileSync(file.path, localPath);
                fs.unlink(file.path, () => { });
            }

            // Construct local URL - using req.get('host') to be dynamic
            const localUrl = `${req.protocol}://${req.get('host')}/uploads/${fileName}`;
            console.log(`✅ File saved locally: ${localUrl}`);

            res.json({
                url: localUrl,
                storage: 'local',
                warning: 'S3 upload failed, using local storage fallback'
            });
        }
    } catch (error) {
        console.error('❌ Upload route error:', error);
        res.status(500).json({ error: 'Failed to upload file', details: error.message });
    } finally {
        if (tempFilePath && fs.existsSync(tempFilePath)) {
            fs.unlink(tempFilePath, () => { });
        }
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

        // Log call started in chat
        await addCallMessageToChat(callerId, receiverId, 'call-started', call._id, call.type);

        const caller = await User.findById(callerId).select('name profilePicture');

        // Emit socket event to receiver
        io.emit(`incoming-call-${receiverId}`, {
            callId: call._id,
            callerId,
            caller: caller ? {
                _id: caller._id,
                name: caller.name,
                profilePicture: signS3Url(caller.profilePicture)
            } : null,
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

        const receiver = await User.findById(call.receiverId).select('name profilePicture');

        // Emit socket event to caller
        io.emit(`call-accepted-${call.callerId}`, {
            callId: call._id,
            roomName: call.roomName,
            type: call.type,
            receiver: receiver ? {
                _id: receiver._id,
                name: receiver.name,
                profilePicture: signS3Url(receiver.profilePicture)
            } : null
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

        // Log missed call in chat
        await addCallMessageToChat(call.callerId, call.receiverId, 'call-missed', call._id, call.type);

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

        // Log call ended in chat
        await addCallMessageToChat(call.callerId, call.receiverId, 'call-ended', call._id, call.type);

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

        const processedChats = chats.map(chat => {
            const chatObj = chat.toObject();
            if (chatObj.participants) {
                chatObj.participants = chatObj.participants.map(p => ({
                    ...p,
                    profilePicture: signS3Url(p.profilePicture)
                }));
            }
            return chatObj;
        });

        res.json({ chats: processedChats });
    } catch (error) {
        console.error('❌ Failed to fetch chats:', error);
        res.status(500).json({ error: 'Failed to fetch chats', details: error.message });
    }
});

// Get specific chat messages
app.get('/api/chats/:chatId', authenticateToken, async (req, res) => {
    try {
        const { chatId } = req.params;
        const currentUserId = req.user.userId || req.user._id;

        console.log(`🔍 Fetching chat: ${chatId} for user: ${currentUserId}`);

        if (!mongoose.Types.ObjectId.isValid(chatId)) {
            console.log(`⚠️ Invalid Chat ID format: ${chatId}`);
            return res.status(400).json({ error: 'Invalid Chat ID format' });
        }

        const chat = await Chat.findOne({
            _id: chatId,
            participants: currentUserId
        }).populate('participants', 'name profilePicture');

        if (!chat) {
            console.log(`❌ Chat not found or user not participant. ID: ${chatId}, User: ${currentUserId}`);
            return res.status(404).json({ error: 'Chat not found' });
        }

        const chatObj = chat.toObject();
        if (chatObj.participants) {
            chatObj.participants = chatObj.participants.map(p => ({
                ...p,
                profilePicture: signS3Url(p.profilePicture)
            }));
        }

        res.json({ chat: chatObj });
    } catch (error) {
        console.error('❌ Failed to fetch chat messages:', error);
        res.status(500).json({ error: 'Failed to fetch chat messages', details: error.message });
    }
});

// Create chat
app.post('/api/chats', authenticateToken, async (req, res) => {
    try {
        const { type, participants } = req.body;
        const currentUserId = req.user.userId;

        // Normalize participants: ensure current user is included and unique
        let allParticipants = [currentUserId];
        if (participants && Array.isArray(participants)) {
            allParticipants = [...new Set([...allParticipants, ...participants])];
        }

        // For private chats (type 'chat'), check if one already exists
        if (type === 'chat' && allParticipants.length === 2) {
            const existingChat = await Chat.findOne({
                type: 'chat',
                participants: { $all: allParticipants, $size: 2 }
            }).populate('participants', 'name profilePicture');

            if (existingChat) {
                console.log(`♻️ Returning existing chat: ${existingChat._id}`);
                const chatObj = existingChat.toObject();
                if (chatObj.participants) {
                    chatObj.participants = chatObj.participants.map(p => ({
                        ...p,
                        profilePicture: signS3Url(p.profilePicture)
                    }));
                }
                return res.json(chatObj);
            }
        }

        // Create new chat
        const chat = await Chat.create({
            ...req.body,
            participants: allParticipants
        });

        console.log(`🆕 Created new chat: ${chat._id}`);
        res.json(chat);
    } catch (error) {
        console.error('❌ Failed to create chat:', error);
        res.status(500).json({ error: 'Failed to create chat', details: error.message });
    }
});

// ==================== SOCKET.IO (Real-time Chat) ====================

io.use((socket, next) => {
    try {
        const token = socket.handshake.auth?.token;
        if (!token) {
            return next(new Error('Unauthorized: Missing token'));
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.userId || decoded._id;
        if (!userId) {
            return next(new Error('Unauthorized: Invalid token payload'));
        }

        socket.userId = userId.toString();
        next();
    } catch (error) {
        next(new Error('Unauthorized: Invalid token'));
    }
});

io.on('connection', (socket) => {
    console.log(`✅ Socket connected: ${socket.id} (user: ${socket.userId})`);

    socket.on('join-chat', async (payload, callback) => {
        const chatId = typeof payload === 'string' ? payload : payload?.chatId;

        try {
            if (!chatId || !mongoose.Types.ObjectId.isValid(chatId)) {
                const response = { ok: false, error: 'Invalid chat ID' };
                if (typeof callback === 'function') callback(response);
                return;
            }

            const chat = await Chat.findOne({
                _id: chatId,
                participants: socket.userId
            }).select('_id');

            if (!chat) {
                const response = { ok: false, error: 'Chat not found or access denied' };
                if (typeof callback === 'function') callback(response);
                return;
            }

            socket.join(chatId);
            console.log(`📥 Socket ${socket.id} joined chat room: ${chatId}`);
            if (typeof callback === 'function') callback({ ok: true, chatId });
        } catch (error) {
            console.error('❌ Error in join-chat handler:', error);
            if (typeof callback === 'function') callback({ ok: false, error: 'Failed to join chat' });
        }
    });

    socket.on('send-message', async (data, callback) => {
        const { chatId, text, clientMessageId } = data || {};
        const safeText = typeof text === 'string' ? text.trim() : '';
        console.log(`📨 Received send-message from ${socket.id}:`, { chatId, text: safeText.substring(0, 50), senderId: socket.userId });

        try {
            if (!chatId || !mongoose.Types.ObjectId.isValid(chatId) || !safeText) {
                const response = { ok: false, error: 'Invalid payload' };
                if (typeof callback === 'function') callback(response);
                return;
            }

            const chat = await Chat.findOneAndUpdate(
                {
                    _id: chatId,
                    participants: socket.userId
                },
                {
                    $push: { messages: { senderId: socket.userId, text: safeText } },
                    lastMessage: safeText,
                    lastMessageAt: new Date()
                },
                { new: true }
            );

            if (!chat) {
                const response = { ok: false, error: 'Chat not found or access denied' };
                if (typeof callback === 'function') callback(response);
                return;
            }

            const newMessage = chat.messages[chat.messages.length - 1];
            const payload = {
                chatId,
                message: newMessage,
                clientMessageId: clientMessageId || null
            };

            io.to(chatId).emit('new-message', payload);
            console.log(`✅ Message broadcasted to room ${chatId}`);
            if (typeof callback === 'function') callback({ ok: true, payload });
        } catch (error) {
            console.error('❌ Error in send-message handler:', error);
            if (typeof callback === 'function') callback({ ok: false, error: 'Failed to send message' });
        }
    });

    // Typing indicator
    socket.on('user-typing', async (data) => {
        const { chatId, isTyping } = data || {};
        if (!chatId || !mongoose.Types.ObjectId.isValid(chatId)) return;

        try {
            const chat = await Chat.findOne({
                _id: chatId,
                participants: socket.userId
            }).select('_id');
            if (!chat) return;

            socket.to(chatId).emit('user-typing', {
                chatId,
                userId: socket.userId,
                isTyping: Boolean(isTyping)
            });
        } catch (error) {
            console.error('❌ Error in user-typing handler:', error);
        }
    });

    socket.on('disconnect', () => {
        console.log('❌ Socket disconnected:', socket.id);
    });
});

// ==================== HEALTH CHECK ====================

app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date() });
});

// Global Error Handler
app.use((err, req, res, next) => {
    console.error('🛑 Unhandled Server Error:', err);
    res.status(500).json({
        error: 'Internal server error',
        details: err.message,
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
});

// ==================== START SERVER ====================

server.listen(PORT, () => {
    console.log(`🚀 INFLIQ MVP Server running on port ${PORT}`);
    console.log(`📱 Frontend should connect to: http://localhost:${PORT}`);
});
