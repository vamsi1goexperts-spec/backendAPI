const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config({ path: '../../.env' });

const app = express();
const PORT = process.env.FEED_SERVICE_URL?.split(':')[2] || 3004;

// Middleware
app.use(cors({ origin: '*' })); // Allow all origins for testing
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Feed Service: MongoDB connected'))
    .catch(err => console.error('❌ MongoDB connection error:', err));

// Auth Middleware
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Get personalized feed
app.get('/api/feed', authMiddleware, async (req, res) => {
    try {
        const { limit = 20, skip = 0 } = req.query;

        // Get user's following list
        const User = mongoose.model('User');
        const user = await User.findById(req.userId).select('following');

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Get posts from followed users + own posts
        const Post = mongoose.model('Post');
        const posts = await Post.find({
            userId: { $in: [...user.following, req.userId] },
            type: 'post'
        })
            .sort({ createdAt: -1 })
            .limit(parseInt(limit))
            .skip(parseInt(skip))
            .populate('userId', 'name profilePhoto isVerified')
            .lean();

        // Add engagement data
        const enrichedPosts = posts.map(post => ({
            ...post,
            likesCount: post.likes?.length || 0,
            commentsCount: post.comments?.length || 0,
            isLiked: post.likes?.includes(req.userId) || false
        }));

        res.json({ success: true, posts: enrichedPosts, cached: false });
    } catch (error) {
        console.error('Feed error:', error);
        res.status(500).json({ error: 'Failed to get feed' });
    }
});

// Get stories
app.get('/api/feed/stories', authMiddleware, async (req, res) => {
    try {
        // For MVP, we'll return mock stories
        // In production, implement story schema with 24-hour expiry
        const User = mongoose.model('User');
        const user = await User.findById(req.userId).select('following');

        const users = await User.find({
            _id: { $in: user.following }
        })
            .limit(20)
            .select('name profilePhoto isVerified');

        const stories = users.map(u => ({
            userId: u._id,
            name: u.name,
            profilePhoto: u.profilePhoto,
            isVerified: u.isVerified,
            hasStory: true,
            seen: false
        }));

        res.json({ success: true, stories });
    } catch (error) {
        console.error('Stories error:', error);
        res.status(500).json({ error: 'Failed to get stories' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', service: 'feed-service' });
});

app.listen(PORT, () => {
    console.log(`🚀 Feed Service running on port ${PORT}`);
});
