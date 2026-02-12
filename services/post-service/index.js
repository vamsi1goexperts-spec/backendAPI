const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config({ path: '../../.env' });

const app = express();
const PORT = process.env.POST_SERVICE_URL?.split(':')[2] || 3003;

// Middleware
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(',') }));
app.use(express.json());

// Post Schema
const postSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['post', 'reel'], default: 'post' },
    mediaUrl: String,
    caption: String,
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    comments: [{
        userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        text: String,
        createdAt: { type: Date, default: Date.now }
    }],
    shares: { type: Number, default: 0 },
    views: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

const Post = mongoose.model('Post', postSchema);

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Post Service: MongoDB connected'))
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

// Routes

// Create post/reel
app.post('/api/posts', authMiddleware, async (req, res) => {
    try {
        const { type, mediaUrl, caption } = req.body;

        if (!mediaUrl) {
            return res.status(400).json({ error: 'Media URL required' });
        }

        const post = new Post({
            userId: req.userId,
            type: type || 'post',
            mediaUrl,
            caption
        });

        await post.save();

        // Update user's post count
        const mongoose2 = require('mongoose');
        const User = mongoose2.model('User');
        await User.findByIdAndUpdate(req.userId, { $inc: { postsCount: 1 } });

        res.json({ success: true, post });
    } catch (error) {
        console.error('Create post error:', error);
        res.status(500).json({ error: 'Failed to create post' });
    }
});

// Get single post
app.get('/api/posts/:id', async (req, res) => {
    try {
        const post = await Post.findById(req.params.id)
            .populate('userId', 'name profilePhoto isVerified')
            .populate('comments.userId', 'name profilePhoto');

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        res.json({
            success: true,
            post: {
                id: post._id,
                type: post.type,
                mediaUrl: post.mediaUrl,
                caption: post.caption,
                likesCount: post.likes.length,
                commentsCount: post.comments.length,
                shares: post.shares,
                views: post.views,
                user: post.userId,
                comments: post.comments,
                createdAt: post.createdAt
            }
        });
    } catch (error) {
        console.error('Get post error:', error);
        res.status(500).json({ error: 'Failed to get post' });
    }
});

// Get user posts
app.get('/api/posts/user/:userId', async (req, res) => {
    try {
        const { limit = 20, skip = 0 } = req.query;

        const posts = await Post.find({ userId: req.params.userId })
            .sort({ createdAt: -1 })
            .limit(parseInt(limit))
            .skip(parseInt(skip))
            .populate('userId', 'name profilePhoto isVerified');

        res.json({ success: true, posts });
    } catch (error) {
        console.error('Get user posts error:', error);
        res.status(500).json({ error: 'Failed to get posts' });
    }
});

// Get reels
app.get('/api/posts/reels', async (req, res) => {
    try {
        const { limit = 20, skip = 0 } = req.query;

        const reels = await Post.find({ type: 'reel' })
            .sort({ createdAt: -1 })
            .limit(parseInt(limit))
            .skip(parseInt(skip))
            .populate('userId', 'name profilePhoto isVerified');

        res.json({ success: true, reels });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get reels' });
    }
});

// Delete post
app.delete('/api/posts/:id', authMiddleware, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        if (post.userId.toString() !== req.userId) {
            return res.status(403).json({ error: 'Not authorized' });
        }

        await Post.findByIdAndDelete(req.params.id);

        // Update user's post count
        const mongoose2 = require('mongoose');
        const User = mongoose2.model('User');
        await User.findByIdAndUpdate(req.userId, { $inc: { postsCount: -1 } });

        res.json({ success: true, message: 'Post deleted' });
    } catch (error) {
        console.error('Delete post error:', error);
        res.status(500).json({ error: 'Failed to delete post' });
    }
});

// Like post
app.post('/api/posts/:id/like', authMiddleware, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        const alreadyLiked = post.likes.includes(req.userId);

        if (alreadyLiked) {
            // Unlike
            post.likes = post.likes.filter(id => id.toString() !== req.userId);
        } else {
            // Like
            post.likes.push(req.userId);
        }

        await post.save();

        res.json({
            success: true,
            liked: !alreadyLiked,
            likesCount: post.likes.length
        });
    } catch (error) {
        console.error('Like post error:', error);
        res.status(500).json({ error: 'Failed to like post' });
    }
});

// Comment on post
app.post('/api/posts/:id/comment', authMiddleware, async (req, res) => {
    try {
        const { text } = req.body;

        if (!text) {
            return res.status(400).json({ error: 'Comment text required' });
        }

        const post = await Post.findById(req.params.id);

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        post.comments.push({
            userId: req.userId,
            text
        });

        await post.save();

        const updatedPost = await Post.findById(req.params.id)
            .populate('comments.userId', 'name profilePhoto');

        res.json({
            success: true,
            comment: updatedPost.comments[updatedPost.comments.length - 1]
        });
    } catch (error) {
        console.error('Comment error:', error);
        res.status(500).json({ error: 'Failed to add comment' });
    }
});

// Increment view count
app.post('/api/posts/:id/view', async (req, res) => {
    try {
        await Post.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to increment view' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', service: 'post-service' });
});

app.listen(PORT, () => {
    console.log(`🚀 Post Service running on port ${PORT}`);
});
