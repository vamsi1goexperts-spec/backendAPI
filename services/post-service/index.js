const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { requiredInProduction } = require('../_shared/config');
const { applyCommonSecurity } = require('../_shared/security');
const { applyRequestContext } = require('../_shared/observability');
const { registerSharedModels } = require('../_shared/models');
const { sendError, ErrorCodes } = require('../_shared/http');
const { logEvent } = require('../_shared/logger');

const app = express();
const PORT = process.env.POST_SERVICE_URL?.split(':')[2] || 3003;
const { Post } = registerSharedModels();

requiredInProduction(['MONGO_URI', 'JWT_SECRET']);

// Middleware
applyRequestContext(app);
applyCommonSecurity(app);
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => logEvent('post-service', 'info', 'mongodb.connected'))
    .catch(err => logEvent('post-service', 'error', 'mongodb.connection_failed', { error: err.message }));

// Auth Middleware
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return sendError(res, 401, ErrorCodes.UNAUTHORIZED, 'No token provided');
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        return sendError(res, 401, ErrorCodes.INVALID_TOKEN, 'Invalid token');
    }
};

// Routes

// Create post/reel
app.post('/api/posts', authMiddleware, async (req, res) => {
    try {
        const { type, mediaUrl, thumbnailUrl, caption, content } = req.body;

        if (!mediaUrl && !content?.trim()) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'Post content or media is required');
        }

        const post = new Post({
            userId: req.userId,
            type: type || 'post',
            mediaUrl,
            thumbnailUrl,
            caption: content || caption || ''
        });

        await post.save();

        res.json({ success: true, post });
    } catch (error) {
        logEvent('post-service', 'error', 'posts.create_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to create post');
    }
});

// Get single post
app.get('/api/posts/:id', async (req, res) => {
    try {
        const post = await Post.findById(req.params.id)
            .populate('userId', 'name profilePhoto isVerified')
            .populate('comments.userId', 'name profilePhoto');

        if (!post) {
            return sendError(res, 404, ErrorCodes.NOT_FOUND, 'Post not found');
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
        logEvent('post-service', 'error', 'posts.get_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to get post');
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
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to get posts');
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
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to get reels');
    }
});

// App-compatible reels feed endpoint
app.get('/api/reels/feed', authMiddleware, async (req, res) => {
    try {
        const page = parseInt(req.query.page || '1', 10);
        const limit = parseInt(req.query.limit || '10', 10);
        const skip = (page - 1) * limit;

        const reels = await Post.find({ type: 'reel' })
            .sort({ createdAt: -1 })
            .limit(limit)
            .skip(skip)
            .populate('userId', 'name profilePhoto isVerified');

        const processed = reels.map((reel) => {
            const reelObj = reel.toObject();
            if (reelObj.userId) {
                reelObj.userId.profilePicture = reelObj.userId.profilePhoto || null;
            }
            reelObj.content = reelObj.caption || '';
            reelObj.isLiked = (reelObj.likes || []).some((id) => id.toString() === req.userId);
            return reelObj;
        });

        res.json({
            reels: processed,
            page,
            hasMore: reels.length === limit
        });
    } catch (error) {
        logEvent('post-service', 'error', 'reels.feed_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to get reels feed');
    }
});

// App-compatible posts feed endpoint
app.get('/api/posts/feed', authMiddleware, async (req, res) => {
    try {
        const page = parseInt(req.query.page || '1', 10);
        const limit = parseInt(req.query.limit || '10', 10);
        const skip = (page - 1) * limit;

        const posts = await Post.find({ type: 'post' })
            .sort({ createdAt: -1 })
            .limit(limit)
            .skip(skip)
            .populate('userId', 'name profilePhoto isVerified');

        const processed = posts.map((post) => {
            const postObj = post.toObject();
            postObj.likesCount = postObj.likes?.length || 0;
            postObj.commentsCount = postObj.comments?.length || 0;
            if (postObj.userId) {
                postObj.userId.profilePicture = postObj.userId.profilePhoto || null;
            }
            postObj.content = postObj.caption || '';
            postObj.isLiked = (postObj.likes || []).some((id) => id.toString() === req.userId);
            return postObj;
        });

        res.json({
            posts: processed,
            page,
            hasMore: posts.length === limit
        });
    } catch (error) {
        logEvent('post-service', 'error', 'posts.feed_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to get feed');
    }
});

// Delete post
app.delete('/api/posts/:id', authMiddleware, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);

        if (!post) {
            return sendError(res, 404, ErrorCodes.NOT_FOUND, 'Post not found');
        }

        if (post.userId.toString() !== req.userId) {
            return sendError(res, 403, ErrorCodes.FORBIDDEN, 'Not authorized');
        }

        await Post.findByIdAndDelete(req.params.id);

        res.json({ success: true, message: 'Post deleted' });
    } catch (error) {
        logEvent('post-service', 'error', 'posts.delete_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to delete post');
    }
});

// Like post
app.post('/api/posts/:id/like', authMiddleware, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);

        if (!post) {
            return sendError(res, 404, ErrorCodes.NOT_FOUND, 'Post not found');
        }

        const alreadyLiked = post.likes.some((id) => id.toString() === req.userId);

        if (alreadyLiked) {
            // Unlike
            post.likes = post.likes.filter(id => id.toString() !== req.userId);
        } else {
            // Like
            post.likes.push(req.userId);
        }

        await post.save();

        const refreshed = await Post.findById(req.params.id).populate('userId', 'name profilePhoto isVerified');
        const postObj = refreshed.toObject();
        if (postObj.userId) {
            postObj.userId.profilePicture = postObj.userId.profilePhoto || null;
        }
        postObj.content = postObj.caption || '';
        postObj.likesCount = postObj.likes?.length || 0;
        postObj.commentsCount = postObj.comments?.length || 0;

        res.json(postObj);
    } catch (error) {
        logEvent('post-service', 'error', 'posts.like_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to like post');
    }
});

// Comment on post
app.post('/api/posts/:id/comment', authMiddleware, async (req, res) => {
    try {
        const { text } = req.body;

        if (!text) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'Comment text required');
        }

        const post = await Post.findById(req.params.id);

        if (!post) {
            return sendError(res, 404, ErrorCodes.NOT_FOUND, 'Post not found');
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
        logEvent('post-service', 'error', 'posts.comment_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to add comment');
    }
});

// Increment view count
app.post('/api/posts/:id/view', async (req, res) => {
    try {
        await Post.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } });
        res.json({ success: true });
    } catch (error) {
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to increment view');
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', service: 'post-service' });
});

app.listen(PORT, () => {
    logEvent('post-service', 'info', 'service.started', { port: PORT });
});
