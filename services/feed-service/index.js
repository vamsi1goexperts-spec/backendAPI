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
const PORT = process.env.FEED_SERVICE_URL?.split(':')[2] || 3004;
const { User, Post, Story } = registerSharedModels();
const MAX_STORIES_PER_USER = parseInt(process.env.MAX_STORIES_PER_USER || '50', 10);
const STORY_CREATE_WINDOW_MS = parseInt(process.env.STORY_CREATE_WINDOW_MS || `${10 * 60 * 1000}`, 10);
const STORY_CREATE_MAX_IN_WINDOW = parseInt(process.env.STORY_CREATE_MAX_IN_WINDOW || '5', 10);
const STORY_CAPTION_MAX_LEN = parseInt(process.env.STORY_CAPTION_MAX_LEN || '300', 10);
const allowedStoryHosts = (
    process.env.STORY_MEDIA_ALLOWED_HOSTS ||
    [
        process.env.S3_BUCKET ? `${process.env.S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com` : '',
        process.env.S3_BUCKET ? `${process.env.S3_BUCKET}.s3.amazonaws.com` : '',
        process.env.CLOUDFRONT_DOMAIN || ''
    ].filter(Boolean).join(',')
)
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);

requiredInProduction(['MONGO_URI', 'JWT_SECRET']);

// Middleware
applyRequestContext(app);
applyCommonSecurity(app);
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => logEvent('feed-service', 'info', 'mongodb.connected'))
    .catch(err => logEvent('feed-service', 'error', 'mongodb.connection_failed', { error: err.message }));

// Auth Middleware
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return sendError(res, 401, ErrorCodes.UNAUTHORIZED, 'No token provided');
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId || decoded._id;
        next();
    } catch (error) {
        return sendError(res, 401, ErrorCodes.INVALID_TOKEN, 'Invalid token');
    }
};

// Get personalized feed
app.get('/api/feed', authMiddleware, async (req, res) => {
    try {
        const { limit = 20, skip = 0 } = req.query;

        // Get user's following list
        const user = await User.findById(req.userId).select('following');

        if (!user) {
            return sendError(res, 404, ErrorCodes.NOT_FOUND, 'User not found');
        }

        // Get posts from followed users + own posts
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
            isLiked: (post.likes || []).some((id) => id.toString() === req.userId) || false
        }));

        res.json({ success: true, posts: enrichedPosts, cached: false });
    } catch (error) {
        logEvent('feed-service', 'error', 'feed.get_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to get feed');
    }
});

// Get stories
app.get('/api/feed/stories', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('following');
        if (!user) {
            return sendError(res, 404, ErrorCodes.NOT_FOUND, 'User not found');
        }

        const now = new Date();
        const participantIds = [...new Set([...user.following.map((id) => id.toString()), req.userId])];
        const rawStories = await Story.find({
            userId: { $in: participantIds },
            expiresAt: { $gt: now }
        })
            .sort({ createdAt: -1 })
            .populate('userId', 'name profilePhoto profilePicture isVerified')
            .lean();

        const storiesByUser = new Map();
        for (const story of rawStories) {
            const storyUser = story.userId;
            const uid = storyUser?._id?.toString();
            if (!uid || storiesByUser.has(uid)) continue;
            const seen = (story.viewers || []).some((viewerId) => viewerId.toString() === req.userId);
            storiesByUser.set(uid, {
                userId: storyUser._id,
                name: storyUser.name || 'User',
                profilePhoto: storyUser.profilePhoto || storyUser.profilePicture || null,
                profilePicture: storyUser.profilePicture || storyUser.profilePhoto || null,
                isVerified: Boolean(storyUser.isVerified),
                hasStory: true,
                seen,
                storyId: story._id,
                mediaUrl: story.mediaUrl,
                mediaType: story.mediaType,
                caption: story.caption || '',
                expiresAt: story.expiresAt,
                createdAt: story.createdAt
            });
        }

        const stories = Array.from(storiesByUser.values());

        res.json({ success: true, stories });
    } catch (error) {
        logEvent('feed-service', 'error', 'stories.get_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to get stories');
    }
});

app.post('/api/feed/stories', authMiddleware, async (req, res) => {
    try {
        const { mediaUrl, mediaType, caption } = req.body;
        if (!mediaUrl || typeof mediaUrl !== 'string') {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'mediaUrl is required');
        }
        const normalizedMediaUrl = mediaUrl.trim();
        let parsedUrl = null;
        try {
            parsedUrl = new URL(normalizedMediaUrl);
        } catch (error) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'Invalid mediaUrl format');
        }
        if (parsedUrl.protocol !== 'https:') {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'mediaUrl must be https');
        }
        if (allowedStoryHosts.length > 0 && !allowedStoryHosts.includes(parsedUrl.hostname.toLowerCase())) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'mediaUrl host is not allowed');
        }

        const normalizedCaption = typeof caption === 'string' ? caption.trim() : '';
        if (normalizedCaption.length > STORY_CAPTION_MAX_LEN) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, `caption exceeds ${STORY_CAPTION_MAX_LEN} characters`);
        }

        const user = await User.findById(req.userId).select('_id');
        if (!user) {
            return sendError(res, 404, ErrorCodes.NOT_FOUND, 'User not found');
        }

        const now = new Date();
        const activeStoriesCount = await Story.countDocuments({
            userId: req.userId,
            expiresAt: { $gt: now }
        });
        if (activeStoriesCount >= MAX_STORIES_PER_USER) {
            return sendError(res, 429, ErrorCodes.RATE_LIMITED, 'Story limit reached. Please wait for older stories to expire.');
        }

        const recentStoriesCount = await Story.countDocuments({
            userId: req.userId,
            createdAt: { $gt: new Date(Date.now() - STORY_CREATE_WINDOW_MS) }
        });
        if (recentStoriesCount >= STORY_CREATE_MAX_IN_WINDOW) {
            return sendError(res, 429, ErrorCodes.RATE_LIMITED, 'Too many stories created in a short time. Try again later.');
        }

        const story = await Story.create({
            userId: req.userId,
            mediaUrl: normalizedMediaUrl,
            mediaType: mediaType === 'video' ? 'video' : 'image',
            caption: normalizedCaption,
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
        });

        const populated = await Story.findById(story._id)
            .populate('userId', 'name profilePhoto profilePicture isVerified')
            .lean();
        res.status(201).json({ success: true, story: populated });
    } catch (error) {
        logEvent('feed-service', 'error', 'stories.create_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to create story');
    }
});

app.post('/api/feed/stories/:id/view', authMiddleware, async (req, res) => {
    try {
        const storyId = req.params.id;
        if (!mongoose.Types.ObjectId.isValid(storyId)) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'Invalid story ID');
        }

        const story = await Story.findOneAndUpdate(
            { _id: storyId, expiresAt: { $gt: new Date() } },
            { $addToSet: { viewers: req.userId } },
            { new: true }
        ).lean();

        if (!story) {
            return sendError(res, 404, ErrorCodes.NOT_FOUND, 'Story not found');
        }
        res.json({ success: true });
    } catch (error) {
        logEvent('feed-service', 'error', 'stories.view_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to mark story as viewed');
    }
});

app.delete('/api/feed/stories/:id', authMiddleware, async (req, res) => {
    try {
        const storyId = req.params.id;
        if (!mongoose.Types.ObjectId.isValid(storyId)) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'Invalid story ID');
        }

        const deleted = await Story.findOneAndDelete({ _id: storyId, userId: req.userId });
        if (!deleted) {
            return sendError(res, 404, ErrorCodes.NOT_FOUND, 'Story not found');
        }
        res.json({ success: true });
    } catch (error) {
        logEvent('feed-service', 'error', 'stories.delete_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to delete story');
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', service: 'feed-service' });
});

app.listen(PORT, () => {
    logEvent('feed-service', 'info', 'service.started', { port: PORT });
});
