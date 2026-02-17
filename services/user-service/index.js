const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { requiredInProduction } = require('../_shared/config');
const { applyCommonSecurity } = require('../_shared/security');
const { applyRequestContext } = require('../_shared/observability');
const { sendError, ErrorCodes } = require('../_shared/http');
const { logEvent } = require('../_shared/logger');

const app = express();
const PORT = process.env.USER_SERVICE_URL?.split(':')[2] || 3002;

requiredInProduction(['MONGO_URI', 'JWT_SECRET']);

// Middleware
applyRequestContext(app);
applyCommonSecurity(app);
app.use(express.json());

// User Schema
const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    phone: String,
    age: Number,
    bio: String,
    profilePhoto: String,
    coverPhoto: String,
    location: {
        type: { type: String, enum: ['Point'], default: 'Point' },
        coordinates: { type: [Number], default: [0, 0] } // [longitude, latitude]
    },
    categories: [String], // ["verified", "sports", "global"]
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    postsCount: { type: Number, default: 0 },
    isVerified: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

userSchema.index({ location: '2dsphere' });

const User = mongoose.model('User', userSchema);

const normalizeUserForApp = (userDoc) => {
    const user = userDoc?.toObject ? userDoc.toObject() : userDoc;
    if (!user) return null;
    return {
        _id: user._id,
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        age: user.age,
        bio: user.bio,
        profilePicture: user.profilePicture || user.profilePhoto || null,
        profilePhoto: user.profilePhoto || user.profilePicture || null,
        coverPhoto: user.coverPhoto || null,
        location: user.location,
        categories: user.categories || [],
        followers: user.followers || [],
        following: user.following || [],
        postsCount: user.postsCount || 0,
        isVerified: Boolean(user.isVerified)
    };
};

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => logEvent('user-service', 'info', 'mongodb.connected'))
    .catch(err => logEvent('user-service', 'error', 'mongodb.connection_failed', { error: err.message }));

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

// Get user profile
app.get('/api/users/profile/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id)
            .select('-__v')
            .populate('followers', 'name profilePhoto')
            .populate('following', 'name profilePhoto');

        if (!user) {
            return sendError(res, 404, ErrorCodes.NOT_FOUND, 'User not found');
        }

        res.json({
            success: true,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                age: user.age,
                bio: user.bio,
                profilePhoto: user.profilePhoto,
                coverPhoto: user.coverPhoto,
                location: user.location,
                categories: user.categories,
                followersCount: user.followers.length,
                followingCount: user.following.length,
                postsCount: user.postsCount,
                isVerified: user.isVerified,
                followers: user.followers,
                following: user.following
            }
        });
    } catch (error) {
        logEvent('user-service', 'error', 'users.profile_lookup_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to get profile');
    }
});

// App-compatible profile route
app.get('/api/users/:id', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.params.id)
            .select('-__v')
            .populate('followers', 'name profilePhoto profilePicture')
            .populate('following', 'name profilePhoto profilePicture');

        if (!user) {
            return sendError(res, 404, ErrorCodes.NOT_FOUND, 'User not found');
        }

        res.json({ user: normalizeUserForApp(user) });
    } catch (error) {
        logEvent('user-service', 'error', 'users.profile_get_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to get profile');
    }
});

// Update user profile
app.put('/api/users/profile', authMiddleware, async (req, res) => {
    try {
        const { name, bio, age, profilePhoto, coverPhoto, location, categories } = req.body;

        const updateData = {};
        if (name) updateData.name = name;
        if (bio) updateData.bio = bio;
        if (age) updateData.age = age;
        if (profilePhoto) updateData.profilePhoto = profilePhoto;
        if (coverPhoto) updateData.coverPhoto = coverPhoto;
        if (categories) updateData.categories = categories;
        if (location && location.coordinates) {
            updateData.location = {
                type: 'Point',
                coordinates: location.coordinates
            };
        }

        const user = await User.findByIdAndUpdate(
            req.userId,
            updateData,
            { new: true }
        );

        res.json({ success: true, user });
    } catch (error) {
        logEvent('user-service', 'error', 'users.profile_update_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to update profile');
    }
});

// Follow user
app.post('/api/users/follow/:id', authMiddleware, async (req, res) => {
    try {
        const targetUserId = req.params.id;

        if (targetUserId === req.userId) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'Cannot follow yourself');
        }

        // Add to following
        await User.findByIdAndUpdate(req.userId, {
            $addToSet: { following: targetUserId }
        });

        // Add to followers
        await User.findByIdAndUpdate(targetUserId, {
            $addToSet: { followers: req.userId }
        });

        res.json({ success: true, message: 'User followed successfully' });
    } catch (error) {
        logEvent('user-service', 'error', 'users.follow_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to follow user');
    }
});

// App-compatible follow route alias
app.post('/api/users/:id/follow', authMiddleware, async (req, res) => {
    try {
        const targetUserId = req.params.id;
        if (targetUserId === req.userId) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'Cannot follow yourself');
        }

        await User.findByIdAndUpdate(req.userId, {
            $addToSet: { following: targetUserId }
        });
        await User.findByIdAndUpdate(targetUserId, {
            $addToSet: { followers: req.userId }
        });

        res.json({ success: true });
    } catch (error) {
        logEvent('user-service', 'error', 'users.follow_alias_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to follow user');
    }
});

// Unfollow user
app.delete('/api/users/unfollow/:id', authMiddleware, async (req, res) => {
    try {
        const targetUserId = req.params.id;

        // Remove from following
        await User.findByIdAndUpdate(req.userId, {
            $pull: { following: targetUserId }
        });

        // Remove from followers
        await User.findByIdAndUpdate(targetUserId, {
            $pull: { followers: req.userId }
        });

        res.json({ success: true, message: 'User unfollowed successfully' });
    } catch (error) {
        logEvent('user-service', 'error', 'users.unfollow_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to unfollow user');
    }
});

// Get followers
app.get('/api/users/followers/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id)
            .populate('followers', 'name profilePhoto isVerified');

        res.json({ success: true, followers: user.followers });
    } catch (error) {
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to get followers');
    }
});

// Get following
app.get('/api/users/following/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id)
            .populate('following', 'name profilePhoto isVerified');

        res.json({ success: true, following: user.following });
    } catch (error) {
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to get following');
    }
});

// Get nearby users (for map)
app.get('/api/users/nearby', authMiddleware, async (req, res) => {
    try {
        const longitude = req.query.longitude ?? req.query.lng;
        const latitude = req.query.latitude ?? req.query.lat;
        const category = (req.query.category || '').toString().trim().toLowerCase();
        const { maxDistance = 50000 } = req.query; // 50km default

        if (!longitude || !latitude) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'Location coordinates required');
        }

        const query = {
            location: {
                $near: {
                    $geometry: {
                        type: 'Point',
                        coordinates: [parseFloat(longitude), parseFloat(latitude)]
                    },
                    $maxDistance: parseInt(maxDistance)
                }
            }
        };
        if (category) {
            if (category === 'verified') {
                query.isVerified = true;
            } else {
                query.categories = category;
            }
        }

        const users = await User.find(query).limit(50).select('name profilePhoto profilePicture location categories isVerified');

        res.json({ success: true, users });
    } catch (error) {
        logEvent('user-service', 'error', 'users.nearby_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to get nearby users');
    }
});

// Get users by category
app.get('/api/users/by-category/:category', async (req, res) => {
    try {
        const { category } = req.params;
        const { limit = 50 } = req.query;

        const users = await User.find({
            categories: category
        })
            .limit(parseInt(limit))
            .select('name profilePhoto location categories isVerified bio');

        res.json({ success: true, users });
    } catch (error) {
        logEvent('user-service', 'error', 'users.by_category_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to get users by category');
    }
});

// Search users
app.get('/api/users/search', authMiddleware, async (req, res) => {
    try {
        const { q } = req.query;

        if (!q) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'Search query required');
        }

        const users = await User.find({
            $or: [
                { name: { $regex: q, $options: 'i' } },
                { email: { $regex: q, $options: 'i' } }
            ]
        })
            .limit(20)
            .select('name profilePhoto isVerified bio');

        res.json({ success: true, users });
    } catch (error) {
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Search failed');
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', service: 'user-service' });
});

app.listen(PORT, () => {
    logEvent('user-service', 'info', 'service.started', { port: PORT });
});
