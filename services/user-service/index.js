const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config({ path: '../../.env' });

const app = express();
const PORT = process.env.USER_SERVICE_URL?.split(':')[2] || 3002;

// Middleware
app.use(cors({ origin: '*' })); // Allow all origins for testing
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

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ User Service: MongoDB connected'))
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

// Get user profile
app.get('/api/users/profile/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id)
            .select('-__v')
            .populate('followers', 'name profilePhoto')
            .populate('following', 'name profilePhoto');

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
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
        console.error('Get profile error:', error);
        res.status(500).json({ error: 'Failed to get profile' });
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
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Follow user
app.post('/api/users/follow/:id', authMiddleware, async (req, res) => {
    try {
        const targetUserId = req.params.id;

        if (targetUserId === req.userId) {
            return res.status(400).json({ error: 'Cannot follow yourself' });
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
        console.error('Follow error:', error);
        res.status(500).json({ error: 'Failed to follow user' });
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
        console.error('Unfollow error:', error);
        res.status(500).json({ error: 'Failed to unfollow user' });
    }
});

// Get followers
app.get('/api/users/followers/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id)
            .populate('followers', 'name profilePhoto isVerified');

        res.json({ success: true, followers: user.followers });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get followers' });
    }
});

// Get following
app.get('/api/users/following/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id)
            .populate('following', 'name profilePhoto isVerified');

        res.json({ success: true, following: user.following });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get following' });
    }
});

// Get nearby users (for map)
app.get('/api/users/nearby', async (req, res) => {
    try {
        const { longitude, latitude, maxDistance = 50000 } = req.query; // 50km default

        if (!longitude || !latitude) {
            return res.status(400).json({ error: 'Location coordinates required' });
        }

        const users = await User.find({
            location: {
                $near: {
                    $geometry: {
                        type: 'Point',
                        coordinates: [parseFloat(longitude), parseFloat(latitude)]
                    },
                    $maxDistance: parseInt(maxDistance)
                }
            }
        }).limit(50).select('name profilePhoto location categories isVerified');

        res.json({ success: true, users });
    } catch (error) {
        console.error('Nearby users error:', error);
        res.status(500).json({ error: 'Failed to get nearby users' });
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
        console.error('Category users error:', error);
        res.status(500).json({ error: 'Failed to get users by category' });
    }
});

// Search users
app.get('/api/users/search', async (req, res) => {
    try {
        const { q } = req.query;

        if (!q) {
            return res.status(400).json({ error: 'Search query required' });
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
        res.status(500).json({ error: 'Search failed' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', service: 'user-service' });
});

app.listen(PORT, () => {
    console.log(`🚀 User Service running on port ${PORT}`);
});
