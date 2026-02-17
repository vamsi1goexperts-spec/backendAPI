const mongoose = require('mongoose');

const getOrCreateModel = (name, schemaFactory) => {
    if (mongoose.models[name]) {
        return mongoose.models[name];
    }
    return mongoose.model(name, schemaFactory());
};

const createUserSchema = () => new mongoose.Schema({
    name: String,
    email: String,
    phone: String,
    age: Number,
    bio: String,
    profilePhoto: String,
    coverPhoto: String,
    location: {
        type: { type: String, enum: ['Point'], default: 'Point' },
        coordinates: { type: [Number], default: [0, 0] }
    },
    categories: [String],
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    postsCount: { type: Number, default: 0 },
    isVerified: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const createPostSchema = () => new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['post', 'reel'], default: 'post' },
    mediaUrl: String,
    thumbnailUrl: String,
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

const createChatSchema = () => new mongoose.Schema({
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

const createStorySchema = () => {
    const schema = new mongoose.Schema({
        userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        mediaUrl: { type: String, required: true },
        thumbnailUrl: { type: String },
        mediaType: { type: String, enum: ['image', 'video'], default: 'image' },
        caption: { type: String, default: '' },
        viewers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
        expiresAt: { type: Date, required: true }
    }, { timestamps: true });
    schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    schema.index({ userId: 1, createdAt: -1 });
    return schema;
};

const registerSharedModels = () => {
    const User = getOrCreateModel('User', createUserSchema);
    const Post = getOrCreateModel('Post', createPostSchema);
    const Chat = getOrCreateModel('Chat', createChatSchema);
    const Story = getOrCreateModel('Story', createStorySchema);
    return { User, Post, Chat, Story };
};

module.exports = { registerSharedModels };

