const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config({ path: '../../.env' });

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: { origin: process.env.ALLOWED_ORIGINS?.split(',') }
});

const PORT = process.env.CHAT_SERVICE_URL?.split(':')[2] || 3005;

// Middleware
app.use(cors({ origin: '*' })); // Allow all origins for testing
app.use(express.json());

// Chat Schema
const chatSchema = new mongoose.Schema({
    type: { type: String, enum: ['chat', 'community', 'debate'], default: 'chat' },
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    name: String, // For communities/debates
    lastMessage: String,
    lastMessageAt: Date,
    unreadCount: { type: Map, of: Number }, // userId -> count
    createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
    chatId: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', required: true },
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: String,
    mediaUrl: String,
    readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now }
});

const Chat = mongoose.model('Chat', chatSchema);
const Message = mongoose.model('Message', messageSchema);

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Chat Service: MongoDB connected'))
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

// Socket.io Authentication
io.use((socket, next) => {
    const token = socket.handshake.auth.token;

    if (!token) {
        return next(new Error('Authentication error'));
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        socket.userId = decoded.userId;
        next();
    } catch (error) {
        next(new Error('Authentication error'));
    }
});

// Socket.io Events
io.on('connection', (socket) => {
    console.log(`User connected: ${socket.userId}`);

    // Join chat room
    socket.on('join-chat', async (chatId) => {
        socket.join(chatId);
        console.log(`User ${socket.userId} joined chat ${chatId}`);
    });

    // Send message
    socket.on('send-message', async (data) => {
        try {
            const { chatId, text, mediaUrl } = data;

            const message = new Message({
                chatId,
                senderId: socket.userId,
                text,
                mediaUrl,
                readBy: [socket.userId]
            });

            await message.save();

            // Update chat last message
            await Chat.findByIdAndUpdate(chatId, {
                lastMessage: text || 'Media',
                lastMessageAt: new Date()
            });

            // Populate sender info
            const populatedMessage = await Message.findById(message._id)
                .populate('senderId', 'name profilePhoto');

            // Emit to all users in the chat
            io.to(chatId).emit('new-message', populatedMessage);
        } catch (error) {
            console.error('Send message error:', error);
            socket.emit('error', { message: 'Failed to send message' });
        }
    });

    // Typing indicator
    socket.on('typing', (data) => {
        socket.to(data.chatId).emit('user-typing', {
            userId: socket.userId,
            chatId: data.chatId
        });
    });

    // Mark message as read
    socket.on('mark-read', async (data) => {
        try {
            const { messageId } = data;

            await Message.findByIdAndUpdate(messageId, {
                $addToSet: { readBy: socket.userId }
            });

            socket.emit('message-read', { messageId });
        } catch (error) {
            console.error('Mark read error:', error);
        }
    });

    socket.on('disconnect', () => {
        console.log(`User disconnected: ${socket.userId}`);
    });
});

// REST API Routes

// Get all chats for user
app.get('/api/chats', authMiddleware, async (req, res) => {
    try {
        const { type } = req.query; // 'chat', 'community', 'debate'

        const query = { participants: req.userId };
        if (type) query.type = type;

        const chats = await Chat.find(query)
            .sort({ lastMessageAt: -1 })
            .populate('participants', 'name profilePhoto isVerified');

        res.json({ success: true, chats });
    } catch (error) {
        console.error('Get chats error:', error);
        res.status(500).json({ error: 'Failed to get chats' });
    }
});

// Create chat
app.post('/api/chats', authMiddleware, async (req, res) => {
    try {
        const { type, participants, name } = req.body;

        if (!participants || participants.length === 0) {
            return res.status(400).json({ error: 'Participants required' });
        }

        // Add current user to participants
        const allParticipants = [...new Set([...participants, req.userId])];

        // Check if chat already exists (for 1-on-1 chats)
        if (type === 'chat' && allParticipants.length === 2) {
            const existingChat = await Chat.findOne({
                type: 'chat',
                participants: { $all: allParticipants, $size: 2 }
            });

            if (existingChat) {
                return res.json({ success: true, chat: existingChat });
            }
        }

        const chat = new Chat({
            type: type || 'chat',
            participants: allParticipants,
            name,
            unreadCount: new Map()
        });

        await chat.save();

        const populatedChat = await Chat.findById(chat._id)
            .populate('participants', 'name profilePhoto isVerified');

        res.json({ success: true, chat: populatedChat });
    } catch (error) {
        console.error('Create chat error:', error);
        res.status(500).json({ error: 'Failed to create chat' });
    }
});

// Get messages for a chat
app.get('/api/chats/:id/messages', authMiddleware, async (req, res) => {
    try {
        const { limit = 50, skip = 0 } = req.query;

        const messages = await Message.find({ chatId: req.params.id })
            .sort({ createdAt: -1 })
            .limit(parseInt(limit))
            .skip(parseInt(skip))
            .populate('senderId', 'name profilePhoto');

        res.json({ success: true, messages: messages.reverse() });
    } catch (error) {
        console.error('Get messages error:', error);
        res.status(500).json({ error: 'Failed to get messages' });
    }
});

// Send message (REST endpoint)
app.post('/api/chats/:id/messages', authMiddleware, async (req, res) => {
    try {
        const { text, mediaUrl } = req.body;

        const message = new Message({
            chatId: req.params.id,
            senderId: req.userId,
            text,
            mediaUrl,
            readBy: [req.userId]
        });

        await message.save();

        // Update chat
        await Chat.findByIdAndUpdate(req.params.id, {
            lastMessage: text || 'Media',
            lastMessageAt: new Date()
        });

        const populatedMessage = await Message.findById(message._id)
            .populate('senderId', 'name profilePhoto');

        // Emit via Socket.io
        io.to(req.params.id).emit('new-message', populatedMessage);

        res.json({ success: true, message: populatedMessage });
    } catch (error) {
        console.error('Send message error:', error);
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// Get communities
app.get('/api/communities', authMiddleware, async (req, res) => {
    try {
        const communities = await Chat.find({
            type: 'community',
            participants: req.userId
        })
            .sort({ lastMessageAt: -1 })
            .populate('participants', 'name profilePhoto');

        res.json({ success: true, communities });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get communities' });
    }
});

// Get debates
app.get('/api/debates', authMiddleware, async (req, res) => {
    try {
        const debates = await Chat.find({
            type: 'debate',
            participants: req.userId
        })
            .sort({ lastMessageAt: -1 })
            .populate('participants', 'name profilePhoto');

        res.json({ success: true, debates });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get debates' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', service: 'chat-service' });
});

server.listen(PORT, () => {
    console.log(`🚀 Chat Service running on port ${PORT}`);
});
