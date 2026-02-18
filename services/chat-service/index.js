const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { getAllowedOrigins, requiredInProduction } = require('../_shared/config');
const { applyCommonSecurity } = require('../_shared/security');
const { applyRequestContext } = require('../_shared/observability');
const { registerSharedModels } = require('../_shared/models');
const { sendError, ErrorCodes } = require('../_shared/http');
const { logEvent } = require('../_shared/logger');

const app = express();
const allowedOrigins = getAllowedOrigins();
const server = http.createServer(app);
const io = socketIo(server, {
    path: '/socket-chat.io',
    cors: { origin: allowedOrigins.includes('*') ? '*' : allowedOrigins }
});

const PORT = process.env.CHAT_SERVICE_URL?.split(':')[2] || 3005;

requiredInProduction(['MONGO_URI', 'JWT_SECRET']);
applyRequestContext(app);
applyCommonSecurity(app);
app.use(express.json());
const { Chat } = registerSharedModels();

mongoose.connect(process.env.MONGO_URI)
    .then(() => logEvent('chat-service', 'info', 'mongodb.connected'))
    .catch((err) => logEvent('chat-service', 'error', 'mongodb.connection_failed', { error: err.message }));

const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return sendError(res, 401, ErrorCodes.UNAUTHORIZED, 'No token provided');
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId || decoded._id;
        next();
    } catch (error) {
        return sendError(res, 401, ErrorCodes.INVALID_TOKEN, 'Invalid token');
    }
};

io.use((socket, next) => {
    try {
        const token = socket.handshake.auth?.token;
        if (!token) return next(new Error('Unauthorized'));
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.userId || decoded._id;
        if (!userId) return next(new Error('Unauthorized'));
        socket.userId = userId.toString();
        next();
    } catch (error) {
        next(new Error('Unauthorized'));
    }
});

io.on('connection', (socket) => {
    logEvent('chat-service', 'info', 'socket.connected', { socketId: socket.id, userId: socket.userId });

    socket.on('join-chat', async (payload, callback) => {
        const chatId = typeof payload === 'string' ? payload : payload?.chatId;
        try {
            if (!chatId || !mongoose.Types.ObjectId.isValid(chatId)) {
                if (typeof callback === 'function') callback({ ok: false, error: 'Invalid chat ID' });
                return;
            }

            const chat = await Chat.findOne({ _id: chatId, participants: socket.userId }).select('_id');
            if (!chat) {
                if (typeof callback === 'function') callback({ ok: false, error: 'Chat not found or access denied' });
                return;
            }

            socket.join(chatId);
            if (typeof callback === 'function') callback({ ok: true, chatId });
        } catch (error) {
            logEvent('chat-service', 'error', 'socket.join_chat_failed', { error: error.message, userId: socket.userId, chatId });
            if (typeof callback === 'function') callback({ ok: false, error: 'Failed to join chat' });
        }
    });

    socket.on('send-message', async (data, callback) => {
        const { chatId, text, clientMessageId } = data || {};
        const safeText = typeof text === 'string' ? text.trim() : '';
        try {
            if (!chatId || !mongoose.Types.ObjectId.isValid(chatId) || !safeText) {
                if (typeof callback === 'function') callback({ ok: false, error: 'Invalid payload' });
                return;
            }

            const chat = await Chat.findOneAndUpdate(
                { _id: chatId, participants: socket.userId },
                {
                    $push: { messages: { senderId: socket.userId, text: safeText, type: 'text' } },
                    lastMessage: safeText,
                    lastMessageAt: new Date()
                },
                { new: true }
            );

            if (!chat) {
                if (typeof callback === 'function') callback({ ok: false, error: 'Chat not found or access denied' });
                return;
            }

            const newMessage = chat.messages[chat.messages.length - 1];
            const payload = { chatId, message: newMessage, clientMessageId: clientMessageId || null };
            io.to(chatId).emit('new-message', payload);

            if (typeof callback === 'function') callback({ ok: true, payload });
        } catch (error) {
            logEvent('chat-service', 'error', 'socket.send_message_failed', { error: error.message, userId: socket.userId, chatId });
            if (typeof callback === 'function') callback({ ok: false, error: 'Failed to send message' });
        }
    });

    socket.on('user-typing', async (data) => {
        const { chatId, isTyping } = data || {};
        if (!chatId || !mongoose.Types.ObjectId.isValid(chatId)) return;

        try {
            const chat = await Chat.findOne({ _id: chatId, participants: socket.userId }).select('_id');
            if (!chat) return;

            socket.to(chatId).emit('user-typing', {
                chatId,
                userId: socket.userId,
                isTyping: Boolean(isTyping)
            });
        } catch (error) {
            logEvent('chat-service', 'warn', 'socket.user_typing_failed', { error: error.message, userId: socket.userId, chatId });
        }
    });
});

app.get('/api/chats', authMiddleware, async (req, res) => {
    try {
        const userId = new mongoose.Types.ObjectId(req.userId);
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        const chats = await Chat.find({ participants: userId })
            .populate('participants', 'name profilePicture')
            .sort({ lastMessageAt: -1 })
            .skip(skip)
            .limit(limit);

        const total = await Chat.countDocuments({ participants: userId });

        // Double check participant inclusion (security)
        const filteredChats = chats.filter(chat =>
            chat.participants.some(p => p._id.toString() === req.userId.toString())
        );

        res.json({
            chats: filteredChats,
            pagination: {
                total,
                page,
                limit,
                hasMore: total > skip + chats.length
            }
        });
    } catch (error) {
        logEvent('chat-service', 'error', 'chats.list_failed', { requestId: req.requestId, error: error.message, userId: req.userId });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to get chats');
    }
});

app.get('/api/chats/:chatId', authMiddleware, async (req, res) => {
    try {
        const { chatId } = req.params;
        const limit = parseInt(req.query.limit) || 50;
        const before = req.query.before; // ISO timestamp for cursor-based message pagination

        if (!mongoose.Types.ObjectId.isValid(chatId)) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'Invalid Chat ID format');
        }

        // For large message histories, we should slice the messages array
        // However, standard Mongoose .find() returns the whole doc.
        // We use aggregation or projection with $slice if the messages array is huge.

        let query = { _id: chatId, participants: req.userId };

        // Find the chat first to get basic info
        const chatDoc = await Chat.findOne(query)
            .populate('participants', 'name profilePicture');

        if (!chatDoc) return sendError(res, 404, ErrorCodes.NOT_FOUND, 'Chat not found');

        // Manual slicing for now as the messages are embedded. 
        // In a more mature system, messages should be a separate collection.
        let allMessages = chatDoc.messages || [];

        // If 'before' is provided, filter messages older than that timestamp
        if (before) {
            const beforeDate = new Date(before);
            allMessages = allMessages.filter(msg => new Date(msg.createdAt) < beforeDate);
        }

        // Sort by createdAt descending to get newest first, then slice for limit
        allMessages.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

        const slicedMessages = allMessages.slice(0, limit);
        const hasMore = allMessages.length > limit;

        // Return messages in ascending order for the UI
        const finalMessages = slicedMessages.reverse();

        res.json({
            chat: {
                ...chatDoc.toObject(),
                messages: finalMessages,
                hasMore
            }
        });
    } catch (error) {
        logEvent('chat-service', 'error', 'chats.get_failed', { requestId: req.requestId, error: error.message, userId: req.userId });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to fetch chat messages');
    }
});

app.post('/api/chats', authMiddleware, async (req, res) => {
    try {
        const { type, participants } = req.body;
        const currentUserId = req.userId;

        // Ensure participants is an array and does not include the current user yet
        let otherParticipants = Array.isArray(participants) ? participants : [];

        // Remove current user if already in array to avoid duplicates
        otherParticipants = otherParticipants.filter(p => p !== currentUserId);

        // Final participants list including current user
        let allParticipants = [currentUserId, ...new Set(otherParticipants)];

        // Strict 1-on-1 chat enforcement
        const chatType = type || 'chat';
        if (chatType === 'chat') {
            if (allParticipants.length !== 2) {
                return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'Individual chats must have exactly 2 participants');
            }
        }

        if (chatType === 'chat') {
            const existingChat = await Chat.findOne({
                type: 'chat',
                participants: { $all: allParticipants, $size: 2 }
            }).populate('participants', 'name profilePicture');

            if (existingChat) return res.json(existingChat);
        }

        const chat = await Chat.create({
            type: chatType,
            participants: allParticipants,
            messages: [],
            lastMessageAt: new Date()
        });

        const populated = await Chat.findById(chat._id).populate('participants', 'name profilePicture');
        res.json(populated);
    } catch (error) {
        logEvent('chat-service', 'error', 'chats.create_failed', { requestId: req.requestId, error: error.message, userId: req.userId });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to create chat');
    }
});

app.get('/health', (req, res) => {
    res.json({ status: 'OK', service: 'chat-service', socketPath: '/socket-chat.io' });
});

server.listen(PORT, () => {
    logEvent('chat-service', 'info', 'service.started', { port: PORT });
});

