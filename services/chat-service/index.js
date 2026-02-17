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
        const chats = await Chat.find({ participants: req.userId })
            .populate('participants', 'name profilePicture')
            .sort({ lastMessageAt: -1 });
        res.json({ chats });
    } catch (error) {
        logEvent('chat-service', 'error', 'chats.list_failed', { requestId: req.requestId, error: error.message, userId: req.userId });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to get chats');
    }
});

app.get('/api/chats/:chatId', authMiddleware, async (req, res) => {
    try {
        const { chatId } = req.params;
        if (!mongoose.Types.ObjectId.isValid(chatId)) {
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'Invalid Chat ID format');
        }

        const chat = await Chat.findOne({
            _id: chatId,
            participants: req.userId
        }).populate('participants', 'name profilePicture');

        if (!chat) return sendError(res, 404, ErrorCodes.NOT_FOUND, 'Chat not found');
        res.json({ chat });
    } catch (error) {
        logEvent('chat-service', 'error', 'chats.get_failed', { requestId: req.requestId, error: error.message, userId: req.userId });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to fetch chat messages');
    }
});

app.post('/api/chats', authMiddleware, async (req, res) => {
    try {
        const { type, participants } = req.body;
        const currentUserId = req.userId;

        let allParticipants = [currentUserId];
        if (participants && Array.isArray(participants)) {
            allParticipants = [...new Set([...allParticipants, ...participants])];
        }

        if (type === 'chat' && allParticipants.length === 2) {
            const existingChat = await Chat.findOne({
                type: 'chat',
                participants: { $all: allParticipants, $size: 2 }
            }).populate('participants', 'name profilePicture');
            if (existingChat) return res.json(existingChat);
        }

        const chat = await Chat.create({
            type: type || 'chat',
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

