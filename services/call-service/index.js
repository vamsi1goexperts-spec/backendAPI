const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const twilio = require('twilio');
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
    path: '/socket.io',
    cors: { origin: allowedOrigins.includes('*') ? '*' : allowedOrigins }
});

const PORT = process.env.CALL_SERVICE_URL?.split(':')[2] || 3006;
const AccessToken = twilio.jwt.AccessToken;
const VideoGrant = AccessToken.VideoGrant;

requiredInProduction(['MONGO_URI', 'JWT_SECRET', 'TWILIO_ACCOUNT_SID']);
applyRequestContext(app);
applyCommonSecurity(app);
app.use(express.json());

const callSchema = new mongoose.Schema({
    callerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['audio', 'video'], default: 'video' },
    status: { type: String, enum: ['ringing', 'active', 'ended', 'rejected', 'missed'], default: 'ringing' },
    roomName: String,
    startedAt: Date,
    endedAt: Date,
    duration: Number,
    createdAt: { type: Date, default: Date.now }
});

const { User, Chat } = registerSharedModels();
const Call = mongoose.models.Call || mongoose.model('Call', callSchema);

mongoose.connect(process.env.MONGO_URI)
    .then(() => logEvent('call-service', 'info', 'mongodb.connected'))
    .catch((err) => logEvent('call-service', 'error', 'mongodb.connection_failed', { error: err.message }));

const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return sendError(res, 401, ErrorCodes.UNAUTHORIZED, 'Access denied');
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return sendError(res, 403, ErrorCodes.INVALID_TOKEN, 'Invalid token');
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
    const userRoom = `user:${socket.userId}`;
    socket.join(userRoom);
    logEvent('call-service', 'info', 'socket.connected', { socketId: socket.id, userId: socket.userId });
});

const emitToUser = (userId, event, payload) => {
    io.to(`user:${userId.toString()}`).emit(event, payload);
};

const addCallMessageToChat = async (callerId, receiverId, messageType, callId, callType) => {
    try {
        let chat = await Chat.findOne({
            participants: { $all: [callerId, receiverId] },
            type: 'chat'
        });

        if (!chat) {
            chat = await Chat.create({
                participants: [callerId, receiverId],
                type: 'chat',
                messages: [],
                lastMessageAt: new Date()
            });
        }

        const callText = {
            'call-started': `${callType === 'video' ? 'Video' : 'Audio'} call started`,
            'call-ended': `${callType === 'video' ? 'Video' : 'Audio'} call ended`,
            'call-missed': `Missed ${callType === 'video' ? 'video' : 'audio'} call`
        }[messageType];

        const newMessage = {
            senderId: callerId,
            text: callText,
            type: messageType,
            callId,
            createdAt: new Date()
        };

        chat.messages.push(newMessage);
        chat.lastMessage = callText;
        chat.lastMessageAt = new Date();
        await chat.save();
    } catch (error) {
        logEvent('call-service', 'error', 'calls.chat_log_failed', { error: error.message, callerId, receiverId, messageType });
    }
};

app.post('/api/calls/token', authMiddleware, async (req, res) => {
    try {
        const { roomName } = req.body;
        const identity = req.user.userId || req.user._id;

        const apiKeySid = process.env.TWILIO_API_KEY_SID || process.env.TWILIO_ACCOUNT_SID;
        const apiKeySecret = process.env.TWILIO_API_KEY_SECRET || process.env.TWILIO_AUTH_TOKEN;
        if (!apiKeySid || !apiKeySecret) {
            return sendError(res, 500, ErrorCodes.DEPENDENCY_UNAVAILABLE, 'Twilio credentials missing');
        }

        const token = new AccessToken(
            process.env.TWILIO_ACCOUNT_SID,
            apiKeySid,
            apiKeySecret,
            { identity, ttl: 3600 }
        );

        token.addGrant(new VideoGrant({ room: roomName }));
        res.json({
            token: token.toJwt(),
            roomName,
            identity
        });
    } catch (error) {
        logEvent('call-service', 'error', 'calls.token_generation_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to generate token', error.message);
    }
});

app.post('/api/calls/initiate', authMiddleware, async (req, res) => {
    try {
        const { receiverId, type } = req.body;
        const callerId = req.user.userId || req.user._id;

        const roomName = `room-${callerId}-${receiverId}-${Date.now()}`;
        const call = await Call.create({
            callerId,
            receiverId,
            type: type || 'video',
            roomName,
            status: 'ringing'
        });

        await addCallMessageToChat(callerId, receiverId, 'call-started', call._id, call.type);

        const caller = await User.findById(callerId).select('name profilePicture');
        emitToUser(receiverId, `incoming-call-${receiverId}`, {
            callId: call._id,
            callerId,
            caller: caller ? {
                _id: caller._id,
                name: caller.name,
                profilePicture: caller.profilePicture || null
            } : null,
            type: call.type,
            roomName
        });

        res.json({ success: true, callId: call._id, roomName });
    } catch (error) {
        logEvent('call-service', 'error', 'calls.initiate_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to initiate call');
    }
});

app.post('/api/calls/:id/accept', authMiddleware, async (req, res) => {
    try {
        const call = await Call.findByIdAndUpdate(
            req.params.id,
            { status: 'active', startedAt: new Date() },
            { new: true }
        );
        if (!call) return sendError(res, 404, ErrorCodes.NOT_FOUND, 'Call not found');

        const receiver = await User.findById(call.receiverId).select('name profilePicture');
        emitToUser(call.callerId, `call-accepted-${call.callerId}`, {
            callId: call._id,
            roomName: call.roomName,
            type: call.type,
            receiver: receiver ? {
                _id: receiver._id,
                name: receiver.name,
                profilePicture: receiver.profilePicture || null
            } : null
        });

        res.json({ success: true, roomName: call.roomName, callId: call._id });
    } catch (error) {
        logEvent('call-service', 'error', 'calls.accept_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to accept call');
    }
});

app.post('/api/calls/:id/reject', authMiddleware, async (req, res) => {
    try {
        const call = await Call.findByIdAndUpdate(
            req.params.id,
            { status: 'rejected', endedAt: new Date() },
            { new: true }
        );
        if (!call) return sendError(res, 404, ErrorCodes.NOT_FOUND, 'Call not found');

        emitToUser(call.callerId, `call-rejected-${call.callerId}`, { callId: call._id });
        await addCallMessageToChat(call.callerId, call.receiverId, 'call-missed', call._id, call.type);
        res.json({ success: true });
    } catch (error) {
        logEvent('call-service', 'error', 'calls.reject_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to reject call');
    }
});

app.post('/api/calls/:id/end', authMiddleware, async (req, res) => {
    try {
        const call = await Call.findById(req.params.id);
        if (!call) return sendError(res, 404, ErrorCodes.NOT_FOUND, 'Call not found');

        const endedAt = new Date();
        const duration = call.startedAt ? Math.floor((endedAt - call.startedAt) / 1000) : 0;
        await Call.findByIdAndUpdate(req.params.id, { status: 'ended', endedAt, duration });
        await addCallMessageToChat(call.callerId, call.receiverId, 'call-ended', call._id, call.type);

        const requesterId = (req.user.userId || req.user._id).toString();
        const otherUserId = call.callerId.toString() === requesterId ? call.receiverId : call.callerId;
        emitToUser(otherUserId, `call-ended-${otherUserId}`, { callId: call._id, duration });

        res.json({ success: true, duration });
    } catch (error) {
        logEvent('call-service', 'error', 'calls.end_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to end call');
    }
});

app.get('/api/calls/history', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.userId || req.user._id;
        const calls = await Call.find({
            $or: [{ callerId: userId }, { receiverId: userId }]
        })
            .populate('callerId', 'name profilePicture')
            .populate('receiverId', 'name profilePicture')
            .sort({ createdAt: -1 })
            .limit(50);
        res.json({ calls });
    } catch (error) {
        logEvent('call-service', 'error', 'calls.history_failed', { requestId: req.requestId, error: error.message });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to fetch call history');
    }
});

app.get('/health', (req, res) => {
    res.json({ status: 'OK', service: 'call-service', socketPath: '/socket.io' });
});

server.listen(PORT, () => {
    logEvent('call-service', 'info', 'service.started', { port: PORT });
});

