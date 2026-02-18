const express = require('express');
const http = require('http');
const { createProxyMiddleware } = require('http-proxy-middleware');
const compression = require('compression');
const { applyCommonSecurity } = require('../_shared/security');
const { requiredInProduction } = require('../_shared/config');
const { applyRequestContext } = require('../_shared/observability');
const { sendError, ErrorCodes } = require('../_shared/http');
const { logEvent } = require('../_shared/logger');

const app = express();
const server = http.createServer(app);

requiredInProduction([
    'AUTH_SERVICE_URL',
    'USER_SERVICE_URL',
    'POST_SERVICE_URL',
    'CHAT_SERVICE_URL',
    'CALL_SERVICE_URL',
    'MEDIA_SERVICE_URL'
]);

const PORT = parseInt(process.env.GATEWAY_PORT || process.env.PORT || '3000', 10);

const targets = {
    auth: process.env.AUTH_SERVICE_URL || 'http://localhost:3001',
    user: process.env.USER_SERVICE_URL || 'http://localhost:3002',
    post: process.env.POST_SERVICE_URL || 'http://localhost:3003',
    feed: process.env.FEED_SERVICE_URL || 'http://localhost:3004',
    chat: process.env.CHAT_SERVICE_URL || 'http://localhost:3005',
    call: process.env.CALL_SERVICE_URL || 'http://localhost:3006',
    media: process.env.MEDIA_SERVICE_URL || 'http://localhost:3008'
};

app.use(compression());
applyCommonSecurity(app);
applyRequestContext(app);

const proxyDefaults = {
    changeOrigin: true,
    xfwd: true,
    proxyTimeout: 30000,
    timeout: 30000,
    onProxyReq: (proxyReq, req) => {
        if (!req.body || Object.keys(req.body).length === 0) {
            return;
        }
        const bodyData = JSON.stringify(req.body);
        proxyReq.setHeader('Content-Type', 'application/json');
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
        proxyReq.write(bodyData);
    },
    onError: (err, req, res) => {
        logEvent('api-gateway', 'error', 'proxy.error', {
            requestId: req.requestId,
            method: req.method,
            path: req.originalUrl,
            error: err.message
        });
        if (!res.headersSent) {
            sendError(res, 502, ErrorCodes.DEPENDENCY_UNAVAILABLE, 'Upstream service unavailable');
        }
    }
};

const proxyTo = (target, extra = {}) => createProxyMiddleware({
    target,
    ...proxyDefaults,
    ...extra
});
const proxyWithPrefix = (target, prefix, extra = {}) => proxyTo(target, {
    ...extra,
    pathRewrite: (path) => `${prefix}${path}`
});

// Service routing
app.use('/api/auth', proxyWithPrefix(targets.auth, '/api/auth'));
app.use('/api/users', proxyWithPrefix(targets.user, '/api/users'));
app.use('/api/posts', proxyWithPrefix(targets.post, '/api/posts'));
app.use('/api/reels', proxyWithPrefix(targets.post, '/api/reels'));
app.use('/api/media', proxyWithPrefix(targets.media, '/api/media'));
app.use('/api/admin/media/audit-logs', proxyTo(targets.media, {
    pathRewrite: (path) => `/api/media/audit-logs${path}`
}));
app.use('/api/feed', proxyWithPrefix(targets.feed, '/api/feed'));

// Transitional legacy routes while migrating contracts.
app.use('/api/chats', proxyWithPrefix(targets.chat, '/api/chats'));
app.use('/api/calls', proxyWithPrefix(targets.call, '/api/calls'));

// Dedicated chat socket namespace/path.
app.use('/socket-chat.io', proxyTo(targets.chat, {
    ws: true,
    pathRewrite: (path) => `/socket-chat.io${path}`
}));

// Calls socket path now points to call-service.
app.use('/socket.io', proxyTo(targets.call, {
    ws: true,
    pathRewrite: (path) => `/socket.io${path}`
}));

app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        service: 'api-gateway',
        routes: {
            auth: targets.auth,
            user: targets.user,
            post: targets.post,
            feed: targets.feed,
            chat: targets.chat,
            call: targets.call,
            media: targets.media
        }
    });
});

server.listen(PORT, () => {
    logEvent('api-gateway', 'info', 'service.started', { port: PORT, targets });
});

