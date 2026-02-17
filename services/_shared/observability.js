const { randomUUID } = require('crypto');

const applyRequestContext = (app) => {
    app.use((req, res, next) => {
        const incomingId = req.headers['x-request-id'];
        const requestId = (typeof incomingId === 'string' && incomingId.trim()) ? incomingId.trim() : randomUUID();
        req.requestId = requestId;
        req.headers['x-request-id'] = requestId;
        res.setHeader('x-request-id', requestId);
        next();
    });
};

module.exports = {
    applyRequestContext
};

