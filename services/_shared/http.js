const ErrorCodes = {
    BAD_REQUEST: 'BAD_REQUEST',
    UNAUTHORIZED: 'UNAUTHORIZED',
    FORBIDDEN: 'FORBIDDEN',
    NOT_FOUND: 'NOT_FOUND',
    RATE_LIMITED: 'RATE_LIMITED',
    INTERNAL_ERROR: 'INTERNAL_ERROR',
    DEPENDENCY_UNAVAILABLE: 'DEPENDENCY_UNAVAILABLE',
    INVALID_TOKEN: 'INVALID_TOKEN'
};

const sendError = (res, status, code, message, details) => {
    const body = { error: message, code };
    if (details) body.details = details;
    return res.status(status).json(body);
};

module.exports = {
    ErrorCodes,
    sendError
};

