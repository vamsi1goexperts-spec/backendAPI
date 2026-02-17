const logEvent = (service, level, event, meta = {}) => {
    const payload = {
        ts: new Date().toISOString(),
        service,
        level,
        event,
        ...meta
    };
    const line = JSON.stringify(payload);
    if (level === 'error') {
        console.error(line);
        return;
    }
    if (level === 'warn') {
        console.warn(line);
        return;
    }
    console.log(line);
};

module.exports = {
    logEvent
};

