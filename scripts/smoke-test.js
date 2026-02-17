const axios = require('axios');

const gatewayBase = process.env.SMOKE_BASE_URL || 'http://localhost:3000';
const timeoutMs = Number(process.env.SMOKE_TIMEOUT_MS || 10000);
const bearerToken = process.env.SMOKE_JWT || '';
const adminToken = process.env.SMOKE_ADMIN_JWT || '';
const smokeUserId = process.env.SMOKE_USER_ID || '';

const ok = (name, details = '') => console.log(`PASS ${name}${details ? ` - ${details}` : ''}`);
const fail = (name, details = '') => console.error(`FAIL ${name}${details ? ` - ${details}` : ''}`);

const http = axios.create({
    baseURL: gatewayBase,
    timeout: timeoutMs,
    validateStatus: () => true
});

const buildHeaders = () => (bearerToken ? { Authorization: `Bearer ${bearerToken}` } : {});

const checks = [];

const addCheck = (name, fn) => checks.push({ name, fn });

addCheck('gateway health', async () => {
    const requestId = `smoke-${Date.now()}`;
    const res = await http.get('/health', {
        headers: { 'x-request-id': requestId }
    });
    if (res.status !== 200 || res.data?.service !== 'api-gateway') {
        throw new Error(`Expected 200 api-gateway, got status=${res.status}`);
    }
    if (res.headers['x-request-id'] !== requestId) {
        throw new Error('x-request-id not echoed by gateway');
    }
});

addCheck('auth route proxy', async () => {
    const res = await http.post('/api/auth/send-otp', { phone: '+10000000000' });
    if (![200, 400, 401, 404, 429].includes(res.status)) {
        throw new Error(`Unexpected status=${res.status}`);
    }
});

addCheck('chat socket path reachability', async () => {
    const res = await http.get('/socket-chat.io/', {
        params: { EIO: 4, transport: 'polling', t: Date.now() }
    });
    if (res.status !== 200 || typeof res.data !== 'string' || !res.data.startsWith('0')) {
        throw new Error(`Expected engine.io open packet, status=${res.status}`);
    }
});

addCheck('call socket path reachability', async () => {
    const res = await http.get('/socket.io/', {
        params: { EIO: 4, transport: 'polling', t: Date.now() }
    });
    if (res.status !== 200 || typeof res.data !== 'string' || !res.data.startsWith('0')) {
        throw new Error(`Expected engine.io open packet, status=${res.status}`);
    }
});

if (bearerToken) {
    addCheck('protected posts feed', async () => {
        const res = await http.get('/api/posts/feed?page=1&limit=1', { headers: buildHeaders() });
        if (res.status !== 200 || !Array.isArray(res.data?.posts)) {
            throw new Error(`Expected posts array, status=${res.status}`);
        }
    });

    addCheck('protected reels feed', async () => {
        const res = await http.get('/api/reels/feed?page=1&limit=1', { headers: buildHeaders() });
        if (res.status !== 200 || !Array.isArray(res.data?.reels)) {
            throw new Error(`Expected reels array, status=${res.status}`);
        }
    });

    addCheck('protected chats list', async () => {
        const res = await http.get('/api/chats', { headers: buildHeaders() });
        if (res.status !== 200 || !Array.isArray(res.data?.chats)) {
            throw new Error(`Expected chats array, status=${res.status}`);
        }
    });

    addCheck('protected call history', async () => {
        const res = await http.get('/api/calls/history', { headers: buildHeaders() });
        if (res.status !== 200 || !Array.isArray(res.data?.calls)) {
            throw new Error(`Expected calls array, status=${res.status}`);
        }
    });

    if (smokeUserId) {
        addCheck('protected user profile contract', async () => {
            const res = await http.get(`/api/users/${smokeUserId}`, { headers: buildHeaders() });
            if (res.status !== 200 || !res.data?.user?._id) {
                throw new Error(`Expected user payload, status=${res.status}`);
            }
        });
    }
} else {
    console.log('INFO Protected route checks skipped (set SMOKE_JWT to enable).');
}

if (adminToken) {
    addCheck('admin media audit logs route', async () => {
        const res = await http.get('/api/admin/media/audit-logs?page=1&limit=1', {
            headers: { Authorization: `Bearer ${adminToken}` }
        });
        if (res.status !== 200 || !Array.isArray(res.data?.logs)) {
            throw new Error(`Expected admin audit logs array, status=${res.status}`);
        }
    });
} else {
    console.log('INFO Admin audit check skipped (set SMOKE_ADMIN_JWT to enable).');
}

const run = async () => {
    console.log(`INFO Running smoke checks against ${gatewayBase}`);
    let failures = 0;

    for (const check of checks) {
        try {
            await check.fn();
            ok(check.name);
        } catch (error) {
            failures += 1;
            fail(check.name, error.message);
        }
    }

    if (failures > 0) {
        console.error(`INFO Smoke failed with ${failures} failing check(s).`);
        process.exit(1);
    }

    console.log('INFO Smoke passed.');
};

run().catch((error) => {
    console.error(`FAIL Unhandled smoke error - ${error.message}`);
    process.exit(1);
});

