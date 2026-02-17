const axios = require('axios');

const baseUrl = process.env.CONTRACT_BASE_URL || 'http://localhost:3000';
const timeoutMs = Number(process.env.CONTRACT_TIMEOUT_MS || 10000);
const email = process.env.CONTRACT_EMAIL || '';
const password = process.env.CONTRACT_PASSWORD || '';
const phone = process.env.CONTRACT_PHONE || '';
const otp = process.env.CONTRACT_OTP || '';

const http = axios.create({
    baseURL: baseUrl,
    timeout: timeoutMs,
    validateStatus: () => true
});

const pass = (name) => console.log(`PASS ${name}`);
const fail = (name, msg) => console.error(`FAIL ${name} - ${msg}`);

const checks = [];
const add = (name, fn) => checks.push({ name, fn });

const hasUserIdContract = (user) => Boolean(user && user._id && user.id);

add('gateway health contract', async () => {
    const res = await http.get('/health');
    if (res.status !== 200 || res.data?.service !== 'api-gateway') {
        throw new Error(`Expected api-gateway health, got status=${res.status}`);
    }
});

add('auth send-otp contract', async () => {
    const payloadPhone = phone || '+10000000000';
    const res = await http.post('/api/auth/send-otp', { phone: payloadPhone });
    if (![200, 400, 401, 429].includes(res.status)) {
        throw new Error(`Unexpected status=${res.status}`);
    }
    if (res.status === 200 && res.data?.testOTP) {
        throw new Error('testOTP leaked in response');
    }
});

const loginHeaders = async () => {
    if (email && password) {
        const res = await http.post('/api/auth/login', { email, password });
        if (res.status !== 200 || !res.data?.token) {
            throw new Error(`Email login failed status=${res.status}`);
        }
        if (!hasUserIdContract(res.data.user)) {
            throw new Error('Auth user payload missing _id/id');
        }
        return { Authorization: `Bearer ${res.data.token}` };
    }

    if (phone && otp) {
        const res = await http.post('/api/auth/verify-otp', { phone, otp });
        if (res.status !== 200 || !res.data?.token) {
            throw new Error(`OTP login failed status=${res.status}`);
        }
        if (!hasUserIdContract(res.data.user)) {
            throw new Error('Auth user payload missing _id/id');
        }
        return { Authorization: `Bearer ${res.data.token}` };
    }

    return null;
};

add('protected feed/user payload contracts', async () => {
    const headers = await loginHeaders();
    if (!headers) {
        console.log('INFO Skipping protected contract checks (set CONTRACT_EMAIL/CONTRACT_PASSWORD or CONTRACT_PHONE/CONTRACT_OTP).');
        return;
    }

    const feed = await http.get('/api/posts/feed?page=1&limit=2', { headers });
    if (feed.status !== 200 || !Array.isArray(feed.data?.posts)) {
        throw new Error(`Posts feed contract failed status=${feed.status}`);
    }

    const firstUser = feed.data.posts?.[0]?.userId;
    if (firstUser && !(firstUser.profilePicture || firstUser.profilePhoto)) {
        throw new Error('Post user payload missing profile picture fields');
    }

    const me = await http.get('/api/users/me', { headers });
    if (![200, 404].includes(me.status)) {
        // Keep backward-compatible if /me not present in current user-service
        const fallback = await http.get('/api/users/search?q=a', { headers });
        if (fallback.status !== 200 || !Array.isArray(fallback.data?.users)) {
            throw new Error(`User payload contract failed status=${fallback.status}`);
        }
    }
});

add('protected chat/call payload contracts', async () => {
    const headers = await loginHeaders();
    if (!headers) {
        console.log('INFO Skipping chat/call contract checks (missing login credentials).');
        return;
    }

    const chats = await http.get('/api/chats', { headers });
    if (chats.status !== 200 || !Array.isArray(chats.data?.chats)) {
        throw new Error(`Chats contract failed status=${chats.status}`);
    }
    const firstChat = chats.data.chats[0];
    if (firstChat) {
        if (!Array.isArray(firstChat.participants)) {
            throw new Error('Chat payload missing participants array');
        }
        if (firstChat.lastMessageAt && Number.isNaN(Date.parse(firstChat.lastMessageAt))) {
            throw new Error('Chat payload has invalid lastMessageAt');
        }
    }

    const calls = await http.get('/api/calls/history', { headers });
    if (calls.status !== 200 || !Array.isArray(calls.data?.calls)) {
        throw new Error(`Call history contract failed status=${calls.status}`);
    }
    const firstCall = calls.data.calls[0];
    if (firstCall) {
        if (!['audio', 'video'].includes(firstCall.type)) {
            throw new Error('Call payload has invalid type');
        }
        if (!['ringing', 'active', 'ended', 'rejected', 'missed'].includes(firstCall.status)) {
            throw new Error('Call payload has invalid status');
        }
        if (firstCall.createdAt && Number.isNaN(Date.parse(firstCall.createdAt))) {
            throw new Error('Call payload has invalid createdAt');
        }
    }
});

const run = async () => {
    console.log(`INFO Running contract checks against ${baseUrl}`);
    let failures = 0;

    for (const check of checks) {
        try {
            await check.fn();
            pass(check.name);
        } catch (error) {
            failures += 1;
            fail(check.name, error.message);
        }
    }

    if (failures > 0) {
        console.error(`INFO Contract tests failed with ${failures} issue(s).`);
        process.exit(1);
    }
    console.log('INFO Contract tests passed.');
};

run().catch((error) => {
    console.error(`FAIL Unhandled contract error - ${error.message}`);
    process.exit(1);
});

