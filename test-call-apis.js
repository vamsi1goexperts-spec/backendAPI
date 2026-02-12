const axios = require('axios');

const BASE_URL = 'http://localhost:3000';
let authToken = '';
let userId = '';
let callId = '';

console.log('🧪 Testing Video Call APIs...\n');

async function testCallAPIs() {
    try {
        // 1. Login first
        console.log('1️⃣ Logging in...');
        const otpResponse = await axios.post(`${BASE_URL}/api/auth/send-otp`, {
            phone: '+1234567890'
        });
        const testOTP = otpResponse.data.testOTP;

        const verifyResponse = await axios.post(`${BASE_URL}/api/auth/verify-otp`, {
            phone: '+1234567890',
            otp: testOTP
        });
        authToken = verifyResponse.data.token;
        userId = verifyResponse.data.user._id;
        console.log(`✅ Logged in as: ${userId}`);
        console.log('');

        // 2. Generate Access Token
        console.log('2️⃣ Testing Generate Access Token...');
        const tokenResponse = await axios.post(
            `${BASE_URL}/api/calls/token`,
            { roomName: 'test-room-123' },
            { headers: { Authorization: `Bearer ${authToken}` } }
        );
        console.log('✅ Access Token Generated:', tokenResponse.data);
        console.log('');

        // 3. Initiate Call
        console.log('3️⃣ Testing Initiate Call...');
        const initiateResponse = await axios.post(
            `${BASE_URL}/api/calls/initiate`,
            {
                receiverId: userId, // Calling self for testing
                type: 'video'
            },
            { headers: { Authorization: `Bearer ${authToken}` } }
        );
        console.log('✅ Call Initiated:', initiateResponse.data);
        callId = initiateResponse.data.callId;
        console.log(`📞 Call ID: ${callId}`);
        console.log('');

        // 4. Accept Call
        console.log('4️⃣ Testing Accept Call...');
        const acceptResponse = await axios.post(
            `${BASE_URL}/api/calls/${callId}/accept`,
            {},
            { headers: { Authorization: `Bearer ${authToken}` } }
        );
        console.log('✅ Call Accepted:', acceptResponse.data);
        console.log('');

        // Wait 2 seconds to simulate call duration
        await new Promise(resolve => setTimeout(resolve, 2000));

        // 5. End Call
        console.log('5️⃣ Testing End Call...');
        const endResponse = await axios.post(
            `${BASE_URL}/api/calls/${callId}/end`,
            {},
            { headers: { Authorization: `Bearer ${authToken}` } }
        );
        console.log('✅ Call Ended:', endResponse.data);
        console.log(`⏱️  Duration: ${endResponse.data.duration} seconds`);
        console.log('');

        // 6. Get Call History
        console.log('6️⃣ Testing Get Call History...');
        const historyResponse = await axios.get(
            `${BASE_URL}/api/calls/history`,
            { headers: { Authorization: `Bearer ${authToken}` } }
        );
        console.log('✅ Call History:', historyResponse.data);
        console.log(`📊 Total calls: ${historyResponse.data.calls.length}`);
        console.log('');

        console.log('🎉 ALL CALL APIs WORKING! ✅');
        console.log('');
        console.log('📊 Summary:');
        console.log(`- Call ID: ${callId}`);
        console.log(`- Call Duration: ${endResponse.data.duration} seconds`);
        console.log(`- Total Calls in History: ${historyResponse.data.calls.length}`);
        console.log('');
        console.log('✅ Video call backend is ready!');

    } catch (error) {
        console.error('❌ Test Failed:', error.response?.data || error.message);
        console.error('Status:', error.response?.status);
    }
}

testCallAPIs();
