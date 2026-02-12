const axios = require('axios');

const BASE_URL = 'http://localhost:3000';
let authToken = '';
let userId = '';
let postId = '';
let chatId = '';

console.log('🧪 Testing INFLIQ MVP APIs...\n');

async function runTests() {
    try {
        // 1. Health Check
        console.log('1️⃣ Testing Health Check...');
        const health = await axios.get(`${BASE_URL}/health`);
        console.log('✅ Health:', health.data);
        console.log('');

        // 2. Send OTP
        console.log('2️⃣ Testing Send OTP...');
        const otpResponse = await axios.post(`${BASE_URL}/api/auth/send-otp`, {
            phone: '+1234567890'
        });
        console.log('✅ OTP Response:', otpResponse.data);
        const testOTP = otpResponse.data.testOTP;
        console.log(`📱 Test OTP: ${testOTP}`);
        console.log('');

        // 3. Verify OTP
        console.log('3️⃣ Testing Verify OTP...');
        const verifyResponse = await axios.post(`${BASE_URL}/api/auth/verify-otp`, {
            phone: '+1234567890',
            otp: testOTP
        });
        console.log('✅ Verify Response:', verifyResponse.data);
        authToken = verifyResponse.data.token;
        userId = verifyResponse.data.user._id;
        console.log(`🔑 Auth Token: ${authToken.substring(0, 20)}...`);
        console.log(`👤 User ID: ${userId}`);
        console.log('');

        // 4. Update User Profile
        console.log('4️⃣ Testing Update User Profile...');
        const updateResponse = await axios.put(
            `${BASE_URL}/api/users/${userId}`,
            {
                name: 'Test User',
                age: 25,
                bio: 'Testing INFLIQ MVP',
                category: 'tech'
            },
            {
                headers: { Authorization: `Bearer ${authToken}` }
            }
        );
        console.log('✅ Updated User:', updateResponse.data);
        console.log('');

        // 5. Get User Profile
        console.log('5️⃣ Testing Get User Profile...');
        const userResponse = await axios.get(`${BASE_URL}/api/users/${userId}`, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        console.log('✅ User Profile:', userResponse.data);
        console.log('');

        // 6. Create Post
        console.log('6️⃣ Testing Create Post...');
        const postResponse = await axios.post(
            `${BASE_URL}/api/posts`,
            {
                type: 'post',
                content: 'This is my first test post on INFLIQ! 🚀',
                mediaType: 'image'
            },
            {
                headers: { Authorization: `Bearer ${authToken}` }
            }
        );
        console.log('✅ Created Post:', postResponse.data);
        postId = postResponse.data._id;
        console.log(`📝 Post ID: ${postId}`);
        console.log('');

        // 7. Like Post
        console.log('7️⃣ Testing Like Post...');
        const likeResponse = await axios.post(
            `${BASE_URL}/api/posts/${postId}/like`,
            {},
            {
                headers: { Authorization: `Bearer ${authToken}` }
            }
        );
        console.log('✅ Liked Post:', likeResponse.data);
        console.log('');

        // 8. Add Comment
        console.log('8️⃣ Testing Add Comment...');
        const commentResponse = await axios.post(
            `${BASE_URL}/api/posts/${postId}/comment`,
            {
                text: 'Great post! 👍'
            },
            {
                headers: { Authorization: `Bearer ${authToken}` }
            }
        );
        console.log('✅ Added Comment:', commentResponse.data);
        console.log('');

        // 9. Get Feed
        console.log('9️⃣ Testing Get Feed...');
        const feedResponse = await axios.get(`${BASE_URL}/api/posts/feed`, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        console.log('✅ Feed:', feedResponse.data);
        console.log(`📰 Total posts in feed: ${feedResponse.data.posts.length}`);
        console.log('');

        // 10. Get Nearby Users
        console.log('🔟 Testing Get Nearby Users...');
        const nearbyResponse = await axios.get(
            `${BASE_URL}/api/users/nearby?lat=28.6139&lng=77.2090&category=tech`,
            {
                headers: { Authorization: `Bearer ${authToken}` }
            }
        );
        console.log('✅ Nearby Users:', nearbyResponse.data);
        console.log('');

        // 11. Create Chat
        console.log('1️⃣1️⃣ Testing Create Chat...');
        const chatResponse = await axios.post(
            `${BASE_URL}/api/chats`,
            {
                type: 'chat',
                participants: []
            },
            {
                headers: { Authorization: `Bearer ${authToken}` }
            }
        );
        console.log('✅ Created Chat:', chatResponse.data);
        chatId = chatResponse.data._id;
        console.log(`💬 Chat ID: ${chatId}`);
        console.log('');

        // 12. Get Chats
        console.log('1️⃣2️⃣ Testing Get Chats...');
        const chatsResponse = await axios.get(`${BASE_URL}/api/chats`, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        console.log('✅ Chats:', chatsResponse.data);
        console.log(`💬 Total chats: ${chatsResponse.data.chats.length}`);
        console.log('');

        console.log('🎉 ALL TESTS PASSED! ✅');
        console.log('');
        console.log('📊 Summary:');
        console.log(`- User ID: ${userId}`);
        console.log(`- Auth Token: ${authToken.substring(0, 30)}...`);
        console.log(`- Post ID: ${postId}`);
        console.log(`- Chat ID: ${chatId}`);
        console.log('');
        console.log('✅ All APIs are working correctly!');

    } catch (error) {
        console.error('❌ Test Failed:', error.response?.data || error.message);
        console.error('Status:', error.response?.status);
    }
}

runTests();
