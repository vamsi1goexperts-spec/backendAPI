require('dotenv').config();
const twilio = require('twilio');
const AccessToken = twilio.jwt.AccessToken;
const VideoGrant = AccessToken.VideoGrant;

const testTokenGeneration = () => {
    try {
        const accountSid = process.env.TWILIO_ACCOUNT_SID;
        const authToken = process.env.TWILIO_AUTH_TOKEN;

        // Fallback logic from server.js
        const apiKeySid = process.env.TWILIO_API_KEY_SID || accountSid;
        const apiKeySecret = process.env.TWILIO_API_KEY_SECRET || authToken;

        console.log('Testing Token Generation with:');
        console.log('Account SID:', accountSid ? 'Present' : 'Missing');
        console.log('API Key SID:', apiKeySid ? (apiKeySid === accountSid ? 'Using Account SID' : 'Using API Key') : 'Missing');
        console.log('API Key Secret:', apiKeySecret ? (apiKeySecret === authToken ? 'Using Auth Token' : 'Using Secret') : 'Missing');

        const identity = 'test-user-123';
        const roomName = 'test-room';

        const token = new AccessToken(
            accountSid,
            apiKeySid,
            apiKeySecret,
            {
                identity: identity,
                ttl: 3600
            }
        );

        const videoGrant = new VideoGrant({
            room: roomName
        });
        token.addGrant(videoGrant);

        const jwt = token.toJwt();
        console.log('\n✅ Token generated successfully!');
        console.log('Token:', jwt.substring(0, 20) + '...');
        return jwt;

    } catch (error) {
        console.error('\n❌ Token generation failed:', error.message);
        if (error.code) console.error('Error Code:', error.code);
    }
};

testTokenGeneration();
