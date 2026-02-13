const mongoose = require('mongoose');
require('dotenv').config();

const chatSchema = new mongoose.Schema({
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    type: { type: String, enum: ['direct', 'group'], default: 'direct' },
    messages: [{
        senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        text: String,
        createdAt: { type: Date, default: Date.now },
        read: { type: Boolean, default: false }
    }],
    lastMessage: String,
    lastMessageAt: Date,
    createdAt: { type: Date, default: Date.now }
});
const Chat = mongoose.model('Chat', chatSchema);

async function seedChat() {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('✅ Connected to MongoDB');

        const vamsiId = '698dd1b79627ee84871265e2';
        const testUserId = '698db1c1c5537aae88e44fea';

        // Remove existing chat if any (to avoid duplicates during repeat testing)
        await Chat.deleteMany({
            participants: { $all: [vamsiId, testUserId] }
        });

        const newChat = new Chat({
            participants: [vamsiId, testUserId],
            type: 'direct',
            messages: [
                {
                    senderId: testUserId,
                    text: 'Hey Vamsi! How is the app development going?',
                    createdAt: new Date(Date.now() - 3600000) // 1 hour ago
                },
                {
                    senderId: vamsiId,
                    text: 'It is going great! Just testing the dynamic chat feature.',
                    createdAt: new Date(Date.now() - 3000000) // 50 mins ago
                },
                {
                    senderId: testUserId,
                    text: 'Awesome. Can we test the video call feature too?',
                    createdAt: new Date(Date.now() - 2400000) // 40 mins ago
                }
            ],
            lastMessage: 'Awesome. Can we test the video call feature too?',
            lastMessageAt: new Date(Date.now() - 2400000)
        });

        await newChat.save();
        console.log('✅ Test chat seeded successfully between Vamsi Reddy and Test User!');

        await mongoose.disconnect();
    } catch (err) {
        console.error('❌ Error:', err.message);
        process.exit(1);
    }
}

seedChat();
