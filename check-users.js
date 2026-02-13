const mongoose = require('mongoose');
require('dotenv').config();

const userSchema = new mongoose.Schema({ name: String, phone: String });
const User = mongoose.model('User', userSchema);

async function checkUsers() {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('✅ Connected to MongoDB');

        const users = await User.find({}, 'name phone');
        console.log('👥 Current Users:');
        users.forEach(u => console.log(`- ${u.name} (${u.phone}) [${u._id}]`));

        await mongoose.disconnect();
    } catch (err) {
        console.error('❌ Error:', err.message);
        process.exit(1);
    }
}

checkUsers();
