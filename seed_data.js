const mongoose = require('mongoose');
require('dotenv').config();

// --- Schemas ---

const userSchema = new mongoose.Schema({
    phone: { type: String, unique: true, sparse: true },
    email: { type: String, unique: true, sparse: true },
    password: String,
    name: String,
    age: Number,
    bio: String,
    profilePicture: String,
    location: {
        type: { type: String, enum: ['Point'], default: 'Point' },
        coordinates: { type: [Number], default: [0, 0] }
    },
    category: { type: String, default: 'global' },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const postSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['post', 'reel'], default: 'post' },
    content: String,
    mediaUrl: String,
    mediaType: { type: String, enum: ['image', 'video'] },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    comments: [],
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', postSchema);

// --- Local Data Generators ---

const firstNames = ['James', 'Mary', 'John', 'Patricia', 'Robert', 'Jennifer', 'Michael', 'Linda', 'William', 'Elizabeth', 'David', 'Barbara', 'Richard', 'Susan', 'Joseph', 'Jessica', 'Thomas', 'Sarah', 'Charles', 'Karen', 'Christopher', 'Nancy', 'Daniel', 'Lisa', 'Matthew', 'Betty', 'Anthony', 'Margaret', 'Mark', 'Sandra'];
const lastNames = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Rodriguez', 'Martinez', 'Hernandez', 'Lopez', 'Gonzalez', 'Wilson', 'Anderson', 'Thomas', 'Taylor', 'Moore', 'Jackson', 'Martin', 'Lee', 'Perez', 'Thompson', 'White', 'Harris', 'Sanchez', 'Clark', 'Ramirez', 'Lewis', 'Robinson'];
const cities = ['New York', 'London', 'Mumbai', 'Sydney', 'Tokyo', 'Paris', 'Berlin', 'Toronto', 'Dubai', 'Singapore'];

const getRandomElement = (arr) => arr[Math.floor(Math.random() * arr.length)];
const getRandomInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

const seedData = async () => {
    try {
        console.log('🌱 Connecting to MongoDB...');
        await mongoose.connect(process.env.MONGO_URI);
        console.log('✅ Connected.');

        const createdUsers = [];

        console.log('🔨 Generating 30 users locally...');

        for (let i = 0; i < 30; i++) {
            const firstName = getRandomElement(firstNames);
            const lastName = getRandomElement(lastNames);
            const name = `${firstName} ${lastName}`;
            const email = `${firstName.toLowerCase()}.${lastName.toLowerCase()}${i}@example.com`;
            const phone = `+91${getRandomInt(7000000000, 9999999999)}`;

            // Random Unsplash User Image
            const gender = i % 2 === 0 ? 'men' : 'women';
            const profilePicture = `https://randomuser.me/api/portraits/${gender}/${i % 99}.jpg`;

            const newUser = new User({
                name,
                email,
                phone,
                password: '$2a$10$abcdefghijklmnopqrstuvwxyz',
                age: getRandomInt(18, 50),
                bio: `Hi, I'm ${name} from ${getRandomElement(cities)}!`,
                profilePicture,
                location: {
                    type: 'Point',
                    coordinates: [getRandomInt(-180, 180), getRandomInt(-90, 90)]
                },
                category: 'global',
                createdAt: new Date()
            });
            createdUsers.push(newUser);
        }

        // Save users
        const savedUsers = await User.insertMany(createdUsers);
        console.log(`✅ Inserted ${savedUsers.length} users into database.`);

        // Create 3 Posts for each User
        const postsToInsert = [];
        const captions = ['Beautiful day!', 'Explored this place today.', 'Feeling great.', 'Work mode on.', 'Nature is amazing.', 'Weekend vibes.', 'Coffee time.', 'My latest click.', 'Tech life.', 'Sunset lover.'];

        for (const user of savedUsers) {
            for (let i = 0; i < 3; i++) {
                const randomId = Math.floor(Math.random() * 1000);

                postsToInsert.push({
                    userId: user._id,
                    type: 'post',
                    content: getRandomElement(captions),
                    mediaUrl: `https://picsum.photos/id/${getRandomInt(1, 500)}/800/800`,
                    mediaType: 'image',
                    likes: [],
                    comments: [],
                    createdAt: new Date(Date.now() - getRandomInt(0, 1000000000))
                });
            }
        }

        await Post.insertMany(postsToInsert);
        console.log(`✅ Inserted ${postsToInsert.length} posts into database.`);

        console.log('🎉 Seeding complete!');
        process.exit(0);

    } catch (error) {
        console.error('❌ Seeding failed:', error);
        process.exit(1);
    }
};

seedData();
