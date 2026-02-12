const twilio = require('twilio');
const AWS = require('aws-sdk');
require('dotenv').config();

console.log('🧪 Testing Twilio and AWS S3 Credentials...\n');

// Test 1: Twilio
async function testTwilio() {
    console.log('1️⃣ Testing Twilio SMS...');
    console.log(`Account SID: ${process.env.TWILIO_ACCOUNT_SID}`);
    console.log(`Phone Number: ${process.env.TWILIO_PHONE_NUMBER}`);

    try {
        const client = twilio(
            process.env.TWILIO_ACCOUNT_SID,
            process.env.TWILIO_AUTH_TOKEN
        );

        // Try to fetch account info (doesn't send SMS, just verifies credentials)
        const account = await client.api.accounts(process.env.TWILIO_ACCOUNT_SID).fetch();
        console.log('✅ Twilio credentials are VALID!');
        console.log(`   Account Status: ${account.status}`);
        console.log(`   Account Name: ${account.friendlyName}`);

        // Optional: Uncomment to send a real test SMS
        /*
        const message = await client.messages.create({
          body: 'Test message from INFLIQ MVP',
          from: process.env.TWILIO_PHONE_NUMBER,
          to: '+YOUR_PHONE_NUMBER_HERE'  // Replace with your phone
        });
        console.log(`   Test SMS sent! SID: ${message.sid}`);
        */

        return true;
    } catch (error) {
        console.error('❌ Twilio credentials FAILED!');
        console.error(`   Error: ${error.message}`);
        console.error(`   Code: ${error.code}`);
        return false;
    }
}

// Test 2: AWS S3
async function testS3() {
    console.log('\n2️⃣ Testing AWS S3...');
    console.log(`Access Key: ${process.env.AWS_ACCESS_KEY_ID?.substring(0, 10)}...`);
    console.log(`Region: ${process.env.AWS_REGION}`);
    console.log(`Bucket: ${process.env.S3_BUCKET}`);

    try {
        const s3 = new AWS.S3({
            accessKeyId: process.env.AWS_ACCESS_KEY_ID,
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
            region: process.env.AWS_REGION
        });

        // Test 1: List buckets (verifies credentials)
        const buckets = await s3.listBuckets().promise();
        console.log('✅ AWS credentials are VALID!');
        console.log(`   Total buckets: ${buckets.Buckets.length}`);

        // Test 2: Check if our bucket exists
        const bucketExists = buckets.Buckets.some(b => b.Name === process.env.S3_BUCKET);
        if (bucketExists) {
            console.log(`✅ Bucket '${process.env.S3_BUCKET}' EXISTS!`);
        } else {
            console.log(`⚠️  Bucket '${process.env.S3_BUCKET}' NOT FOUND`);
            console.log(`   Available buckets: ${buckets.Buckets.map(b => b.Name).join(', ')}`);
        }

        // Test 3: Try to upload a test file
        if (bucketExists) {
            const testContent = 'INFLIQ MVP Test File - ' + new Date().toISOString();
            const params = {
                Bucket: process.env.S3_BUCKET,
                Key: 'test-upload-' + Date.now() + '.txt',
                Body: testContent,
                ContentType: 'text/plain',
                ACL: 'public-read'
            };

            const result = await s3.upload(params).promise();
            console.log('✅ Test file uploaded successfully!');
            console.log(`   URL: ${result.Location}`);

            // Clean up - delete test file
            await s3.deleteObject({ Bucket: process.env.S3_BUCKET, Key: params.Key }).promise();
            console.log('✅ Test file deleted (cleanup)');
        }

        return true;
    } catch (error) {
        console.error('❌ AWS S3 credentials FAILED!');
        console.error(`   Error: ${error.message}`);
        console.error(`   Code: ${error.code}`);
        return false;
    }
}

// Run tests
async function runTests() {
    const twilioOk = await testTwilio();
    const s3Ok = await testS3();

    console.log('\n' + '='.repeat(50));
    console.log('📊 RESULTS:');
    console.log('='.repeat(50));
    console.log(`Twilio: ${twilioOk ? '✅ WORKING' : '❌ FAILED'}`);
    console.log(`AWS S3: ${s3Ok ? '✅ WORKING' : '❌ FAILED'}`);
    console.log('='.repeat(50));

    if (twilioOk && s3Ok) {
        console.log('\n🎉 All credentials are working! You\'re ready to deploy!');
    } else {
        console.log('\n⚠️  Some credentials need attention. Check the errors above.');
    }
}

runTests();
