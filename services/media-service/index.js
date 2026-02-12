const express = require('express');
const AWS = require('aws-sdk');
const multer = require('multer');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config({ path: '../../.env' });

const app = express();
const PORT = process.env.MEDIA_SERVICE_URL?.split(':')[2] || 3008;

// Middleware
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(',') }));
app.use(express.json());

// Configure AWS S3
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION
});

// Configure Multer for memory storage
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: parseInt(process.env.MAX_FILE_SIZE) || 52428800 // 50MB
    },
    fileFilter: (req, file, cb) => {
        // Allow images and videos
        const allowedMimes = [
            'image/jpeg',
            'image/png',
            'image/jpg',
            'image/gif',
            'video/mp4',
            'video/quicktime',
            'video/x-msvideo'
        ];

        if (allowedMimes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only images and videos allowed.'));
        }
    }
});

// Auth Middleware
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Routes

// Upload file to S3
app.post('/api/media/upload', authMiddleware, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file provided' });
        }

        const { folder = 'general' } = req.body; // posts, profiles, covers, reels

        // Generate unique filename
        const timestamp = Date.now();
        const filename = `${folder}/${req.userId}/${timestamp}-${req.file.originalname}`;

        // Upload to S3
        const params = {
            Bucket: process.env.S3_BUCKET,
            Key: filename,
            Body: req.file.buffer,
            ContentType: req.file.mimetype,
            ACL: 'public-read'
        };

        const result = await s3.upload(params).promise();

        res.json({
            success: true,
            url: result.Location,
            key: result.Key,
            bucket: result.Bucket
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Upload failed', details: error.message });
    }
});

// Upload multiple files
app.post('/api/media/upload-multiple', authMiddleware, upload.array('files', 10), async (req, res) => {
    try {
        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ error: 'No files provided' });
        }

        const { folder = 'general' } = req.body;

        const uploadPromises = req.files.map(async (file) => {
            const timestamp = Date.now();
            const filename = `${folder}/${req.userId}/${timestamp}-${file.originalname}`;

            const params = {
                Bucket: process.env.S3_BUCKET,
                Key: filename,
                Body: file.buffer,
                ContentType: file.mimetype,
                ACL: 'public-read'
            };

            return s3.upload(params).promise();
        });

        const results = await Promise.all(uploadPromises);

        const urls = results.map(result => ({
            url: result.Location,
            key: result.Key
        }));

        res.json({ success: true, files: urls });
    } catch (error) {
        console.error('Multiple upload error:', error);
        res.status(500).json({ error: 'Upload failed', details: error.message });
    }
});

// Delete file from S3
app.delete('/api/media/:key(*)', authMiddleware, async (req, res) => {
    try {
        const key = req.params.key;

        const params = {
            Bucket: process.env.S3_BUCKET,
            Key: key
        };

        await s3.deleteObject(params).promise();

        res.json({ success: true, message: 'File deleted successfully' });
    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ error: 'Delete failed', details: error.message });
    }
});

// Get signed URL for private files
app.get('/api/media/signed-url/:key(*)', authMiddleware, async (req, res) => {
    try {
        const key = req.params.key;
        const { expires = 3600 } = req.query; // Default 1 hour

        const params = {
            Bucket: process.env.S3_BUCKET,
            Key: key,
            Expires: parseInt(expires)
        };

        const url = s3.getSignedUrl('getObject', params);

        res.json({ success: true, url });
    } catch (error) {
        console.error('Signed URL error:', error);
        res.status(500).json({ error: 'Failed to generate signed URL' });
    }
});

// List files for user
app.get('/api/media/list', authMiddleware, async (req, res) => {
    try {
        const { folder = '' } = req.query;
        const prefix = folder ? `${folder}/${req.userId}/` : `${req.userId}/`;

        const params = {
            Bucket: process.env.S3_BUCKET,
            Prefix: prefix
        };

        const data = await s3.listObjectsV2(params).promise();

        const files = data.Contents.map(item => ({
            key: item.Key,
            size: item.Size,
            lastModified: item.LastModified,
            url: `https://${process.env.S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${item.Key}`
        }));

        res.json({ success: true, files });
    } catch (error) {
        console.error('List files error:', error);
        res.status(500).json({ error: 'Failed to list files' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', service: 'media-service' });
});

app.listen(PORT, () => {
    console.log(`🚀 Media Service running on port ${PORT}`);
});
