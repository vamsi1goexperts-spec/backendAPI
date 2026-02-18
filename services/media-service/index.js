const express = require('express');
const AWS = require('aws-sdk');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { createClient } = require('redis');
const ffmpeg = require('fluent-ffmpeg');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { requiredInProduction, isProduction, strictProductionMode } = require('../_shared/config');
const { applyCommonSecurity } = require('../_shared/security');
const { applyRequestContext } = require('../_shared/observability');
const { sendError, ErrorCodes } = require('../_shared/http');
const sharp = require('sharp');

const app = express();
const PORT = process.env.MEDIA_SERVICE_URL?.split(':')[2] || 3008;
const AWS_REGION_PATTERN = /^(?:us|eu|ap|sa|ca|me|af|cn|us-gov|il)-[a-z0-9-]+-\d$/;
const DEFAULT_ALLOWED_FOLDERS = ['general', 'posts', 'profiles', 'covers', 'reels', 'stories'];
const ALLOWED_FOLDERS = (process.env.MEDIA_ALLOWED_FOLDERS || DEFAULT_ALLOWED_FOLDERS.join(','))
    .split(',')
    .map((f) => f.trim().toLowerCase())
    .filter(Boolean);
const MAX_MULTIPLE_UPLOAD_FILES = parseInt(process.env.MAX_MULTIPLE_UPLOAD_FILES || '10', 10);
const SIGNED_URL_EXPIRES_MIN = parseInt(process.env.SIGNED_URL_EXPIRES_MIN || '60', 10);
const SIGNED_URL_EXPIRES_MAX = parseInt(process.env.SIGNED_URL_EXPIRES_MAX || '3600', 10);
const USER_UPLOAD_WINDOW_MS = parseInt(process.env.USER_UPLOAD_WINDOW_MS || '60000', 10);
const USER_UPLOAD_MAX_IN_WINDOW = parseInt(process.env.USER_UPLOAD_MAX_IN_WINDOW || '30', 10);
const MEDIA_STRICT_SIGNATURE_CHECK = (process.env.MEDIA_STRICT_SIGNATURE_CHECK || 'true').toLowerCase() === 'true';
const MEDIA_AUDIT_LOG_ENABLED = (process.env.MEDIA_AUDIT_LOG_ENABLED || 'true').toLowerCase() === 'true';
const MEDIA_AUDIT_LOG_RETENTION_DAYS = parseInt(process.env.MEDIA_AUDIT_LOG_RETENTION_DAYS || '30', 10);
const MEDIA_AUDIT_READ_MAX_LIMIT = parseInt(process.env.MEDIA_AUDIT_READ_MAX_LIMIT || '100', 10);
const MEDIA_ADMIN_USER_IDS = (process.env.MEDIA_ADMIN_USER_IDS || '')
    .split(',')
    .map((id) => id.trim())
    .filter(Boolean);
const redisUrl = process.env.REDIS_URL || '';
const MEDIA_RATE_LIMIT_PREFIX = process.env.MEDIA_RATE_LIMIT_PREFIX || 'media:rate';
const CLOUDFRONT_DOMAIN = process.env.CLOUDFRONT_DOMAIN || null; // e.g. d123.cloudfront.net
const userUploadTimestamps = new Map();
let redisClient = null;
let redisReady = false;

const getValidatedAwsRegion = () => {
    const region = process.env.AWS_REGION?.trim();
    if (!region || !AWS_REGION_PATTERN.test(region)) {
        throw new Error(`Invalid AWS_REGION value: ${region || '(empty)'}`);
    }
    return region;
};

const awsRegion = getValidatedAwsRegion();
let MediaUploadAudit = null;

const logEvent = (level, event, meta = {}) => {
    const payload = {
        ts: new Date().toISOString(),
        service: 'media-service',
        level,
        event,
        ...meta
    };
    const line = JSON.stringify(payload);
    if (level === 'error') console.error(line);
    else console.log(line);
};

const initRedis = async () => {
    if (!redisUrl) {
        if (isProduction && strictProductionMode) {
            throw new Error('REDIS_URL is required in strict production mode');
        }
        return;
    }
    try {
        redisClient = createClient({ url: redisUrl });
        redisClient.on('error', (error) => {
            redisReady = false;
            logEvent('error', 'redis_error', { message: error.message });
        });
        redisClient.on('ready', () => {
            redisReady = true;
            logEvent('info', 'redis_connected');
        });
        await redisClient.connect();
    } catch (error) {
        redisReady = false;
        redisClient = null;
        if (isProduction && strictProductionMode) {
            throw new Error(`Redis unavailable in strict production mode: ${error.message}`);
        }
        logEvent('warn', 'redis_unavailable_fallback', { message: error.message });
    }
};

const normalizeUserIdFromToken = (decoded) => (decoded?.userId || decoded?._id || '').toString();

const sanitizeFilename = (name) => {
    const input = (name || 'upload').toString();
    const dot = input.lastIndexOf('.');
    const rawBase = dot > 0 ? input.slice(0, dot) : input;
    const rawExt = dot > 0 ? input.slice(dot + 1) : '';
    const safeBase = rawBase
        .replace(/[^a-zA-Z0-9-_]/g, '_')
        .replace(/_+/g, '_')
        .slice(0, 80) || 'file';
    const safeExt = rawExt
        .toLowerCase()
        .replace(/[^a-z0-9]/g, '')
        .slice(0, 10);
    return safeExt ? `${safeBase}.${safeExt}` : safeBase;
};

const MIME_TO_EXTENSION = {
    'image/jpeg': 'jpg',
    'image/jpg': 'jpg',
    'image/png': 'png',
    'image/gif': 'gif',
    'video/mp4': 'mp4',
    'video/quicktime': 'mov',
    'video/x-msvideo': 'avi'
};

const detectBufferKind = (buffer) => {
    if (!buffer || buffer.length < 12) return null;

    // JPEG: FF D8 FF
    if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
        return 'image/jpeg';
    }
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if (
        buffer[0] === 0x89 &&
        buffer[1] === 0x50 &&
        buffer[2] === 0x4e &&
        buffer[3] === 0x47 &&
        buffer[4] === 0x0d &&
        buffer[5] === 0x0a &&
        buffer[6] === 0x1a &&
        buffer[7] === 0x0a
    ) {
        return 'image/png';
    }
    // GIF: GIF87a / GIF89a
    if (
        buffer[0] === 0x47 &&
        buffer[1] === 0x49 &&
        buffer[2] === 0x46 &&
        buffer[3] === 0x38 &&
        (buffer[4] === 0x37 || buffer[4] === 0x39) &&
        buffer[5] === 0x61
    ) {
        return 'image/gif';
    }
    // MP4/MOV family: ....ftyp....
    if (
        buffer[4] === 0x66 &&
        buffer[5] === 0x74 &&
        buffer[6] === 0x79 &&
        buffer[7] === 0x70
    ) {
        const brand = buffer.toString('ascii', 8, 12).toLowerCase();
        if (['qt  ', 'moov'].includes(brand)) return 'video/quicktime';
        return 'video/mp4';
    }
    // AVI: RIFF....AVI 
    if (
        buffer[0] === 0x52 &&
        buffer[1] === 0x49 &&
        buffer[2] === 0x46 &&
        buffer[3] === 0x46 &&
        buffer[8] === 0x41 &&
        buffer[9] === 0x56 &&
        buffer[10] === 0x49
    ) {
        return 'video/x-msvideo';
    }

    return null;
};

const validateFileIntegrity = (file) => {
    const expectedExt = MIME_TO_EXTENSION[file.mimetype];
    if (!expectedExt) {
        return { ok: false, error: 'Unsupported file MIME type' };
    }

    if (MEDIA_STRICT_SIGNATURE_CHECK) {
        const detected = detectBufferKind(file.buffer);
        if (!detected || detected !== file.mimetype) {
            return { ok: false, error: 'File content does not match declared MIME type' };
        }
    }

    return { ok: true, expectedExt };
};

const resolveAllowedFolder = (folder) => {
    const normalized = (folder || 'general').toString().trim().toLowerCase();
    return ALLOWED_FOLDERS.includes(normalized) ? normalized : null;
};

const optimizeImage = async (buffer) => {
    try {
        return await sharp(buffer)
            .resize(1200, 1200, {
                fit: 'inside',
                withoutEnlargement: true
            })
            .jpeg({ quality: 80, progressive: true })
            .toBuffer();
    } catch (error) {
        console.error('Image optimization error:', error);
        return buffer; // Fallback to raw buffer
    }
};

const canAccessUserKey = (key, userId) => {
    if (!key || !userId) return false;
    const normalizedKey = key.toString().replace(/^\/+/, '');
    return ALLOWED_FOLDERS.some((folder) => normalizedKey.startsWith(`${folder}/${userId}/`));
};

const enforcePerUserUploadRate = async (userId) => {
    if (redisReady && redisClient) {
        const nowBucket = Math.floor(Date.now() / USER_UPLOAD_WINDOW_MS);
        const key = `${MEDIA_RATE_LIMIT_PREFIX}:${userId}:${nowBucket}`;
        const count = await redisClient.incr(key);
        if (count === 1) {
            await redisClient.expire(key, Math.max(1, Math.ceil(USER_UPLOAD_WINDOW_MS / 1000)));
        }
        return count <= USER_UPLOAD_MAX_IN_WINDOW;
    }
    const now = Date.now();
    const existing = userUploadTimestamps.get(userId) || [];
    const recent = existing.filter((ts) => now - ts <= USER_UPLOAD_WINDOW_MS);
    if (recent.length >= USER_UPLOAD_MAX_IN_WINDOW) {
        return false;
    }
    recent.push(now);
    userUploadTimestamps.set(userId, recent);
    return true;
};

const getRequestIp = (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.length > 0) {
        return forwarded.split(',')[0].trim();
    }
    return req.ip || req.socket?.remoteAddress || 'unknown';
};

const maskIp = (ip) => {
    if (!ip || ip === 'unknown') return 'unknown';
    const v4 = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (v4) return `${v4[1]}.${v4[2]}.x.x`;
    const chunks = ip.split(':');
    if (chunks.length > 2) return `${chunks.slice(0, 2).join(':')}::xxxx`;
    return 'masked';
};

const redactAuditRecord = (doc) => ({
    id: doc._id,
    userId: doc.userId,
    ip: maskIp(doc.ip),
    route: doc.route,
    action: doc.action,
    status: doc.status,
    mimeType: doc.mimeType,
    size: doc.size,
    folder: doc.folder,
    key: doc.key || null,
    error: doc.error || null,
    metadata: doc.metadata || null,
    createdAt: doc.createdAt
});

const ensureAuditModel = async () => {
    if (!MEDIA_AUDIT_LOG_ENABLED || MediaUploadAudit || !process.env.MONGO_URI) return;
    try {
        if (mongoose.connection.readyState === 0) {
            await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 5000 });
        }
        const schema = new mongoose.Schema({
            userId: { type: String, index: true },
            ip: String,
            route: String,
            action: String,
            status: { type: String, enum: ['success', 'error', 'rejected'], default: 'success' },
            mimeType: String,
            size: Number,
            folder: String,
            key: String,
            error: String,
            metadata: mongoose.Schema.Types.Mixed,
            createdAt: { type: Date, default: Date.now },
            expiresAt: { type: Date, index: true }
        }, { versionKey: false });
        schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
        MediaUploadAudit = mongoose.models.MediaUploadAudit || mongoose.model('MediaUploadAudit', schema);
    } catch (error) {
        console.warn('⚠️ Media audit logging disabled for this run:', error.message);
    }
};

const writeAuditLog = async (entry) => {
    if (!MEDIA_AUDIT_LOG_ENABLED) return;
    await ensureAuditModel();
    if (!MediaUploadAudit) return;
    const retentionMs = Math.max(1, MEDIA_AUDIT_LOG_RETENTION_DAYS) * 24 * 60 * 60 * 1000;
    try {
        await MediaUploadAudit.create({
            ...entry,
            expiresAt: new Date(Date.now() + retentionMs)
        });
    } catch (error) {
        console.warn('⚠️ Failed to write media audit log:', error.message);
    }
};

const isAdminRequest = (req) => {
    const payload = req.authPayload || {};
    const tokenAdmin = payload.admin === true || payload.role === 'admin';
    const envAdmin = MEDIA_ADMIN_USER_IDS.includes(req.userId);
    return tokenAdmin || envAdmin;
};

setInterval(() => {
    if (redisReady) return;
    const now = Date.now();
    for (const [userId, timestamps] of userUploadTimestamps.entries()) {
        const recent = timestamps.filter((ts) => now - ts <= USER_UPLOAD_WINDOW_MS);
        if (recent.length === 0) userUploadTimestamps.delete(userId);
        else userUploadTimestamps.set(userId, recent);
    }
}, Math.max(30000, USER_UPLOAD_WINDOW_MS)).unref();

// Middleware
requiredInProduction(['JWT_SECRET', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_REGION', 'S3_BUCKET', 'REDIS_URL']);
applyRequestContext(app);
applyCommonSecurity(app);
app.use(express.json());

// Configure AWS S3
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: awsRegion
});
initRedis().catch((error) => {
    logEvent('error', 'startup_dependency_error', { message: error.message });
    process.exit(1);
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
        return sendError(res, 401, ErrorCodes.UNAUTHORIZED, 'No token provided');
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.authPayload = decoded;
        req.userId = normalizeUserIdFromToken(decoded);
        if (!req.userId) {
            return sendError(res, 401, ErrorCodes.INVALID_TOKEN, 'Invalid token payload');
        }
        next();
    } catch (error) {
        return sendError(res, 401, ErrorCodes.INVALID_TOKEN, 'Invalid token');
    }
};

// Routes

// Upload file to S3
app.post('/api/media/upload', authMiddleware, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            await writeAuditLog({
                userId: req.userId,
                ip: getRequestIp(req),
                route: req.originalUrl,
                action: 'upload-single',
                status: 'rejected',
                error: 'No file provided'
            });
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'No file provided');
        }
        const integrity = validateFileIntegrity(req.file);
        if (!integrity.ok) {
            await writeAuditLog({
                userId: req.userId,
                ip: getRequestIp(req),
                route: req.originalUrl,
                action: 'upload-single',
                status: 'rejected',
                mimeType: req.file.mimetype,
                size: req.file.size,
                error: integrity.error
            });
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, integrity.error);
        }
        if (!(await enforcePerUserUploadRate(req.userId))) {
            await writeAuditLog({
                userId: req.userId,
                ip: getRequestIp(req),
                route: req.originalUrl,
                action: 'upload-single',
                status: 'rejected',
                mimeType: req.file.mimetype,
                size: req.file.size,
                error: 'Rate limit exceeded'
            });
            return sendError(res, 429, 'MEDIA_RATE_LIMIT', 'Upload rate limit exceeded. Please try again later.');
        }

        const requestedFolder = req.body?.folder || 'general';
        const folder = resolveAllowedFolder(requestedFolder);
        if (!folder) {
            await writeAuditLog({
                userId: req.userId,
                ip: getRequestIp(req),
                route: req.originalUrl,
                action: 'upload-single',
                status: 'rejected',
                mimeType: req.file.mimetype,
                size: req.file.size,
                error: 'Invalid folder'
            });
            return sendError(res, 400, 'MEDIA_INVALID_FOLDER', `Invalid folder. Allowed: ${ALLOWED_FOLDERS.join(', ')}`);
        }
        const baseName = sanitizeFilename(req.file.originalname).replace(/\.[^.]+$/, '');
        const safeName = `${baseName}.${integrity.expectedExt}`;

        // Generate unique filename
        const timestamp = Date.now();
        const filename = `${folder}/${req.userId}/${timestamp}-${safeName}`;

        let finalBuffer = req.file.buffer;
        let finalMimeType = req.file.mimetype;

        // Image Optimization
        if (req.file.mimetype.startsWith('image/') && req.file.mimetype !== 'image/gif') {
            logEvent('info', 'optimizing_image', { originalSize: req.file.size });
            finalBuffer = await optimizeImage(req.file.buffer);
            logEvent('info', 'image_optimized', { newSize: finalBuffer.length });
        }

        let thumbnailUrl = null;

        // If video, generate thumbnail
        if (req.file.mimetype.startsWith('video/')) {
            try {
                const tempDir = os.tmpdir();
                const videoPath = path.join(tempDir, `video-${timestamp}.${integrity.expectedExt}`);
                const thumbName = `thumb-${timestamp}.jpg`;
                const thumbPath = path.join(tempDir, thumbName);

                // Write video buffer to temp file
                fs.writeFileSync(videoPath, req.file.buffer);

                // Extract frame
                await new Promise((resolve, reject) => {
                    ffmpeg(videoPath)
                        .screenshots({
                            timestamps: ['10%'],
                            filename: thumbName,
                            folder: tempDir,
                            size: '640x?'
                        })
                        .on('end', resolve)
                        .on('error', reject);
                });

                // Upload thumbnail to S3
                const thumbKey = `${folder}/${req.userId}/${timestamp}-thumb.jpg`;
                const thumbParams = {
                    Bucket: process.env.S3_BUCKET,
                    Key: thumbKey,
                    Body: fs.readFileSync(thumbPath),
                    ContentType: 'image/jpeg',
                    ACL: 'public-read'
                };
                const thumbResult = await s3.upload(thumbParams).promise();
                thumbnailUrl = CLOUDFRONT_DOMAIN
                    ? `https://${CLOUDFRONT_DOMAIN}/${thumbResult.Key}`
                    : thumbResult.Location;

                // Cleanup temp files
                fs.unlinkSync(videoPath);
                fs.unlinkSync(thumbPath);
            } catch (thumbError) {
                logEvent('warn', 'thumbnail_generation_failed', { error: thumbError.message });
            }
        }

        // Upload to S3
        const params = {
            Bucket: process.env.S3_BUCKET,
            Key: filename,
            Body: finalBuffer,
            ContentType: finalMimeType,
            ACL: 'public-read'
        };

        const result = await s3.upload(params).promise();
        const mediaUrl = CLOUDFRONT_DOMAIN
            ? `https://${CLOUDFRONT_DOMAIN}/${result.Key}`
            : result.Location;

        await writeAuditLog({
            userId: req.userId,
            ip: getRequestIp(req),
            route: req.originalUrl,
            action: 'upload-single',
            status: 'success',
            mimeType: req.file.mimetype,
            size: req.file.size,
            folder,
            key: result.Key
        });
        return res.json({
            success: true,
            url: mediaUrl,
            thumbnailUrl: thumbnailUrl,
            key: result.Key,
            bucket: result.Bucket
        });
    } catch (error) {
        logEvent('error', 'upload_single_error', { message: error.message, userId: req.userId });
        await writeAuditLog({
            userId: req.userId,
            ip: getRequestIp(req),
            route: req.originalUrl,
            action: 'upload-single',
            status: 'error',
            mimeType: req.file?.mimetype,
            size: req.file?.size,
            error: error.message
        });
        return sendError(res, 500, 'MEDIA_UPLOAD_FAILED', 'Upload failed', error.message);
    }
});

// Upload multiple files
app.post('/api/media/upload-multiple', authMiddleware, upload.array('files', MAX_MULTIPLE_UPLOAD_FILES), async (req, res) => {
    try {
        if (!req.files || req.files.length === 0) {
            await writeAuditLog({
                userId: req.userId,
                ip: getRequestIp(req),
                route: req.originalUrl,
                action: 'upload-multiple',
                status: 'rejected',
                error: 'No files provided'
            });
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, 'No files provided');
        }
        if (req.files.length > MAX_MULTIPLE_UPLOAD_FILES) {
            await writeAuditLog({
                userId: req.userId,
                ip: getRequestIp(req),
                route: req.originalUrl,
                action: 'upload-multiple',
                status: 'rejected',
                metadata: { filesCount: req.files.length },
                error: 'Too many files'
            });
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, `Too many files. Max ${MAX_MULTIPLE_UPLOAD_FILES} per request.`);
        }
        if (!(await enforcePerUserUploadRate(req.userId))) {
            await writeAuditLog({
                userId: req.userId,
                ip: getRequestIp(req),
                route: req.originalUrl,
                action: 'upload-multiple',
                status: 'rejected',
                metadata: { filesCount: req.files.length },
                error: 'Rate limit exceeded'
            });
            return sendError(res, 429, 'MEDIA_RATE_LIMIT', 'Upload rate limit exceeded. Please try again later.');
        }

        const requestedFolder = req.body?.folder || 'general';
        const folder = resolveAllowedFolder(requestedFolder);
        if (!folder) {
            await writeAuditLog({
                userId: req.userId,
                ip: getRequestIp(req),
                route: req.originalUrl,
                action: 'upload-multiple',
                status: 'rejected',
                metadata: { filesCount: req.files.length },
                error: 'Invalid folder'
            });
            return sendError(res, 400, 'MEDIA_INVALID_FOLDER', `Invalid folder. Allowed: ${ALLOWED_FOLDERS.join(', ')}`);
        }

        const invalidFile = req.files.find((file) => !validateFileIntegrity(file).ok);
        if (invalidFile) {
            await writeAuditLog({
                userId: req.userId,
                ip: getRequestIp(req),
                route: req.originalUrl,
                action: 'upload-multiple',
                status: 'rejected',
                mimeType: invalidFile.mimetype,
                size: invalidFile.size,
                metadata: { filesCount: req.files.length },
                error: `Invalid file "${invalidFile.originalname}"`
            });
            return sendError(res, 400, ErrorCodes.BAD_REQUEST, `Invalid file "${invalidFile.originalname}"`);
        }

        const uploadPromises = req.files.map(async (file) => {
            const integrity = validateFileIntegrity(file);
            const timestamp = Date.now();
            const baseName = sanitizeFilename(file.originalname).replace(/\.[^.]+$/, '');
            const safeName = `${baseName}.${integrity.expectedExt}`;
            const filename = `${folder}/${req.userId}/${timestamp}-${safeName}`;

            let finalBuffer = file.buffer;
            if (file.mimetype.startsWith('image/') && file.mimetype !== 'image/gif') {
                finalBuffer = await optimizeImage(file.buffer);
            }

            const params = {
                Bucket: process.env.S3_BUCKET,
                Key: filename,
                Body: finalBuffer,
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

        await writeAuditLog({
            userId: req.userId,
            ip: getRequestIp(req),
            route: req.originalUrl,
            action: 'upload-multiple',
            status: 'success',
            folder,
            metadata: {
                filesCount: req.files.length,
                keys: urls.map((f) => f.key)
            }
        });
        return res.json({ success: true, files: urls });
    } catch (error) {
        logEvent('error', 'upload_multiple_error', { message: error.message, userId: req.userId });
        await writeAuditLog({
            userId: req.userId,
            ip: getRequestIp(req),
            route: req.originalUrl,
            action: 'upload-multiple',
            status: 'error',
            metadata: { filesCount: req.files?.length || 0 },
            error: error.message
        });
        return sendError(res, 500, 'MEDIA_UPLOAD_FAILED', 'Upload failed', error.message);
    }
});

// Delete file from S3
app.delete('/api/media/:key(*)', authMiddleware, async (req, res) => {
    try {
        const key = (req.params.key || '').toString().replace(/^\/+/, '');
        if (!canAccessUserKey(key, req.userId)) {
            return sendError(res, 403, ErrorCodes.FORBIDDEN, 'Not authorized to delete this file');
        }

        const params = {
            Bucket: process.env.S3_BUCKET,
            Key: key
        };

        await s3.deleteObject(params).promise();

        res.json({ success: true, message: 'File deleted successfully' });
    } catch (error) {
        logEvent('error', 'delete_error', { message: error.message, userId: req.userId });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Delete failed', error.message);
    }
});

// Get signed URL for private files
app.get('/api/media/signed-url/:key(*)', authMiddleware, async (req, res) => {
    try {
        const key = (req.params.key || '').toString().replace(/^\/+/, '');
        if (!canAccessUserKey(key, req.userId)) {
            return sendError(res, 403, ErrorCodes.FORBIDDEN, 'Not authorized to access this file');
        }
        const requestedExpires = parseInt(req.query.expires || `${SIGNED_URL_EXPIRES_MAX}`, 10);
        const expires = Math.max(SIGNED_URL_EXPIRES_MIN, Math.min(SIGNED_URL_EXPIRES_MAX, requestedExpires));

        const params = {
            Bucket: process.env.S3_BUCKET,
            Key: key,
            Expires: expires
        };

        const url = s3.getSignedUrl('getObject', params);

        res.json({ success: true, url });
    } catch (error) {
        logEvent('error', 'signed_url_error', { message: error.message, userId: req.userId });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to generate signed URL');
    }
});

// List files for user
app.get('/api/media/list', authMiddleware, async (req, res) => {
    try {
        const requestedFolder = req.query?.folder?.toString().trim();
        let prefix = '';
        if (requestedFolder) {
            const folder = resolveAllowedFolder(requestedFolder);
            if (!folder) {
                return sendError(res, 400, ErrorCodes.BAD_REQUEST, `Invalid folder. Allowed: ${ALLOWED_FOLDERS.join(', ')}`);
            }
            prefix = `${folder}/${req.userId}/`;
        } else {
            // Default to common folder fan-out to avoid exposing other users' keys.
            prefix = '';
        }

        let files = [];
        if (prefix) {
            const params = {
                Bucket: process.env.S3_BUCKET,
                Prefix: prefix
            };
            const data = await s3.listObjectsV2(params).promise();
            files = (data.Contents || []).map(item => ({
                key: item.Key,
                size: item.Size,
                lastModified: item.LastModified,
                url: `https://${process.env.S3_BUCKET}.s3.${awsRegion}.amazonaws.com/${item.Key}`
            }));
        } else {
            const aggregated = [];
            for (const folder of ALLOWED_FOLDERS) {
                const params = {
                    Bucket: process.env.S3_BUCKET,
                    Prefix: `${folder}/${req.userId}/`
                };
                const data = await s3.listObjectsV2(params).promise();
                aggregated.push(...(data.Contents || []));
            }
            files = aggregated.map(item => ({
                key: item.Key,
                size: item.Size,
                lastModified: item.LastModified,
                url: `https://${process.env.S3_BUCKET}.s3.${awsRegion}.amazonaws.com/${item.Key}`
            }));
        }

        res.json({ success: true, files });
    } catch (error) {
        logEvent('error', 'list_files_error', { message: error.message, userId: req.userId });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to list files');
    }
});

// Audit logs (admin-only)
app.get('/api/media/audit-logs', authMiddleware, async (req, res) => {
    try {
        if (!MEDIA_AUDIT_LOG_ENABLED) {
            return sendError(res, 403, ErrorCodes.FORBIDDEN, 'Media audit logging is disabled');
        }
        if (!isAdminRequest(req)) {
            return sendError(res, 403, ErrorCodes.FORBIDDEN, 'Admin access required');
        }

        await ensureAuditModel();
        if (!MediaUploadAudit) {
            return sendError(res, 503, ErrorCodes.DEPENDENCY_UNAVAILABLE, 'Audit store unavailable');
        }

        const page = Math.max(1, parseInt(req.query.page || '1', 10));
        const requestedLimit = Math.max(1, parseInt(req.query.limit || '20', 10));
        const limit = Math.min(MEDIA_AUDIT_READ_MAX_LIMIT, requestedLimit);
        const skip = (page - 1) * limit;

        const query = {};
        if (req.query.status) query.status = req.query.status;
        if (req.query.action) query.action = req.query.action;
        if (req.query.userId) query.userId = req.query.userId.toString();
        if (req.query.from || req.query.to) {
            query.createdAt = {};
            if (req.query.from) query.createdAt.$gte = new Date(req.query.from);
            if (req.query.to) query.createdAt.$lte = new Date(req.query.to);
        }

        const [total, rows] = await Promise.all([
            MediaUploadAudit.countDocuments(query),
            MediaUploadAudit.find(query)
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .lean()
        ]);

        res.json({
            success: true,
            page,
            limit,
            total,
            hasMore: skip + rows.length < total,
            logs: rows.map(redactAuditRecord)
        });
    } catch (error) {
        logEvent('error', 'audit_logs_query_error', { message: error.message, userId: req.userId });
        return sendError(res, 500, ErrorCodes.INTERNAL_ERROR, 'Failed to fetch audit logs');
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', service: 'media-service' });
});

app.listen(PORT, () => {
    logEvent('info', 'service_started', { port: PORT, redisReady });
});
