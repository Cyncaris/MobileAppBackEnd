const express = require('express');
const Pusher = require('pusher');
const cors = require('cors');
require('dotenv').config();
const cookieParser = require('cookie-parser');
const { supabase } = require('./config/supabase');  
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

console.log('Supabase client initialized:', !!supabase.from);

const app = express();

app.use(helmet());
app.use(cookieParser(process.env.COOKIE_SECRET));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
});
app.use(limiter);

app.use(cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());
app.use(cookieParser());

// Initialize Pusher
const pusher = new Pusher({
    appId: process.env.PUSHER_APP_ID,
    key: process.env.NEXT_PUBLIC_PUSHER_KEY,
    secret: process.env.PUSHER_SECRET,
    cluster: process.env.NEXT_PUBLIC_PUSHER_CLUSTER,
    useTLS: true,
});

// Read keys from environment variables
const privateKey = process.env.PRIVATE_KEY.replace(/\\n/g, '\n');
const publicKey = process.env.PUBLIC_KEY.replace(/\\n/g, '\n');

if (!privateKey || !publicKey) {
    console.error('RSA keys are missing in environment variables.');
    process.exit(1);
}

// Secure cookie options
const getCookieOptions = () => {
    const options = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
        maxAge: 3600000, // 1 hour
        path: '/',
    };
    if (process.env.COOKIE_DOMAIN) {
        options.domain = process.env.COOKIE_DOMAIN;
    }
    return options;
};

// Enhanced token generation with RSA private key
const generateToken = (payload) => {
    const tokenPayload = {
        ...payload,
        nonce: crypto.randomBytes(16).toString('hex'),
    };
    delete tokenPayload.exp;

    return jwt.sign(tokenPayload, privateKey, {
        algorithm: 'RS256',
        expiresIn: '1h',
        jwtid: crypto.randomBytes(16).toString('hex'),
    });
};

// Token verification middleware using the RSA public key
function verifyToken(req, res, next) {
    try {
        const token = req.cookies.authToken || 
                     (req.headers.authorization?.startsWith('Bearer ') && req.headers.authorization.split(' ')[1]);

        if (!token) {
            return res.status(401).json({ success: false, message: 'No token provided' });
        }

        jwt.verify(token, publicKey, { algorithms: ['RS256'] }, (err, payload) => {
            if (err) return res.status(403).json({ success: false, message: 'Invalid token' });
            req.user = payload;
            next();
        });
    } catch (error) {
        console.error('Token verification error:', error);
        if (error.name === 'TokenExpiredError') {
            res.clearCookie('authToken', getCookieOptions());
            return res.status(401).json({ success: false, message: 'Token expired' });
        }
        return res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// QR authentication endpoint
app.post('/api/login', async (req, res) => {
    const { channel, user_id } = req.body;
    console.log('Received authentication request:', { channel, user_id });

    const sessionResponse = await verifySessionId(channel);
    if (sessionResponse.status !== 200) {
        return res.status(sessionResponse.status).json(sessionResponse.body);
    }

    try {
        await pusher.trigger(`private-${channel}`, "login-event", {
            user_id,
            timestamp: Date.now(),
        });

        res.json({
            success: true,
            msg: "Authentication successful",
            data: { channel },
        });
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(500).json({ success: false, msg: "Authentication failed", error: error.message });
    }
});

// Update gen-token endpoint to use the enhanced token generation
app.post('/api/gen-token', async (req, res) => {
    try {
        const { userId } = req.body;
        if (!userId) {
            return res.status(400).json({ success: false, message: 'userId is required' });
        }

        const user = await getUserById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const payload = {
            id: userId,
            username: user.name,
            role: user.role_id,
            restricted: false,
            iat: Math.floor(Date.now() / 1000),
        };

        const token = generateToken(payload);
        res.cookie('authToken', token, getCookieOptions());

        return res.status(200).json({
            success: true,
            message: 'Token generated successfully',
            user: { id: userId, username: user.name, role: user.role_id },
        });
    } catch (error) {
        console.error('Token generation error:', error);
        return res.status(500).json({ success: false, message: 'Error generating token' });
    }
});

// Token update endpoint
app.post('/api/update-token', async (req, res) => {
    const currentToken = req.cookies.authToken;
    if (!currentToken) {
        return res.status(401).json({ success: false, message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(currentToken, publicKey, { algorithms: ['RS256'] });

        const newPayload = {
            ...decoded,
            restricted: true,
            iat: Math.floor(Date.now() / 1000),
            nonce: crypto.randomBytes(32).toString('hex'),
        };
        delete newPayload.exp;

        const newToken = jwt.sign(newPayload, privateKey, {
            algorithm: 'RS256',
            expiresIn: '1h',
        });

        res.cookie('authToken', newToken, getCookieOptions());

        return res.status(200).json({ success: true, message: 'Token updated successfully' });
    } catch (error) {
        console.error('Token update error:', error);
        return res.status(500).json({ success: false, message: 'Error updating token' });
    }
});

// Routes for token verification
app.get('/api/verify-token', verifyToken, (req, res) => {
    res.json({ success: true, user: req.user });
});

// Protected route
app.get('/protected', verifyToken, (req, res) => {
    res.json({ message: `Hello ${req.user.username}!`, userId: req.user.userId });
});

app.post('/logout', (req, res) => {
    res.clearCookie('authToken', getCookieOptions());
    res.json({ success: true, message: "Logged out successfully" });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Production server running on port ${PORT}`);
});
