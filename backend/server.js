const express = require('express');
const Pusher = require('pusher');
const cors = require('cors');
require('dotenv').config();
const cookieParser = require('cookie-parser');
const { supabase } = require('./config/supabase');  
const auth = require('./auth');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware and configuration
app.use(cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
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

const secretKey = process.env.JWT_SECRET;

const getCookieOptions = () => ({
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // Changed for cross-origin
    maxAge: 3600000,
    path: '/',
});

// QR authentication endpoint
app.post('/api/login', async (req, res) => {
    const { channel, user_id } = req.body;
    console.log('Received authentication request:', { channel, user_id });

    const sessionResponse = await verifySessionId(channel);
    if (sessionResponse.status !== 200) {
        return res.status(sessionResponse.status).json(sessionResponse.body);
    }

    console.log('Session verified:', sessionResponse);
    try {
        await pusher.trigger(`private-${channel}`, "login-event", {
            user_id,
            timestamp: Date.now()
        });
        res.json({ success: true, msg: "Authentication successful", data: { channel } });
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(500).json({ success: false, msg: "Authentication failed", error: error.message });
    }
});

// Token generation endpoint
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
            exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour
        };

        const token = jwt.sign(payload, secretKey);
        res.cookie('authToken', token, getCookieOptions());

        return res.status(200).json({ 
            success: true,
            message: 'Token generated successfully',
            user: { id: userId, username: user.name, role: user.role_id }
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
        const decoded = jwt.verify(currentToken, secretKey);
        const newPayload = { ...decoded, restricted: true, iat: Math.floor(Date.now() / 1000) };
        delete newPayload.exp;

        const newToken = jwt.sign(newPayload, secretKey, { expiresIn: '1h' });
        res.cookie('authToken', newToken, getCookieOptions());

        return res.status(200).json({ success: true, message: 'Token updated successfully' });
    } catch (error) {
        console.error('Token update error:', error);
        return res.status(500).json({ success: false, message: 'Error updating token', error: error.message });
    }
});

// Verify token middleware
function verifyToken(req, res, next) {
    try {
        const token = req.cookies.authToken || (req.headers.authorization?.startsWith('Bearer ') && req.headers.authorization.split(' ')[1]);

        if (!token) {
            return res.status(401).json({ success: false, message: 'No token provided' });
        }

        const decoded = jwt.verify(token, secretKey);
        req.user = { userId: decoded.id, username: decoded.username, role: decoded.role, restricted: decoded.restricted };
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            res.clearCookie('authToken', getCookieOptions());
            return res.status(401).json({ success: false, message: 'Token expired' });
        }
        return res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// Protected routes and other endpoints
app.get('/api/verify-token', verifyToken, (req, res) => res.json({ success: true, user: req.user }));
app.get('/protected', verifyToken, (req, res) => res.json({ message: `Hello ${req.user.username}!`, userId: req.user.userId }));

// Logout
app.post('/logout', (req, res) => {
    res.clearCookie('authToken', getCookieOptions());
    console.log('Logged out successfully');
    res.json({ success: true, message: "Logged out successfully" });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Test server running on port ${PORT}`));
