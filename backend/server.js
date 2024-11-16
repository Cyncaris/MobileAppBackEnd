const express = require('express');
const Pusher = require('pusher');
const cors = require('cors');
require('dotenv').config();
const cookieParser = require('cookie-parser');
const { supabase } = require('./config/supabase');
const auth = require('./auth');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

console.log('Supabase client initialized:', !!supabase.from);

const app = express();
const jwt = require('jsonwebtoken');

app.use(helmet());
app.use(cookieParser(process.env.COOKIE_SECRET));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});

const fs = require('fs');

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

// Read keys
const privateKey = fs.readFileSync('private.pem', 'utf8');
const publicKey = fs.readFileSync('public.pem', 'utf8');

const secretKey = process.env.JWT_SECRET;
if (!secretKey) {
    console.error('JWT_SECRET is missing in environment variables');
    process.exit(1); // Exit if JWT_SECRET is not set
}

const getCookieOptions = () => ({
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
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

        console.log(`Authentication triggered for channel: ${channel}`);

        res.json({
            success: true,
            msg: "Authentication successful",
            data: { channel }
        });
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(500).json({
            success: false,
            msg: "Authentication failed",
            error: error.message
        });
    }
});

// Enhanced token generation
const generateToken = (payload) => {
    const tokenPayload = {
        ...payload,
        nonce: require('crypto').randomBytes(16).toString('hex')
    };
    // Remove exp if it exists since we're setting it in sign options
    delete tokenPayload.exp;

    return jwt.sign(
        tokenPayload,
        privateKey,
        {
            algorithm: 'RS256',
            expiresIn: '1h',
            jwtid: require('crypto').randomBytes(16).toString('hex')
        }
    );
};

// Update gen-token endpoint to use this function
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
            iat: Math.floor(Date.now() / 1000)
        };

        const token = generateToken(payload);
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
        // Verify with public key
        const decoded = jwt.verify(currentToken, publicKey, { algorithms: ['RS256'] });

        const newPayload = {
            ...decoded,
            restricted: true,
            iat: Math.floor(Date.now() / 1000),
            nonce: require('crypto').randomBytes(32).toString('hex')
        };
        delete newPayload.exp;

        // Sign with private key
        const newToken = jwt.sign(newPayload, privateKey, {
            algorithm: 'RS256',
            expiresIn: '1h'
        });

        res.cookie('authToken', newToken, getCookieOptions());

        return res.status(200).json({ success: true, message: 'Token updated successfully' });
    } catch (error) {
        console.error('Token update error:', error);
        return res.status(500).json({ success: false, message: 'Error updating token' });
    }
});

async function getUserById(user_id) {
    if (!user_id) throw new Error('Missing user_id parameter');

    const { data, error } = await supabase.from('useraccount').select('*').eq('id', user_id).single();
    if (error) throw new Error(error.message);

    return { user_id: data.id, email: data.email, name: `${data.first_name} ${data.last_name}`, role_id: data.role_id };
}

async function verifySessionId(channel) {
    try {
        if (!channel) return { status: 400, success: false, msg: "Channel token is required" };

        const { data: sessionData, error: sessionError } = await supabase.from('qr_sessions').select('*').eq('session_id', channel).maybeSingle();
        if (sessionError) return { status: 500, success: false, msg: "Database error" };

        if (!sessionData) return { status: 404, success: false, msg: "Invalid QR code" };

        if (new Date() > new Date(sessionData.expires_at)) {
            await supabase.from('qr_sessions').update({ status: 'expired' }).eq('session_id', channel);
            return { status: 410, success: false, msg: "QR code has expired" };
        }

        await supabase.from('qr_sessions').update({ status: 'validated' }).eq('session_id', channel);
        return { status: 200, success: true, msg: "Valid QR code" };
    } catch (error) {
        console.error('Unexpected error in session validation:', error);
        return { status: 500, success: false, msg: "An unexpected error occurred" };
    }
}

// Update token verification middleware
function verifyToken(req, res, next) {
    try {
        const token = req.cookies.authToken || req.headers.authorization?.replace('Bearer ', '');

        if (!token) {
            return res.status(401).json({ success: false, message: 'No token provided' });
        }

        jwt.verify(token, publicKey, { algorithms: ['RS256'] }, (err, payload) => {
            if (err) return res.sendStatus(403);
            req.user = payload;
            next();
        });


        // req.user = {
        //     userId: decoded.id,
        //     username: decoded.username,
        //     role: decoded.role,
        //     restricted: decoded.restricted
        // };
        // next();
    } catch (error) {
        console.error('Token verification error:', error);
        if (error.name === 'TokenExpiredError') {
            res.clearCookie('authToken', getCookieOptions());
            return res.status(401).json({ success: false, message: 'Token expired' });
        }
        return res.status(401).json({ success: false, message: 'Invalid token' });
    }
}


// Route for token verification
app.get('/api/verify-token', verifyToken, (req, res) => {
    res.json({ success: true, user: req.user });
});

// Your protected route
app.get('/protected', verifyToken, (req, res) => {
    res.json({ message: `Hello ${req.user.username}!`, userId: req.user.userId });
});

app.post('/logout', (req, res) => {
    try {
        // Clear cookie with matching settings
        res.clearCookie('authToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
            path: '/',
            domain: process.env.COOKIE_DOMAIN || undefined,  // Must match the domain used to set the cookie
            expires: new Date(0), // Forces immediate expiration
            maxAge: 0 // Also force immediate expiration
        });

        // Clear any other related cookies if they exist
        res.clearCookie('authToken', {
            path: '/',
            domain: undefined
        });

        // Clear cookie without any options as fallback
        res.clearCookie('authToken');

        console.log('Logged out successfully');
        res.status(200).json({
            success: true,
            message: "Logged out successfully"
        });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({
            success: false,
            message: "Error during logout"
        });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Test server running on port ${PORT}`);
});