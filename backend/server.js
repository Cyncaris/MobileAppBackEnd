const express = require('express');
const Pusher = require('pusher');
const cors = require('cors');
require('dotenv').config();
const cookieParser = require('cookie-parser');
const { supabase } = require('./config/supabase');  
const auth = require('./auth');

// Add this debug log to verify Supabase client initialization
console.log('Supabase client initialized:', !!supabase.from);

const app = express();
const jwt = require('jsonwebtoken');

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

const key = process.env.PUSHER_SECRET; // Ensure `SECRET_KEY` is set in your environment variables
if (!key) {
    throw new Error('SECRET_KEY is missing');
}

const secretKey = process.env.JWT_SECRET;


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

        // Trigger Pusher event
        await pusher.trigger(
            `private-${channel}`,
            "login-event",
            {
                user_id,
                timestamp: Date.now()
            }
        );

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

app.post('/api/gen-token', async (req, res) => {
    const { userId } = req.body;
    console.log('Received token request:', { userId });

    const user = await getUserById(userId);

    // Validate request body    
    if ( !userId) {
        return res.status(400).json({ 
            success: false,
            message: 'userId are required' 
        });
    }

    // Payload to include in the token
    const payload = {
        id: userId,
        username: user.name,
        role: user.role_id,
        restricted: false,  // Added this line
        iat: Math.floor(Date.now() / 1000), // Issued at time
    };

    console.log('Signing token for user:', payload);

    try {
        const token = jwt.sign(payload, secretKey, { 
            expiresIn: '1h'  // 1 hour expiration
        });

        // Set cookie with enhanced security options
        res.cookie('authToken', token, { 
            httpOnly: true,  // Prevents JavaScript access
            secure: process.env.NODE_ENV === 'production',  // HTTPS only in production
            sameSite: 'strict',  // CSRF protection
            maxAge: 3600000,  // 1 hour in milliseconds
            path: '/',  // Cookie is available for all paths
            domain: process.env.NODE_ENV === 'production' ? 'yoursite.com' : 'localhost'
        });

        // Send success response
        return res.status(200).json({ 
            success: true,
            message: 'Token generated successfully',
        });

    } catch (error) {
        console.error('Token generation error:', error);
        return res.status(500).json({ 
            success: false,
            message: 'Error generating token',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
});

app.post('/api/update-token', async (req, res) => {
    // Get the current token from cookies
    const currentToken = req.cookies.authToken;
    
    if (!currentToken) {
        return res.status(401).json({
            success: false,
            message: 'No token provided'
        });
    }

    try {
        // Verify and decode the current token
        const decoded = jwt.verify(currentToken, secretKey);
        
        // Create new payload with all existing data plus restricted flag
        const newPayload = {
            ...decoded,
            restricted: true,
            iat: Math.floor(Date.now() / 1000) // Update issued at time
        };
        
        // Remove the exp field if it exists, as jwt.sign will add a new one
        delete newPayload.exp;
        
        // Generate new token
        const newToken = jwt.sign(newPayload, secretKey, {
            expiresIn: '1h'
        });

        // Set the new cookie
        res.cookie('authToken', newToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 3600000,
            path: '/',
            domain: process.env.NODE_ENV === 'production' ? 'yoursite.com' : 'localhost'
        });

        return res.status(200).json({
            success: true,
            message: 'Token updated successfully'
        });

    } catch (error) {
        console.error('Token update error:', error);
        return res.status(500).json({
            success: false,
            message: 'Error updating token',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
});

async function getUserById(user_id) {
    if (!user_id) {
        throw new Error('Missing user_id parameter');
    }

    const { data, error } = await supabase
        .from('useraccount')
        .select('*')
        .eq('id', user_id)
        .single();

    if (error) {
        throw new Error(error.message);
    }

   const name = `${data.first_name} ${data.last_name}`;
   console.log('User data:', name);

    return {
        user_id: data.id,
        email: data.email,
        name: name,
        role_id: data.role_id,
    };
}

// verify sessionId
async function verifySessionId(channel) {
    try {
        if (!channel) {
            return {
                status: 400,
                success: false,
                msg: "Channel token is required"
            };
        }

        const session_id = channel;  // Extract session ID from channel name

        const { data: sessionData, error: sessionError } = await supabase
            .from('qr_sessions')
            .select('*')
            .eq('session_id', session_id)
            .maybeSingle();

        if (sessionError) {
            console.error('Supabase error:', sessionError);
            return {
                status: 500,
                success: false,
                msg: "Database error"
            };
        }

        if (!sessionData) {
            return {
                status: 404,
                success: false,
                msg: "Invalid QR code"
            };
        }

        // Check if session has expired
        if (new Date() > new Date(sessionData.expires_at)) {
            // Update status to expired
            const { error: updateError } = await supabase
                .from('qr_sessions')
                .update({ status: 'expired' })
                .eq('session_id', channel);

            if (updateError) {
                console.error('Status update error:', updateError);
            }

            return {
                status: 410,
                success: false,
                msg: "QR code has expired"
            };
        }

        // Update status to validated
        const { error: updateError } = await supabase
            .from('qr_sessions')
            .update({ status: 'validated' })
            .eq('session_id', channel);

        if (updateError) {
            console.error('Status update error:', updateError);
            return {
                status: 500,
                success: false,
                msg: "Failed to update session status"
            };
        }
        return {
            status: 200,
            success: true,
            msg: "Valid QR code",
            
        };

    } catch (error) {
        // Log any unexpected errors but don't throw them
        console.error('Unexpected error in session validation:', error);
        return {
            status: 500,
            success: false,
            msg: "An unexpected error occurred"
        };
    }
}


// Verify token middleware
function verifyToken(req, res, next) {
    const token = req.cookies.authToken;

    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'No token provided' 
        });
    }

    try {
        const decoded = jwt.verify(token, secretKey);
        
        // Attach user info to request object instead of sending response
        req.user = {
            userId: decoded.id,
            username: decoded.username,
            role: decoded.role,
            restricted: decoded.restricted
        };
        
        // Pass control to next middleware
        next();
        
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            res.clearCookie('authToken');
            return res.status(401).json({ 
                success: false,
                message: 'Token expired' 
            });
        }
        return res.status(401).json({ 
            success: false,
            message: 'Invalid token' 
        });
    }
}

// Separate route for token verification (for your frontend RoleBasedRoute)
app.get('/api/verify-token', verifyToken, (req, res) => {
    res.json({
        success: true,
        user: req.user
    });
});

// Your protected route
app.get('/protected', verifyToken, (req, res) => {
    res.json({
        message: `Hello ${req.user.username}!`,
        userId: req.user.userId
    });
});



app.get('/profile', auth.checkAuth, (req, res) => {
    // Common pattern for success response
    res.json({
        success: true,
        data: {
            userId: req.user.id,
            username: req.user.username,
            email: req.user.email,
            // any other user data you want to send
        },
        message: "Profile retrieved successfully"
    });
});

app.post('/logout', (req, res) => {
    // Backend cleanup
    try {
        // 1. Clear the authentication cookie
        res.clearCookie('authToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/'
        });

        // 2. Optional: If you're using sessions or tokens storage
        // await invalidateToken(req.user.id);  // If you store tokens in DB
        // req.session.destroy();               // If using sessions
        console.log('Logged out successfully');
        res.json({
            success: true,
            message: "Logged out successfully"
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Logout failed",
            error: error.message
        });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Test server running on port ${PORT}`);
});