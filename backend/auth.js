const jwt = require('jsonwebtoken');
require('dotenv').config();

// Simple authentication utility
const auth = {
    // Verify and decode JWT token from cookie
    verifyAuthCookie(cookie) {
        try {
            if (!cookie) {
                throw new Error('No authentication cookie provided');
            }
            return jwt.verify(cookie, process.env.JWT_SECRET_KEY);
        } catch (error) {
            return null;
        }
    },

    // Middleware for protected routes
    checkAuth(req, res, next) {
        try {
            const token = req.cookies.authToken;
            const userData = auth.verifyAuthCookie(token);

            if (!userData) {
                return res.status(401).json({ error: 'Authentication failed' });
            }

            req.user = userData;
            next();
        } catch (error) {
            res.status(401).json({ error: 'Authentication failed' });
        }
    }
};

module.exports = auth;