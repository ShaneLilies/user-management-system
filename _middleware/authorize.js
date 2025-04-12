const { expressjwt: jwt } = require('express-jwt');
const config = require('../config.json'); // adjust path if needed
const db = require('_helpers/db');

module.exports = authorize;

function authorize(roles = []) {
    // Convert single role string to array
    if (typeof roles === 'string') {
        roles = [roles];
    }

    const secret = config.secret || process.env.JWT_SECRET || 'default_secret_key';

    return [
        // Authenticate JWT and attach user to req.user
        jwt({ secret, algorithms: ['HS256'] }),

        // Role-based authorization
        async (req, res, next) => {
            try {
                const account = await db.Account.findByPk(req.user.id);

                if (!account || (roles.length && !roles.includes(account.role))) {
                    return res.status(401).json({ message: 'Unauthorized' });
                }

                // Attach extra info to req.user
                req.user.role = account.role;
                const refreshTokens = await account.getRefreshTokens();
                req.user.ownsToken = token => !!refreshTokens.find(x => x.token === token);

                next();
            } catch (err) {
                return res.status(500).json({ message: 'Authorization error', error: err.message });
            }
        }
    ];
}
