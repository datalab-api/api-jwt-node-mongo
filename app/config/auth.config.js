module.exports = {
    secret: require('crypto').randomBytes(64).toString('hex'),
    jwtExpiration: 86400,           // 24 hour
    jwtRefreshExpiration: '7d',   // 7 days
};