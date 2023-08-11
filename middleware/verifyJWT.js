const jwt = require('jsonwebtoken');
require('dotenv').config();

const verifyJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.sendStatus(401);
    console.log(authHeader); //Bearer Token
    const token = authHeader.split(' ')[1];
    jwt.verify(
        token,
        process.env.ACESS_TOKEN_SECRET,
        (err, decode) => {
            if (err) return res.sendStatus(403); // invalid token
            req.user = decoded.username;
            next();
        }
    );
}

module.exports = verifyJWT;