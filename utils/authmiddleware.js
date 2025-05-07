const jwt = require('jsonwebtoken');
const User = require('../models/User');

const protect = async (req, res, next) => {
    try {
        const token = req.headers.authorization.split(" ")[1];
        if (!token) {
            return res.status(401).json({
                success: false,
                data: null,
                message: 'Token Not Found'
            })
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        if (!decoded) {
            return res.status(401).json({
                success: false,
                data: null,
                message: 'Unauthorize'
            })
        }
        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.status(401).json({ success: false, message: 'User not exist', data: null });
        }
        req.user = user;
        next();
    } catch (error) {
        return res.status(500).json({
            success: false,
            data: null,
            message: 'Something went wrong'
        })
    }
};

module.exports = protect;