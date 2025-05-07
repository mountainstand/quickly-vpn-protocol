const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    googleId: String,
    appleId: String,
    userName: String,
    email: {
        type: String,
        validate: {
            validator: function (email) {
                return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); // Regular expression for email validation
            },
            message: (props) => `${props.value} is not a valid email address!`,
        }
    },
    emailToken: String,
    socialType: String,
    udid: String,
    password: String,
    openvpnPassword: String,
    publicKey: String,
    privateKey: String,
    wireguardIpAddress: String,
    openvpnIpAddress: String,
    isIkev2: String,
    lastConnection: Date,
}, {
    timestamps: true
});

const User = mongoose.model("User", userSchema);
module.exports = User;