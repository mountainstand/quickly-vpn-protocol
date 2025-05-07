const User = require("../models/User");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require('nodemailer');
const Joi = require("joi");
require('dotenv').config();
const crypto = require("crypto")

function generateUniqueToken(length = 32) {
    return crypto.randomBytes(length).toString('hex'); // Converts to hex format
}

const socialSigninSchema = Joi.object({
    udid: Joi.string().required().messages({
        "any.required": "UDID is required",
        "string.empty": "UDID cannot be empty",
    }),
    googleId: Joi.string().optional(),
    appleId: Joi.string().optional(),
    socialType: Joi.string().optional(),
    email: Joi.string().email().messages({
        "string.email": "Invalid email format",
        "string.empty": "Email cannot be empty",
    }),
    userName: Joi.string().messages({
        "string.empty": "Username cannot be empty",
    }),
}).xor('googleId', 'appleId');

module.exports = {
    login: async (req, res) => {
        try {
            const { email, password } = req.body;
            if (!email || !password) {
                return res.status(400).json({
                    success: false,
                    data: null,
                    message: "All field required!"
                })
            }
            const user = await User.findOne({ email });
            if (!user) {
                return res.status(400).json({
                    success: false,
                    data: null,
                    message: "You are not registered user"
                })
            }
            console.log("object,", user.password)
            const checkPassword = await bcrypt.compare(password + process.env.SALT_KEY, user.password);
            if (!checkPassword) {
                return res.status(400).json({
                    success: false,
                    data: null,
                    message: "you are not authorize user"
                })
            }
            const token = jwt.sign({ userId: user._id, userName: user.userName }, process.env.JWT_SECRET_KEY, {
                expiresIn: process.env.JWT_EXPIRE_TIME,
            });
            return res.status(200).json({
                success: true,
                data: {
                    token,
                    user
                },
                message: "Login successfully"
            })
        } catch (error) {
            console.log(error)
            return res.status(500).json({
                success: false,
                data: null,
                message: "Something went wrong"
            })
        }
    },

    register: async (req, res) => {
        try {
            const { userName, email, password } = req.body;
            if (!email || !password) {
                return res.status(400).json({
                    success: false,
                    data: null,
                    message: "All fields required!"
                })
            }
            const user = await User.findOne({ email });
            if (user) {
                return res.status(400).json({
                    success: false,
                    data: null,
                    message: "Email already exists"
                })
            }
            const hashedPassword = await bcrypt.hash(password + process.env.SALT_KEY, 10);
            const newUser = await User.create({
                userName,
                email,
                password: hashedPassword
            })
            if (!newUser) {
                return res.status(400).json({
                    success: false,
                    data: null,
                    message: "Something went wrong"
                })
            }
            const token = jwt.sign({ userId: newUser._id, userName: newUser.userName }, process.env.JWT_SECRET_KEY, {
                expiresIn: process.env.JWT_EXPIRE_TIME,
            });
            return res.status(200).json({
                success: true,
                data: {
                    token,
                    user: newUser
                },
                message: "You are registered successfully"
            })

        } catch (error) {
            return res.status(400).json({
                success: false,
                data: null,
                message: "Something went wrong"
            })
        }
    },

    forgotpassword: async (req, res) => {
        try {
            const { email } = req.body;
            const emailToken = generateUniqueToken();
            const user = await User.findOneAndUpdate({ email }, { emailToken });

            if (!user) {
                return res.status(400).json({
                    success: false,
                    data: null,
                    message: 'This email does not exist'
                });
            }

            const resetUrl = `${process.env.VPN_Backend_URL}/api/auth/reset-password/${emailToken}`;

            // const transporter = nodemailer.createTransport({
            //     name: process.env.SMTP_APP_NAME,
            //     host: process.env.SMTP_HOST,
            //     port: process.env.SMTP_PORT,
            //     secure: true,
            //     auth: {
            //         user: process.env.EMAIL_USER,
            //         pass: process.env.EMAIL_PASS
            //     },
            //     logger: true,
            //     debug: true
            // });

            const transporter = nodemailer.createTransport({
                name: "quick_vpn",
                host: "smtp.gmail.com",
                port: 465,
                secure: true,
                auth: {
                    user: "developersiapp@gmail.com",
                    pass: "fdpqqqsqahytyjka"
                },
                logger: true,
                debug: true
            });

            // const transporter = nodemailer.createTransport({
            //     host: "sandbox.smtp.mailtrap.io",
            //     port: 2525,
            //     auth: {
            //         user: "78332cb485694c",
            //         pass: "29634085db480e"
            //     }
            // });

            const mailOptions = {
                from: `"Support Team" <${process.env.EMAIL_USER}>`,
                to: email,
                subject: "Reset Your Password",
                text: emailToken,
                html: `<h4>Hi ${user.userName}</h4>
              <p>We received a request to reset your password. Click the button below to set a new password:</p>
              <a href="${resetUrl}" style="display: inline-block; padding: 10px 15px; background: #007bff; color: white; text-decoration: none; border-radius: 5px;">
              🔒 Reset Password
              </a>
              <p>If you didn’t request a password reset, please ignore this email.</p>`
            };

            // Sending the email
            const info = await transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error("Error sending email:", error);
                } else {
                    console.log("Email sent:", info.response);
                }
            });
            console.log('Email sent:', info); // This logs the email sent response

            // Send success response
            return res.status(200).json({
                success: true,
                message: 'Email sent successfully'
            });

        } catch (error) {
            console.log('Error:', error);
            // Handle error response
            return res.status(500).json({
                success: false,
                message: 'An error occurred while sending the email'
            });
        }
    },

    resetpasswordform: async (req, res) => {
        try {
            const { token } = req.params;
            if (!token) {
                return res.status(400).send("<h1>Invalid Url</h1>");
            }
            const user = await User.findOne({ emailToken: token });
            if (!user) {
                return res.status(400).send("<h1>this url is expired</h1>");
            }
            return res.status(400).render("reset-password.ejs");

        } catch (error) {
            console.log(error);
            return res.status(500).send("<h1>Some thing went wrong</h1>");
        }
    },

    resetpassword: async (req, res) => {
        try {
            const { token } = req.params;
            const { email, password } = req.body;
            console.log(email, password);
            if (!email || !password || !token) {
                return res.status(400).send("<h1>All field required</h1>");
            }

            const hashedPassword = await bcrypt.hash(password + process.env.SALT_KEY, 10);
            console.log(hashedPassword)
            const user = await User.findOneAndUpdate(
                { email, emailToken: token },
                { $set: { emailToken: null, password: hashedPassword } },
                { new: true }
            );
            if (!user) {
                return res.status(400).send("<h1>invalid User</h1>");
            }
            return res.status(400).send("<h1>Password reset Successfully</h1>");
        } catch (error) {
            console.log(error);
            return res.status(500).send("<h1>Some thing went wrong</h1>");
        }
    },

    userDetail: async (req, res) => {
        try {
            const id = req.user.userId;
            console.log(req.user)
            const userDetails = await User.findById(id)
            if (!userDetails) {
                return res.status(400).json({
                    success: false,
                    data: null,
                    message: "User does not exist",
                })
            }
            return res.status(200).json({
                success: true,
                data: userDetails,
                message: "User fetched successfully",
            })

        } catch (error) {
            console.log("error:", error)
            return res.status(500).json({
                success: false,
                data: null,
                message: "Something went wrong",
            })
        }
    },

    deleteUser: async (req, res) => {
        try {
            const id = req.user.userId;
            const user = await User.findByIdAndDelete(id);
            if (!user) {
                return res.status(400).json({
                    success: false,
                    data: null,
                    message: "User does not exist",
                })
            }
            return res.status(200).json({
                success: true,
                data: null,
                message: "User delete successfully",
            })
        } catch (error) {
            return res.status(500).json({
                success: false,
                data: null,
                message: "Something went wrong",
            })
        }
    },

    socialLogin: async (req, res) => {
        try {
            // Validate request body
            const { error } = socialSigninSchema.validate(req.body);
            if (error) {
                console.log(error.details[0])
                return res.status(400).json({
                    success: false,
                    data: null,
                    message: error.details[0].message,
                });
            }

            const { udid, googleId, appleId, email, userName, socialType } = req.body;
            const user = await User.findOneAndUpdate(
                {
                    $or: [
                        { email },
                        { googleId },
                        { appleId }
                    ]
                },
                { appleId, userName, socialType },
                { new: true }
            );


            if (!user) {
                const newUser = await User.create({
                    udid,
                    googleId,
                    appleId,
                    email,
                    userName,
                    socialType,
                });
                const token = jwt.sign({ userId: newUser._id, userName: newUser.userName }, process.env.JWT_SECRET_KEY, {
                    expiresIn: process.env.JWT_EXPIRE_TIME,
                });
                return res.status(201).json({
                    success: true,
                    data: {
                        token,
                        user: newUser
                    },
                    message: "Login successfully",
                });
            }
            const token = jwt.sign({ userId: user._id, userName: user.userName }, process.env.JWT_SECRET_KEY, {
                expiresIn: process.env.JWT_EXPIRE_TIME,
            });
            return res.status(201).json({
                success: true,
                data: {
                    token,
                    user
                },
                message: "Login successfully",
            });
        } catch (error) {
            console.error("Error in social sign-in:", error);
            return res.status(500).json({
                success: false,
                message: "Something went wrong",
            });
        }
    }
};


