import userModel from '../models/user.model.js';
import bcrypt from 'bcryptjs';
import verifyEmailTemplate from '../utils/verifyEmailTemplate.js';
import sendEmail from '../config/sendEmail.js';
import generateAccessToken from '../utils/generateAccessToken.js';
import generateRefreshToken from '../utils/generateRefreshToken.js';
import uploadImageCloudinary from '../utils/uploadImageCloudinary.js';
import generateOtp from '../utils/generateOtp.js';
import forgotPasswordTemplate from '../utils/forgotPasswordTemplate.js';
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv';

dotenv.config();

export async function registerUserController(req, res) {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({
                message: 'Please enter all fields',
                error: true,
                success: false
            })
        }
        const user = await userModel.findOne({ email });
        if (user) {
            return res.json({
                message: 'User already exists',
                error: true,
                success: false
            })
        }

        const salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(password, salt);

        const payload = {
            name,
            email,
            password: hashPassword
        }

        const newUser = new userModel(payload);
        const save = await newUser.save();

        const verifyEmailUrl = `${process.env.FRONTEND_URL}/verify-email?code=${save?._id}`;

        const verifictionEmail = await sendEmail({
            sendto: email,
            subject: 'Verify your Email',
            html: verifyEmailTemplate({
                name,
                url: verifyEmailUrl
            })
        });

        return res.json({
            message: 'User registered successfully',
            error: false,
            success: true,
            data: save
        })

    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }

}


export async function verifyEmailController(req, res) {
    try {
        const { code } = req.body;
        const user = await userModel.findOne({ _id: code });
        if (!user) {
            return res.status(400).json({
                message: 'Invalid verification code',
                error: true,
                success: false
            });
        }
        const userUpdate = await userModel.updateOne({ _id: code }, { verify_email: true });
        return res.json({
            message: 'Email verified successfully',
            error: false,
            success: true,
            data: userUpdate
        });
    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }
}


//login controller

export async function loginController(req, res) {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({
                message: 'Please enter all fields',
                error: true,
                success: false
            });
        }
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(400).json({
                message: 'User not found',
                error: true,
                success: false
            });
        }
        if (user.status !== 'active') {
            return res.status(400).json({
                message: 'User is not active',
                error: true,
                success: false
            });
        }
        const checkPassword = await bcrypt.compare(password, user.password);

        if (!checkPassword) {
            return res.status(400).json({
                message: 'Invalid password',
                error: true,
                success: false
            });
        }

        const accessToken = await generateAccessToken(user._id);
        const refreshToken = await generateRefreshToken(user._id);

        const cookieOption = {
            httpOnly: true,
            secure: true,
            sameSite: 'none'
        }
        res.cookie('accessToken', accessToken, cookieOption);
        res.cookie('refreshToken', refreshToken, cookieOption);

        return res.json({
            message: 'User logged in successfully',
            error: false,
            success: true,
            data: {
                accessToken,
                refreshToken
            }
        });
    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }
}

//logout controller

export async function logoutController(req, res) {
    try {
        const userid = req.userId;
        const cookieOption = {
            httpOnly: true,
            secure: true,
            sameSite: 'none'
        }
        res.clearCookie('accessToken', cookieOption);
        res.clearCookie('refreshToken', cookieOption);

        const removeRefreshToken = await userModel.findByIdAndUpdate(userid, { refresh_token: '' });

        return res.json({
            message: 'User logged out successfully',
            error: false,
            success: true
        });
    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }
}

//upload user avatar
export async function uploadAvatar(req, res) {
    try {
        const userId = req.userId;
        const image = req.file;

        const uploadImage = await uploadImageCloudinary(image);

        const updateUser = await userModel.findByIdAndUpdate(userId, { avatar: uploadImage.url });

        return res.json({
            message: 'Image uploaded successfully',
            error: false,
            success: true,
            data: {
                _id: userId,
                avatar: uploadImage.url
            }
        })


    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        })
    }
}

//update user details
export async function updateUserDetails(req, res) {
    try {
        const userId = req.userId;
        const { name, email, password, mobile } = req.body;
        let hashPassword = "";
        if (password) {
            const salt = await bcrypt.genSalt(10);
            hashPassword = await bcrypt.hash(password, salt);
        }
        const updateUser = await userModel.updateOne({ _id: userId }, {
            ...(name && { name: name }),
            ...(email && { email: email }),
            ...(password && { password: hashPassword }),
            ...(mobile && { mobile: mobile })
        })
        return res.json({
            message: 'User updated successfully',
            error: false,
            success: true,
            data: updateUser
        });
    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        })
    }
}

//forgot password
export async function forgotPasswordController(req, res) {
    try {
        const { email } = req.body;
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(400).json({
                message: 'User not found',
                error: true,
                success: false
            });
        }
        const otp = generateOtp();
        const expireTime = new Date() + 60 * 60 * 1000;

        const upadte = await userModel.findByIdAndUpdate(user._id, {
            forgot_password_otp: otp,
            forgot_password_expiry: new Date(expireTime).toISOString()
        });

        await sendEmail({
            sendto: email,
            subject: 'Forgot Password OTP',
            html: forgotPasswordTemplate({ name: user.name, otp: otp })
        });

        return res.json({
            message: 'OTP sent to your email',
            error: false,
            success: true
        })
    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        })
    }
}

//verify forgot password otp
export async function verifyForgotPasswordOtp(req, res) {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) {
            return res.status(400).json({
                message: 'Please provide email and OTP',
                error: true,
                success: false
            })
        }
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(400).json({
                message: 'User not found',
                error: true,
                success: false
            });
        }
        const currentTime = new Date().toISOString();
        if (user.forgot_password_expiry < currentTime) {
            return res.status(400).json({
                message: 'OTP is expired',
                error: true,
                success: false
            });
        }
        if (otp !== user.forgot_password_otp) {
            return res.status(400).json({
                message: "Inavalid OTP",
                error: true,
                success: false
            })
        }
        return res.json({
            message: 'OTP verified successfully',
            error: false,
            success: true
        });
    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        })
    }
}

//reset password
export async function resetPasswordController(req, res) {
    try {
        const { email, newPassword, confirmPassword } = req.body;
        if (!email || !newPassword || !confirmPassword) {
            return res.status(400).json({
                message: 'Please enter all fields',
                error: true,
                success: false
            })
        }
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(400).json({
                message: 'User not found',
                error: true,
                success: false
            });
        }
        if (newPassword !== confirmPassword) {
            return res.status(400).json({
                message: 'Passwords do not match',
                error: true,
                success: false
            });
        }
        const salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(newPassword, salt);

        const update = await userModel.findOneAndUpdate(user._id, { password: hashPassword });
        return res.json({
            message: 'Password reset successfully',
            error: false,
            success: true
        })

    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        })
    }
}

//refresh token controler
export async function refreshToken(request, response) {
    try {
        const refreshToken = request.cookies.refreshToken || request?.headers?.authorization?.split(" ")[1]  /// [ Bearer token]

        if (!refreshToken) {
            return response.status(401).json({
                message: "Invalid token",
                error: true,
                success: false
            })
        }

        const verifyToken = await jwt.verify(refreshToken, process.env.SECRET_KEY_REFRESH_TOKEN)

        if (!verifyToken) {
            return response.status(401).json({
                message: "token is expired",
                error: true,
                success: false
            })
        }

        const userId = verifyToken?._id

        const newAccessToken = await generateAccessToken(userId)

        const cookiesOption = {
            httpOnly: true,
            secure: true,
            sameSite: "None"
        }

        response.cookie('accessToken', newAccessToken, cookiesOption)

        return response.json({
            message: "New Access token generated",
            error: false,
            success: true,
            data: {
                accessToken: newAccessToken
            }
        })


    } catch (error) {
        return response.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        })
    }
}