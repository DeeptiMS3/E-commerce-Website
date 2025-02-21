import userModel from "../models/user.model.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const generateRefreshToken = async (userId) => {
    const token = await jwt.sign({ id: userId },
        process.env.SECRET_KEY_REFRESH_TOKEN,
        { expiresIn: '7d' });

    const updateRefreshTokenUser = await userModel.updateOne({ _id: userId }, { refresh_token: token });
    return token;
};

export default generateRefreshToken;