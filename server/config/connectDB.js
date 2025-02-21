import mongoose from "mongoose";
import dotenv from "dotenv";


dotenv.config();

if (!process.env.MONGODB_URI) {
    throw new Error("Please provide a MONGODB_URI");
}

async function connectDB() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log("Mongodb connected");
    }
    catch (error) {
        console.log("Mongodb connect error", error);
        process.exit(1);
    }
}

export default connectDB;