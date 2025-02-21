import mongoose from "mongoose";


const addressSchema = new mongoose.Schema({
    address_line: {
        type: String,
        required: [true, "Please provide an address line"],
        default: "",
    },
    city: {
        type: String,
        required: [true, "Please provide a city"],
        default: "",
    },
    state: {
        type: String,
        required: [true, "Please provide a state"],
        default: "",
    },
    pincode: {
        type: String,
        required: [true, "Please provide a pincode"],
        default: "",
    },
    country: {
        type: String,
        required: [true, "Please provide a country"],
        default: "",
    },
    mobile: {
        type: Number,
        required: [true, "Please provide a mobile number"],
        default: null,
    },
    status: {
        type: Boolean,
        default: true,
    },
}, { timestamps: true });

const addressModel = mongoose.model("address", addressSchema);

export default addressModel;
