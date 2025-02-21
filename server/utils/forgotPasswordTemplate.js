const forgotPasswordTemplate = ({ name, otp }) => {
    return `
    <h1>Forgot your password?</h1>
    <p>Dear ${name}, <br> You have submitted a password change request. Please use the following OTP to reset your password.</p>
    <span style="font-size:20px;background-color:#07120e;color:#fff;padding:10px">${otp}</span>
    <p>This OTP is valid upto 1h only! Enter this OTP in Grocify to proceed with resetting your password.<br><br>
    Thank you<br>Grocify</p>
  `;
}

export default forgotPasswordTemplate;