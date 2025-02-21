const verifyEmailTemplate = ({ name, url }) => {
    return `
        <h1>Hi ${name}</h1>
        <p>Thanks for signing up with us</p>
        <p>Please click on the following link to verify your email</p>
        <a href="${url}" style="color:white;padding:5px;background-color:#2596be;border-radius:5px;text-decoration:none;">Verify Email</a>
        <p>If you did not sign up with us, please ignore this email.<br><br>
        Thank you<br>Grocify</p>
    `;
}

export default verifyEmailTemplate;