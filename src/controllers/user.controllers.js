const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const sendEmail = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');
const jwt = require('jsonwebtoken');

const getAll = catchError(async(req, res) => {
    const users = await User.findAll();
    return res.json(users);
});

const create = catchError(async(req, res) => {
    const { email, password, firstName, lastName, country, image, frontBaseUrl } = req.body;
    const encriptedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: encriptedPassword, firstName, lastName, country, image });
    const code = require('crypto').randomBytes(32).toString("hex");
    const link = `${frontBaseUrl}/verify_email/${code}`;
    await sendEmail({
        to: email,
        subject: "Verificate email for user app",
        html: `
            <h1>Hello ${firstName} ${lastName}</h1>
            <p>Verify your account clicking this link!</p>
            <a href="${link}">${link}</a>
            <h4>Thank you!</h4>
        `
    });
    await EmailCode.create({ code, userId: user.id });
    return res.status(201).json(user);
});

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const user = await User.findByPk( id );
    if(!user) return res.sendStatus(404);
    return res.json(user);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    const users = await User.destroy({ where: {id} });
    if(users === 0) return res.sendStatus(404);
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const { firstName, lastName, country, image } = req.body;
    const user = await User.update(
        { firstName, lastName, country, image },
        { where: {id}, returning: true }
    );
    if(user[0] === 0) return res.sendStatus(404);
    return res.json(user[1][0]);
});

const verifyEmail = catchError(async(req, res) => {
    const { code } = req.params;
    const emailCode = await EmailCode.findOne({ where: { code } })
    if(!emailCode) return res.status(401).json({ message: "Invalid code" });
    await User.update(
        { isVerified: true },
        { where: { id: emailCode.userId } }
    );
    await emailCode.destroy();
    return res.json(emailCode);
});

const login = catchError(async(req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });
    if(!user || !user.isVerified) return res.status(401).json({ message: "Invalid credentials" });
    const isValid = await bcrypt.compare(password, user.password);
    if(!isValid) return res.status(401).json({ message: "Invalid credentials" });
    const token = jwt.sign(
        { user },
        process.env.TOKEN_SECRET,
        { expiresIn: '1d' }
    );
    return res.json({ user, token });
});

const getLoggedUser = catchError(async(req, res) => {
    return res.json(req.user);
});

const passwordVerifyEmail = catchError(async(req, res) => {
    const { email, frontBaseUrl } = req.body;
    const user = await User.findOne({ where: { email } });
    if(!user) return res.status(401).json({ message: "Invalid credentials" });
    const code = require('crypto').randomBytes(32).toString("hex");
    const link = `${frontBaseUrl}/reset_password/${code}`;
    await sendEmail({
        to: email,
        subject: "Reset password for user app",
        html: `
            <h1>Hello ${user.firstName} ${user.lastName}</h1>
            <p>Reset your password clicking this link!</p>
            <a href="${link}">${link}</a>
            <h4>Thank you!</h4>
        `
    });
    await EmailCode.create({ code, userId: user.id });
    return res.json(user);
});

const changePassword = catchError(async(req, res) => {
    const { code } = req.params;
    const emailCode = await EmailCode.findOne({ where: { code } });
    if(!emailCode) return res.status(401).json({ message: "Invalid code" });
    const { password } = req.body;
    const encriptedPassword = await bcrypt.hash(password, 10);
    await User.update(
        { password: encriptedPassword },
        { where: { id: emailCode.userId } }
    );
    emailCode.destroy();
    return res.json(emailCode);
});

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyEmail,
    login,
    getLoggedUser,
    passwordVerifyEmail,
    changePassword
}