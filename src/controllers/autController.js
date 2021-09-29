//se puede hacer una carpeta de rutas, pero por la sencilles del proyecto voy hacer todo en esta carpeta
const { Router } = require('express');
const router = Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const config = require('../config');
const verifyToken = require('./verifyToken');


router.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    const user = new User ({
        username,
        email,
        password
    })
    user.password = await user.hashPassword(user.password);
    //console.log(user)
    await user.save();

    const token = jwt.sign({id: user._id}, config.secret, {
        expiresIn: 60 * 60 * 24
    })

    res.json({auth: true, token})
})


router.get('/profile', verifyToken, async (req, res) => {

    const user = await User.findById(req.userId, { password: 0 });
    if(!user) {
        return res.status(404).send('No user found')
    }
    res.json(user);
})


router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
        return res.status(404).send("The email doesn't exists");
    }
    const passValid = await user.validatePassword(password);
    if (!passValid) {
        return res.status(401).json({auth: false, token: null});
    }

    const token = jwt.sign({id: user._id}, config.secret, {
        expiresIn: 60 * 60 * 24
    });

    res.json({ auth: true, token });
})


router.put('/restorepassword', verifyToken, async (req, res) => {
    try {
        if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{10,}$/.test(req.body.password)) {
            return res.json({
                message:
                "The password must have at least 10 caracters, one uppercase letter, one lowercase letter and one of the following characters @$!%*?&",
            });
        }
        let user = await User.findByIdAndUpdate(req.userId, {
            password: await User.hashPassword(req.body.password),
            resetPassword: false,
        });
        if (user) {
            return res.send({ message: "Password restored" });
        } else {
            return res.send({ message: "Couldn't update" });
        }
    } catch (error) {
        console.log(error);
    }
})

module.exports = router;