const express = require('express');
const passport = require('passport');
const GitHubStrategy = require('passport-github').Strategy;
const router = express.Router();
const auth = require('../../middleware/auth');
const User = require('../../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');

// Configure Passport GitHub Strategy
passport.use(
    new GitHubStrategy(
        {
            clientID: config.get('githubClientId'),
            clientSecret: config.get('githubClientSecret'),
            callbackURL: 'http://localhost:5000/api/auth/github/callback',
        },
        async (accessToken, refreshToken, profile, done) => {
            const { id, username, photos } = profile;

            try {
                let user = await User.findOne({ githubId: id });

                if (!user) {
                    user = new User({
                        githubId: id,
                        name: username,
                        avatar: photos[0]?.value || '',
                    });
                    await user.save();
                }

                return done(null, user);
            } catch (err) {
                console.error(err.message);
                return done(err, null);
            }
        }
    )
);

// Initialize Passport
router.use(passport.initialize());

// @route GET api/auth
// @desc Test route
// @access Public
router.get('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route POST api/auth
// @desc Authenticate User and get token
// @access Public
router.post(
    '/',
    [
        check('email', 'Please include a valid email').isEmail(),
        check('password', 'Password is required').exists(),
    ],
    async (req, res) => {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        try {
            // See if user exists
            let user = await User.findOne({ email });

            if (!user) {
                return res.status(400).json({ errors: [{ msg: 'Invalid Credentials' }] });
            }

            const isMatch = await bcrypt.compare(password, user.password);

            if (!isMatch) {
                return res.status(400).json({ errors: [{ msg: 'Invalid Credentials' }] });
            }

            // Return jsonWebToken
            const payload = {
                user: {
                    id: user.id,
                },
            };

            jwt.sign(
                payload,
                config.get('jwtSecret'),
                { expiresIn: 360000 },
                (err, token) => {
                    if (err) throw err;
                    res.json({ token });
                }
            );
        } catch (err) {
            console.log(err.message);
            res.status(500).send('Server error');
        }
    }
);

// @route GET api/auth/github
// @desc Redirect to GitHub for authentication
// @access Public
router.get('/github', passport.authenticate('github'));

// @route GET api/auth/github/callback
// @desc GitHub callback URL
// @access Public
router.get(
    '/github/callback',
    passport.authenticate('github', { failureRedirect: '/' }),
    (req, res) => {
        res.json({ msg: 'GitHub authentication successful', user: req.user });
    }
);

module.exports = router;