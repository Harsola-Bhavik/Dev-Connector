const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const {check , validationResult} = require('express-validator');

const User = require('../../models/User');
const multer = require('multer');
const path = require('path');
const auth = require('../../middleware/auth');
// @route POST api/users
// @desc Register User
// @access Public

router.post('/' ,[
    check('name' , 'Name is required')
    .not()
    .isEmpty(),
    check('email','Please include a vaild email').isEmail(),
    check(
        'password',
        'Please enter a password with 6 or more characters'
    ).isLength({min : 6})
], 
    async (req,res) => {
    
    const errors = validationResult(req);

    if(!errors.isEmpty()){
        return res.status(400).json({errors : errors.array()});
    }

    const {name, email ,password} = req.body;

    try {
    
    
        //See if user exists
        let user = await User.findOne({ email });

        if(user){
            return res.status(400).json({ errors : [{msg: 'User already exists'}]});
        }
    
        //Get users gravatar
        const avatar =gravatar.url(email,{
            s: '200',
            r: 'pg',
            d: 'mm'
        })

        user = new User({
            name,
            email,
            avatar,
            password
        });
    
        //Encrypt password
        const salt = await bcrypt.genSalt(10);

        user.password = await bcrypt.hash(password, salt);
        await user.save();
    
        //Return jsonWebToken

        const payload = {
            user : {
                id : user.id
            }
        }

        jwt.sign(
            payload,
            config.get('jwtSecret'),
            {expiresIn : 360000},
            (err,token) => {
                if(err) throw err;
                res.json({ token });
            }
        );
    
    } catch (err) {
        
        console.error('Registration error:', err.message);
        if (err.name === 'MongooseError' || err.message.includes('buffering timed out')) {
            return res.status(503).json({ errors: [{ msg: 'Database unavailable. Please try again later.' }] });
        }
        res.status(500).json({ errors: [{ msg: 'Server error' }] });
    }




});
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, 'public/uploads/');
  },
  filename: function(req, file, cb) {
    cb(null, req.user.id + '-' + Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5000000 },
  fileFilter: function(req, file, cb) {
    const filetypes = /jpeg|jpg|png|gif/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb('Error: Images Only!');
    }
  }
});

// @route POST api/users/avatar
// @desc Upload user avatar
// @access Private
router.post('/avatar', auth, upload.single('avatar'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ errors: [{ msg: 'Please upload a file' }] });
  }

  try {
    const user = await User.findById(req.user.id);
    user.avatar = `/public/uploads/${req.file.filename}`;
    await user.save();
    res.json(user.avatar);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

module.exports = router;