const router = require('express').Router();
const User = require('../models/userModel');
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const checkAuth = require('../middleware/authCheck')


router.post('/register', async(req,res)=>{

    bcrypt.hash(req.body.password, 10, async (err, hash)=>{
        if(err){
            return res.status(500).send({
                success:false,
                message:"Hash password error"
            })
        }else{
            
            const existingUser = await User.findOne({email: req.body.email})
                if(existingUser){
                    return res.status(200).send({
                        message:"User Already Exist",
                        success:false
                    })
                }
            const user = new User({
                name:req.body.name,
                email:req.body.email,
                password:hash,
                isAdmin:req.body.isAdmin,
                isUser:req.body.isUser,
                secreatKey:req.body.secreatKey
            })

            if(user.isAdmin == true){
                
                if(user.secreatKey == process.env.SECRET_KEY){
    
                    user.save().then(()=>{
                        res.status(200).send({
                            message:"Account Has been Create",
                            success:true,
                            user
                        })
                        
                    }).catch(()=>{
                        res.status(500).send({
                            message:"Authentication Failed....",
                            success:false
                        })
                    })
                }else{
                    res.status(401).send({
                            message:"Key not Match...",
                            success:false
                        })
                }
            }else{
                user.save().then(()=>{
                    res.status(200).send({
                        message:"Account Has been Create",
                        success:true,
                        user
                    })
                    
                }).catch(()=>{
                    res.status(500).send({
                        message:"Authentication Failed....",
                        success:false
                    })
                })
            }


        }
    })

})


router.post('/login', (req,res)=>{
    // res.json("Login Work")
    User.find({email:req.body.email}).exec().then((result)=>{
        if(result.length < 1){
            return res.status(401).send({
                message:"User Not Found",
                success:false
            })
        }

        const user = result[0];
        bcrypt.compare(req.body.password, user.password, (err,result)=>{
            if(result){
                const payload = {
                    userId : user._id,

                }
                const token = jwt.sign(payload, process.env.SECRET_KEY)
                res.status(200).send({
                    message:"Login Successfully",
                    success:true,
                    token:token,
                    user
                })
            }else{
                res.status(500).send({
                    message:"User Not Login",
                    success:false
                })
            }
        })

    }).catch((error)=>{
        res.status(500).send({
            message:"Something Went Worng",
            success:false
        })
    })
})

router.get('/profile',checkAuth,(req,res)=>{
    const userId = req.userData.userId
    User.findById(userId).exec().then((result)=>{
        res.status(200).send({
            success:true,
            data:result
        })
        
    }).catch(()=>{
        res.status(500).send({
            message:"Something Went Worng",
            success:false

        })
    })
})



module.exports  = router;