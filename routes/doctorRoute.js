const router = require('express').Router();
const Doctor = require('../models/doctorModel');
const mongodb = require('mongodb');
const checkAuth = require('../middleware/authCheck');
const User = require('../models/userModel');

router.post('/add-doctor', async(req,res)=>{

    const existingUser = await Doctor.findOne({email: req.body.email})
    if(existingUser){
        return res.status(200).send({
            message:"User Already Exist",
            success:false
        })
    }
    const doctor = await new Doctor({
            firstName:req.body.firstName,
            lastName:req.body.lastName,
            email:req.body.email,
            mobile:req.body.mobile,
            website:req.body.website,
            address:req.body.address,
            // proffiestionl details
            specification:req.body.specification,
            experience:req.body.experience,
            fees:req.body.fees,
            timeIn:req.body.timeIn,
            timeOut:req.body.timeOut
    })
    doctor.save()
    .then(()=>{
            res.status(201).send({
                message:"Doctor Create Successfully",
                success:true,
                doctor
            })
        }).catch(()=>{
            res.status(500).send({
                message:"Server Side Error",
                success:false
            })
        })

})


router.get('/doctor',checkAuth,(req,res)=>{
    const userId = req.userData.userId
    // console.log(userId)
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

router.get('/all-doctor',(req,res)=>{
  Doctor.find().then((result)=>{
    res.status(200).send({
        message:"All doctor Data",
        success:true,
        doctors:result
    })
  }).catch((err)=>{
    res.status(500).send({
        message:"Server Side error dorctor not found",
        success:false
    })
  })
})


router.get('/get-doctor/:_id', (req,res)=>{
    const dID={
        _id: new mongodb.ObjectId(req.params._id)
    } 
    Doctor.findById(dID).then((result)=>{
        res.status(200).send({
            message:"Doctor get by Id ",
            success:true,
            data:result
        })
    }).catch((err)=>{
        res.status(500).send({
            message:"Something went worng",
            success:false
        })
    })
})

router.put('/edit-doctor/:id', (req,res)=>{
    console.log(req.params.id)
    // const dID={
    //     _id: new mongodb.ObjectId(req.params._id)
    // } 
    Doctor.findByIdAndUpdate({_id:req.params.id} ,{
            $set:{
            firstName:req.body.firstName,
            lastName:req.body.lastName,
            email:req.body.email,
            mobile:req.body.mobile,
            website:req.body.website,
            address:req.body.address,
            // proffiestionl details
            specification:req.body.specification,
            experience:req.body.experience,
            fees:req.body.fees,
            timing:req.body.timing
            }
        })
        .then((result)=>{
        res.status(201).json({
            data: result
        });
    }).catch((err)=>{
        res.status(500).json({
                    message: "not found any relative data"
                })
    })
    
})


module.exports  = router;