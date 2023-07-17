const router = require('express').Router();
const Notification = require('../models/notification')



router.post('/', async(req,res)=>{

    const bookingApp = await new Notification({
            doctorId:req.body.doctorId,
            userId:req.body.userId,
            userName:req.body.userName,
            mobile:req.body.mobile,
            age:req.body.age,
            address:req.body.address,
            weight:req.body.weight,
            checkType:req.body.checkType,
            currentDate:req.body.currentDate,
            status:req.body.status,
            // fees:req.body.fees,
            // timing:req.body.timing
    })

    bookingApp.save()
    .then(()=>{
            res.status(200).send({
                message:"Book Appoientment Successfully",
                success:true,
                bookingApp
            })
        }).catch(()=>{
            res.status(500).send({
                message:"Server Side Error",
                success:false
            })
        })
})

router.get('/all-notification',(req,res)=>{
    Notification.find().then((result)=>{
      res.status(200).send({
          message:"All Appointment Data",
          success:true,
          notification:result
      })
    }).catch((err)=>{
      res.status(500).send({
          message:"Server Side error dorctor not found",
          success:false
      })
    })
})

router.delete('/:id',(req,res)=>{
    Notification.findByIdAndDelete({_id:req.params.id}).exec().then((result)=>{
        res.status(201).send({
            message:"Delete appoientment successfully",
            result
        })
    }).catch(err=>{
        res.status(500).send({
            message:"Server side error",
            err
        })
    })
})

module.exports  = router;