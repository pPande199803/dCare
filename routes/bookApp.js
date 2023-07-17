const router = require('express').Router();
const BookApp = require('../models/bookAppModel')
const Notification = require('../models/notification')



router.post('/', async(req,res)=>{

    const existingUser = await BookApp.findOne({userId: req.body.userId})
    const existingDoctor = await BookApp.findOne({doctorId:req.body.doctorId})
    if(existingDoctor && existingUser){
        return res.status(200).send({
            message:"AppoientMent is Already book",
            success:false
        })
    }

    const bookingApp = await new BookApp({
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
    // console.log(bookingApp)
    if(bookingApp.currentDate === req.body.currentDate){
        res.status(201).send({
            message:"already Appioentment Has been booked"
        })
    }

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


router.post('/notification',async (req,res)=>{
    let today = new Date().toISOString().slice(0, 10)
    const existingUser = await Notification.findOne({userId: req.body.userId})
    const existingDoctor = await Notification.findOne({doctorId:req.body.doctorId})
   
    if(today == req.body.currentDate && existingUser && existingDoctor){
        return res.status(200).send({
            message:"Notification is already send... date3",
            success:false
        })
    }
    
    const notification = await new Notification({

            doctorId:req.body.doctorId,
            userId:req.body.userId,
            userName:req.body.userName,
           notification:req.body.notification,
           currentDate:req.body.currentDate,
           status:req.body.status
    })

    notification.save()
    .then(()=>{
            res.status(200).send({
                message:"Appoientment Notification Send Successfully",
                success:true,
                notification
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





router.get('/all-appoientment',(req,res)=>{
    BookApp.find().then((result)=>{
      res.status(200).send({
          message:"All Appointment Data",
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

router.put('/appoientment/:id', (req,res)=>{
    // console.log(req.params.id)
    // const dID={
    //     _id: new mongodb.ObjectId(req.params._id)
    // } 
    BookApp.findByIdAndUpdate({_id:req.params.id} ,{
            $set:{
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

router.delete('/:id',(req,res)=>{
    BookApp.findByIdAndDelete({_id:req.params.id}).exec().then((result)=>{
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