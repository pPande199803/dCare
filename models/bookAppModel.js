const mongoose = require('mongoose');


const Schema = mongoose.Schema;

const bookingSchema = new Schema({
    
    doctorId:{
        type:String,
        required:[true, "this field is required"],
        
    },
    userId:{
        type:String,
        required:[true, "this field is required"],
        
    },
    userName:{
        type:String,
        required:[true, "this field is required"],
        
    },
    mobile:{
        type:String,
        required:[true, "this field is required"],
        
    },
    age:{
        type:String,
        required:[true, "this field is required"],
        
    },
    weight:{
        type:String,
        required:[true, "this field is required"],
        
    },
    address:{
        type:String,
        required:[true, "this field is required"],
        
    },
    checkType:{
        type:String,
        required:[true, "this field is required"],
        
    },
    currentDate:{
        type:Date,
        required:[true, "this field is required"],
        
    },
    status:{
        type:String,
        required:[true, "this field is required"],
        
    }
},{ timestamps: true })

module.exports = mongoose.model('BookApp', bookingSchema)



