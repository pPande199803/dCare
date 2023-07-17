const mongoose = require('mongoose');


const Schema = mongoose.Schema;

const doctorSchema = new Schema({
    
    firstName:{
        type:String,
        required:[true, "this field is required"],
        
    },
    lastName:{
        type:String,
        required:[true, "this field is required"],
        
    },
    email:{
        type:String,
        required:[true, "this field is required"],
        unique:true
        
    },
    mobile:{
        type:String,
        required:[true, "this field is required"],
        
    },
    website:{
        type:String
        
    },
    address:{
        type:String,
        required:[true, "this field is required"],
        
    },
    // profission details 
    specification:{
        type:String,
        required:[true, "this field is required"],
        
    },
    experience:{
        type:String,
        required:[true, "this field is required"],
        
    },
    fees:{
        type:String,
        required:[true, "this field is required"],
        
    },
    timeIn:{
        type:String,
        required:[true, "this field is required"],
        
    },
    timeOut:{
        type:String,
        required:[true, "this field is required"],
        
    },
},{ timestamps: true })

module.exports = mongoose.model('Doctor', doctorSchema)



