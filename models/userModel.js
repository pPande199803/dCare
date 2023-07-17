const mongoose = require('mongoose');


const Schema = mongoose.Schema;

const userSchema = new Schema({
    name:{
        type:String,
        required:[true, "this field is required"],
        
    },
    email:{
        type:String,
        required:[true,  "this field is required"],
        unique:true
    },
    password:{
        type:String,
        required:[true , "this field is required"]
    },
    isAdmin:{
        type:Boolean,
    },
    isUser:{
        type:Boolean,
    },
    secreatKey:{
        type:String,
    }
},{ timestamps: true }

)

module.exports = mongoose.model('User', userSchema)



