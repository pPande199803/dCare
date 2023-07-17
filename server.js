const express = require('express');
const mongoose = require('mongoose');
const env = require('dotenv');
const cors = require('cors')
const authRoute = require('./routes/auth-route')
const doctorRoute = require('./routes/doctorRoute')
const bookApp = require('./routes/bookApp')
const Notification = require('./routes/notification')

env.config();

const app = express();


app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGO_URL).then(()=>{
    console.log('Database Connect SuccessFully')
}).catch(()=>{
    console.log('Something went worrong')
})

const port = process.env.PORT || 5000; 


app.use('/api/auth', authRoute)
app.use('/api/doctor', doctorRoute)
app.use('/api/book-appoinment', bookApp)
app.use('/api/notification', Notification)


app.get('/',(req,res)=>{
    res.send("Welcome to server")
})

app.listen(port, ()=>{
    console.log("Server is Running ")
})